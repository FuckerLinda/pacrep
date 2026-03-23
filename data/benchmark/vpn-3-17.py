import os
import re
import json
import random
from pathlib import Path
from collections import defaultdict

from scapy.all import PcapReader

# =========================
# 0. 配置
# =========================
ROOT = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_raw")   # 你解压后的总目录
OUT_DIR = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_vpn_nonvpn")
OUT_DIR.mkdir(parents=True, exist_ok=True)

SEED = 2026
TRAIN_RATIO = 0.8
VALID_RATIO = 0.1
TEST_RATIO = 0.1

# 标签约定：你自己统一即可
LABEL_NONVPN = 0
LABEL_VPN = 1

# PacRep 当前 sample 的标签槽位长度是 6 个
N_TASKS = 6
TASK_ID = 0   # 当前先把 VPN vs NonVPN 放到 task-0


# =========================
# 1. 找到所有 pcap 文件并打标签
# =========================
def collect_pcaps(root: Path):
    vpn_pcaps = []
    nonvpn_pcaps = []

    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in [".pcap", ".pcapng", ".cap"]:
            p_str = str(p).lower()
            if "nonvpn-pcap" in p_str or "nonvpn-pcaps" in p_str or "nonvpn" in p_str:
                nonvpn_pcaps.append(p)
            elif "vpn-pcap" in p_str or "vpn-pcaps" in p_str or "\\vpn" in p_str:
                vpn_pcaps.append(p)

    return vpn_pcaps, nonvpn_pcaps


# =========================
# 2. 先按 pcap 文件切分 train/valid/test
# =========================
def split_files(file_list, seed=2026, train_ratio=0.8, valid_ratio=0.1):
    file_list = list(file_list)
    random.Random(seed).shuffle(file_list)

    n = len(file_list)
    n_train = int(n * train_ratio)
    n_valid = int(n * valid_ratio)

    train_files = file_list[:n_train]
    valid_files = file_list[n_train:n_train + n_valid]
    test_files = file_list[n_train + n_valid:]

    return train_files, valid_files, test_files


# =========================
# 3. packet -> token list
# =========================
def packet_to_tokens(pkt):
    """
    尽量模仿 preprocess_exp.py 的思路：
    - 用 repr(pkt)
    - 按 \\ 和空格切分
    - 删除 src/dst/port 等易泄漏字段
    """
    text = repr(pkt)
    tokens = re.split(r"\\| ", text)

    clean_tokens = []
    for tok in tokens:
        if not tok:
            continue
        tok_lower = tok.lower()

        # 去掉易泄漏/高变字段
        if ("src" in tok_lower) or ("dst" in tok_lower) or ("port" in tok_lower):
            continue

        # 也可以进一步去掉时间戳、seq号等强标识字段
        if ("time" in tok_lower) or ("options" in tok_lower):
            continue

        clean_tokens.append(tok)

    return clean_tokens


# =========================
# 4. 从单个 pcap 提取 packet 样本
# =========================
def extract_samples_from_pcap(pcap_path: Path, label_value: int):
    """
    输出列表中每个元素是：
    {
      "text": [...],
      "label": {0: ..., 1: None, ..., 5: None}
    }
    """
    samples = []
    try:
        pr = PcapReader(str(pcap_path))
    except Exception as e:
        print(f"[WARN] cannot open {pcap_path}: {e}")
        return samples

    while True:
        try:
            pkt = pr.read_packet()
            if pkt is None:
                break
        except EOFError:
            break
        except Exception:
            continue

        # 模仿 preprocess_exp.py，只保留含 Raw 的包
        if 'Raw' not in pkt:
            continue

        tokens = packet_to_tokens(pkt)
        if not tokens:
            continue

        label_dict = {i: None for i in range(N_TASKS)}
        label_dict[TASK_ID] = label_value

        sample = {
            "text": tokens,
            "label": label_dict
        }
        samples.append(sample)

    return samples


# =========================
# 5. 批量提取 split 样本
# =========================
def build_split_samples(vpn_files, nonvpn_files):
    split_samples = []

    for p in vpn_files:
        split_samples.extend(extract_samples_from_pcap(p, LABEL_VPN))

    for p in nonvpn_files:
        split_samples.extend(extract_samples_from_pcap(p, LABEL_NONVPN))

    return split_samples


# =========================
# 6. 构造 PacRep 三元组
# =========================
def build_triplets(samples, seed=2026):
    """
    samples: list of {"text":..., "label":...}
    返回 list of JSON-string-ready dict:
      {"anchor":..., "positive":..., "negative":...}
    """
    rnd = random.Random(seed)

    by_label = defaultdict(list)
    for s in samples:
        by_label[s["label"][TASK_ID]].append(s)

    labels = list(by_label.keys())
    triplets = []

    for anchor in samples:
        anchor_label = anchor["label"][TASK_ID]

        pos_pool = by_label[anchor_label]
        neg_pool = []
        for lb in labels:
            if lb != anchor_label:
                neg_pool.extend(by_label[lb])

        if len(pos_pool) < 2:
            # 没有足够正样本时跳过
            continue
        if len(neg_pool) < 1:
            continue

        # positive 不能和 anchor 本身完全同一个对象
        positive = anchor
        while positive is anchor:
            positive = rnd.choice(pos_pool)

        negative = rnd.choice(neg_pool)

        triplets.append({
            "anchor": anchor,
            "positive": positive,
            "negative": negative
        })

    return triplets


# =========================
# 7. 写出 txt
# =========================
def write_jsonl(path: Path, items):
    with open(path, "w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")


# =========================
# 8. 主流程
# =========================
def main():
    vpn_pcaps, nonvpn_pcaps = collect_pcaps(ROOT)
    print(f"VPN pcaps: {len(vpn_pcaps)}")
    print(f"NonVPN pcaps: {len(nonvpn_pcaps)}")


    vpn_pcaps = vpn_pcaps[:10]   # 只取前10个 VPN pcap 文件
    nonvpn_pcaps = nonvpn_pcaps[:10]  # 只取前10个 NonVPN pcap 文件
    print(f"VPN pcaps: {vpn_pcaps}")
    print(f"NonVPN pcaps: {nonvpn_pcaps}")

    vpn_train, vpn_valid, vpn_test = split_files(vpn_pcaps, seed=SEED, train_ratio=TRAIN_RATIO, valid_ratio=VALID_RATIO)
    non_train, non_valid, non_test = split_files(nonvpn_pcaps, seed=SEED, train_ratio=TRAIN_RATIO, valid_ratio=VALID_RATIO)

    print("=== file split ===")
    print("train:", len(vpn_train), len(non_train))
    print("valid:", len(vpn_valid), len(non_valid))
    print("test :", len(vpn_test), len(non_test))

    train_samples = build_split_samples(vpn_train, non_train)
    valid_samples = build_split_samples(vpn_valid, non_valid)
    test_samples  = build_split_samples(vpn_test,  non_test)

    print("=== packet samples ===")
    print("train samples:", len(train_samples))
    print("valid samples:", len(valid_samples))
    print("test  samples:", len(test_samples))

    train_triplets = build_triplets(train_samples, seed=SEED)
    valid_triplets = build_triplets(valid_samples, seed=SEED + 1)
    test_triplets  = build_triplets(test_samples,  seed=SEED + 2)

    print("=== triplets ===")
    print("train triplets:", len(train_triplets))
    print("valid triplets:", len(valid_triplets))
    print("test  triplets:", len(test_triplets))

    write_jsonl(OUT_DIR / "train.txt", train_triplets)
    write_jsonl(OUT_DIR / "valid.txt", valid_triplets)
    write_jsonl(OUT_DIR / "test.txt", test_triplets)

    print(f"Done. Output saved to: {OUT_DIR}")


if __name__ == "__main__":
    main()