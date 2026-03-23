import re
import json
import random
from pathlib import Path
from collections import defaultdict

from scapy.all import PcapReader

# =====================================================
# 0. 配置
# =====================================================
ROOT = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_raw")
OUT_DIR = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_pacrep")
OUT_DIR.mkdir(parents=True, exist_ok=True)

SEED = 2026
random.seed(SEED)

# PacRep 论文中 ISXW2016/ISCXVPN 的 packet 数量设置
TARGET_TRAIN = 191541
TARGET_VALID = 600
TARGET_TEST = 600

# 调试阶段保留每个 pcap 的 packet 上限；正式全量可改成 None
MAX_PACKETS_PER_PCAP = 5000

# PacRep 当前样例数据中标签槽位数
N_TASKS = 6

# task 0: VPN vs NonVPN
TASK_VPN = 0
LABEL_NONVPN = 0
LABEL_VPN = 1

# task 1: 原始应用族标签（先保留原始信息，后面再决定是否映射成论文里的 12 类）
TASK_APP = 1
RAW_APP2ID = {
    "aim": 0,
    "bittorrent": 1,
    "email": 2,
    "facebook": 3,
    "ftps": 4,
    "gmail": 5,
    "hangouts": 6,
    "icq": 7,
    "netflix": 8,
    "scp": 9,
    "sftp": 10,
    "skype": 11,
    "spotify": 12,
    "vimeo": 13,
    "voipbuster": 14,
    "youtube": 15,
}
ID2RAW_APP = {v: k for k, v in RAW_APP2ID.items()}


# =====================================================
# 1. 收集所有 pcap
# =====================================================
def collect_pcaps(root: Path):
    """
    递归扫描 root，收集 VPN 与 NonVPN 的 pcap 文件。
    """
    vpn_pcaps = []
    nonvpn_pcaps = []

    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in [".pcap", ".pcapng", ".cap"]:
            p_str = str(p).lower()
            # 先判断 nonvpn，避免字符串 "nonvpn" 被 "vpn" 子串误伤
            if "nonvpn-pcap" in p_str or "nonvpn-pcaps" in p_str or "nonvpn" in p_str:
                nonvpn_pcaps.append(p)
            elif "vpn-pcap" in p_str or "vpn-pcaps" in p_str or "\\vpn" in p_str:
                vpn_pcaps.append(p)

    random.shuffle(vpn_pcaps)
    random.shuffle(nonvpn_pcaps)
    return vpn_pcaps, nonvpn_pcaps


# =====================================================
# 2. 从文件名推断“原始应用族”
# =====================================================
def infer_raw_app_label_from_name(filename: str):
    """
    从文件名中识别原始应用族。
    注意：gmail 必须在 email 之前判断，否则 gmailchat 会被误判成 email。
    """
    name = filename.lower()

    # 更具体的关键词优先
    if "bittorrent" in name:
        return RAW_APP2ID["bittorrent"]
    elif "gmail" in name:
        return RAW_APP2ID["gmail"]
    elif "voipbuster" in name:
        return RAW_APP2ID["voipbuster"]
    elif "hangout" in name:
        return RAW_APP2ID["hangouts"]
    elif "netflix" in name:
        return RAW_APP2ID["netflix"]
    elif re.search(r"(^|[_\-])scp", name):
        return RAW_APP2ID["scp"]
    elif "sftp" in name:
        return RAW_APP2ID["sftp"]
    elif "ftps" in name:
        return RAW_APP2ID["ftps"]
    elif "spotify" in name:
        return RAW_APP2ID["spotify"]
    elif "youtube" in name:
        return RAW_APP2ID["youtube"]
    elif "vimeo" in name:
        return RAW_APP2ID["vimeo"]
    elif "skype" in name:
        return RAW_APP2ID["skype"]
    elif "facebook" in name:
        return RAW_APP2ID["facebook"]
    elif "email" in name or "mail" in name:
        return RAW_APP2ID["email"]
    elif "icq" in name:
        return RAW_APP2ID["icq"]
    elif "aim" in name:
        return RAW_APP2ID["aim"]
    else:
        return None


# =====================================================
# 3. packet -> token list
# =====================================================
def packet_to_tokens(pkt):
    """
    把单个 packet 转为 token 列表。
    当前沿用 preprocess_exp.py 的粗粒度思路。
    """
    text = repr(pkt)
    tokens = re.split(r"\\| ", text)

    clean_tokens = []
    for tok in tokens:
        if not tok:
            continue
        tok_lower = tok.lower()

        # 去掉明显泄漏字段
        if ("src" in tok_lower) or ("dst" in tok_lower) or ("port" in tok_lower):
            continue

        # 去掉部分高变字段
        if ("time" in tok_lower) or ("options" in tok_lower):
            continue

        clean_tokens.append(tok)

    return clean_tokens


# =====================================================
# 4. 从单个 pcap 提取 packet 样本
# =====================================================
def extract_samples_from_pcap(pcap_path: Path, vpn_label: int, app_label: int, max_packets_per_pcap=None):
    """
    从单个 pcap 中提取 packet 样本。
    输出样本格式：
    {
        "text": [...],
        "label": {0: VPN标签, 1: 应用族标签, 其余任务位为 None}
    }
    """
    samples = []

    try:
        pr = PcapReader(str(pcap_path))
    except Exception as e:
        print(f"[WARN] cannot open {pcap_path}: {e}")
        return samples

    count = 0
    while True:
        try:
            pkt = pr.read_packet()
            if pkt is None:
                break
        except EOFError:
            break
        except Exception:
            continue

        # 当前先沿用 demo 逻辑：仅保留 Raw 包
        if 'Raw' not in pkt:
            continue

        tokens = packet_to_tokens(pkt)
        if not tokens:
            continue

        label_dict = {i: None for i in range(N_TASKS)}
        label_dict[TASK_VPN] = vpn_label
        label_dict[TASK_APP] = app_label

        samples.append({
            "text": tokens,
            "label": label_dict
        })

        count += 1
        if max_packets_per_pcap is not None and count >= max_packets_per_pcap:
            break

    try:
        pr.close()
    except Exception:
        pass

    return samples


# =====================================================
# 5. 建立统一 packet 样本池
# =====================================================
def build_sample_pool(vpn_pcaps, nonvpn_pcaps, max_packets_per_pcap=None):
    """
    遍历所有 pcap，提取 packet 样本，形成统一样本池。
    同时统计每个应用族在 VPN / NonVPN 两边的样本数。
    """
    pool = []

    app_count = defaultdict(int)
    vpn_count = defaultdict(int)
    nonvpn_count = defaultdict(int)

    for p in vpn_pcaps:
        app_label = infer_raw_app_label_from_name(p.name)
        if app_label is None:
            print(f"[WARN] unknown raw app label for VPN file: {p.name}")
            continue

        samples = extract_samples_from_pcap(
            pcap_path=p,
            vpn_label=LABEL_VPN,
            app_label=app_label,
            max_packets_per_pcap=max_packets_per_pcap
        )
        print(f"[VPN ] {p.name}: {len(samples)}")
        pool.extend(samples)

        app_count[app_label] += len(samples)
        vpn_count[app_label] += len(samples)

    for p in nonvpn_pcaps:
        app_label = infer_raw_app_label_from_name(p.name)
        if app_label is None:
            print(f"[WARN] unknown raw app label for NonVPN file: {p.name}")
            continue

        samples = extract_samples_from_pcap(
            pcap_path=p,
            vpn_label=LABEL_NONVPN,
            app_label=app_label,
            max_packets_per_pcap=max_packets_per_pcap
        )
        print(f"[NON ] {p.name}: {len(samples)}")
        pool.extend(samples)

        app_count[app_label] += len(samples)
        nonvpn_count[app_label] += len(samples)

    print("\n=== raw app distribution in full pool ===")
    for app_id in sorted(app_count.keys()):
        app_name = ID2RAW_APP[app_id]
        print(
            f"{app_name:12s} total={app_count[app_id]:7d} "
            f"vpn={vpn_count[app_id]:7d} nonvpn={nonvpn_count[app_id]:7d}"
        )

    return pool, vpn_count, nonvpn_count


# =====================================================
# 6. 过滤“只在一边出现”的应用族
# =====================================================
def filter_one_sided_apps(samples, vpn_count, nonvpn_count):
    """
    去掉只出现在 VPN 或只出现在 NonVPN 一边的应用族，
    以降低二分类任务的应用泄漏风险。

    保留条件：
        同一应用族在 vpn_count 和 nonvpn_count 中都 > 0
    """
    keep_app_ids = []
    drop_app_ids = []

    all_app_ids = sorted(set(list(vpn_count.keys()) + list(nonvpn_count.keys())))
    for app_id in all_app_ids:
        if vpn_count[app_id] > 0 and nonvpn_count[app_id] > 0:
            keep_app_ids.append(app_id)
        else:
            drop_app_ids.append(app_id)

    print("\n=== app filter (keep both-sided apps only) ===")
    print("keep:", [ID2RAW_APP[x] for x in keep_app_ids])
    print("drop:", [ID2RAW_APP[x] for x in drop_app_ids])

    filtered = [s for s in samples if s["label"][TASK_APP] in keep_app_ids]
    return filtered, keep_app_ids, drop_app_ids


# =====================================================
# 7. 打印某个样本集合的应用分布
# =====================================================
def print_pool_stats(name, samples):
    """
    打印某个样本集合的整体分布：
    - 总样本数
    - VPN/NonVPN 数量
    - 各应用族数量
    """
    by_app = defaultdict(int)
    by_vpn = defaultdict(int)

    for s in samples:
        by_app[s["label"][TASK_APP]] += 1
        by_vpn[s["label"][TASK_VPN]] += 1

    print(f"\n=== {name} stats ===")
    print(f"total: {len(samples)}")
    print(f"vpn={by_vpn[LABEL_VPN]}, nonvpn={by_vpn[LABEL_NONVPN]}")

    for app_id in sorted(by_app.keys()):
        print(f"{ID2RAW_APP[app_id]:12s}: {by_app[app_id]}")


# =====================================================
# 8. 修正版：先给 valid/test 预留，再补 train
# =====================================================
def stratified_split_by_raw_app(samples, n_train, n_valid, n_test, seed=2026):
    """
    按原始应用族分层切分 train/valid/test。

    与旧版不同：
        先保证 valid/test 每类尽量有覆盖，
        再把剩余样本主要分给 train。

    这样可以避免小类全被 train 抽空，导致 valid/test 丢类。
    """
    rnd = random.Random(seed)

    by_app = defaultdict(list)
    for s in samples:
        by_app[s["label"][TASK_APP]].append(s)

    for app in by_app:
        rnd.shuffle(by_app[app])

    app_ids = sorted(by_app.keys())
    n_classes = len(app_ids)

    # 先给 valid / test 分配基础配额
    valid_quota = max(1, n_valid // n_classes)
    test_quota = max(1, n_test // n_classes)

    train, valid, test = [], [], []
    leftovers = []

    for app in app_ids:
        items = by_app[app]

        # 先预留 valid/test
        v = items[:valid_quota]
        te = items[valid_quota:valid_quota + test_quota]
        rest = items[valid_quota + test_quota:]

        valid.extend(v)
        test.extend(te)
        leftovers.extend(rest)

    rnd.shuffle(leftovers)

    # train 先尽量从 leftovers 填满
    train = leftovers[:n_train]
    leftovers = leftovers[n_train:]

    # 如果 valid/test 还没到目标数，再继续从 leftovers 补
    def fill_to_target(target_list, target_size, leftovers_list):
        need = target_size - len(target_list)
        if need > 0:
            target_list.extend(leftovers_list[:need])
            leftovers_list = leftovers_list[need:]
        return leftovers_list

    leftovers = fill_to_target(valid, n_valid, leftovers)
    leftovers = fill_to_target(test, n_test, leftovers)

    rnd.shuffle(train)
    rnd.shuffle(valid)
    rnd.shuffle(test)

    return train[:n_train], valid[:n_valid], test[:n_test]


# =====================================================
# 9. 打印 split 分布
# =====================================================
def print_split_stats(name, samples):
    """
    打印 train / valid / test 某个 split 的分布。
    """
    by_app = defaultdict(int)
    by_vpn = defaultdict(int)

    for s in samples:
        by_app[s["label"][TASK_APP]] += 1
        by_vpn[s["label"][TASK_VPN]] += 1

    print(f"\n=== {name} stats ===")
    print(f"total: {len(samples)}")
    print(f"vpn={by_vpn[LABEL_VPN]}, nonvpn={by_vpn[LABEL_NONVPN]}")

    for app_id in sorted(by_app.keys()):
        print(f"{ID2RAW_APP[app_id]:12s}: {by_app[app_id]}")


# =====================================================
# 10. 构造 PacRep 三元组
# =====================================================
def build_triplets(samples, task_id=TASK_VPN, seed=2026):
    """
    按指定 task_id 构造 PacRep 所需的三元组：
    anchor / positive / negative

    当前默认按 task0（VPN 二分类）构造。
    """
    rnd = random.Random(seed)

    by_label = defaultdict(list)
    for s in samples:
        y = s["label"][task_id]
        by_label[y].append(s)

    labels = list(by_label.keys())
    triplets = []

    for anchor in samples:
        anchor_label = anchor["label"][task_id]

        pos_pool = by_label[anchor_label]
        neg_pool = []
        for lb in labels:
            if lb != anchor_label:
                neg_pool.extend(by_label[lb])

        if len(pos_pool) < 2 or len(neg_pool) < 1:
            continue

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


# =====================================================
# 11. 写出 jsonl
# =====================================================
def write_jsonl(path: Path, items):
    """
    以 JSON Lines 格式写出到磁盘。
    """
    with open(path, "w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")


# =====================================================
# 12. 主流程
# =====================================================
def main():
    vpn_pcaps, nonvpn_pcaps = collect_pcaps(ROOT)
    print("VPN pcaps:", len(vpn_pcaps))
    print("NonVPN pcaps:", len(nonvpn_pcaps))

    pool, vpn_count, nonvpn_count = build_sample_pool(
        vpn_pcaps=vpn_pcaps,
        nonvpn_pcaps=nonvpn_pcaps,
        max_packets_per_pcap=MAX_PACKETS_PER_PCAP
    )

    print(f"\nTotal packet samples in pool (before filtering): {len(pool)}")

    # 去掉只在单边出现的应用族，降低 VPN/NonVPN 二分类的应用泄漏风险
    pool, keep_app_ids, drop_app_ids = filter_one_sided_apps(pool, vpn_count, nonvpn_count)
    print_pool_stats("filtered pool", pool)

    print(f"\nTotal packet samples in pool (after filtering): {len(pool)}")

    train_samples, valid_samples, test_samples = stratified_split_by_raw_app(
        pool,
        n_train=TARGET_TRAIN,
        n_valid=TARGET_VALID,
        n_test=TARGET_TEST,
        seed=SEED
    )

    print_split_stats("train", train_samples)
    print_split_stats("valid", valid_samples)
    print_split_stats("test", test_samples)

    train_triplets = build_triplets(train_samples, task_id=TASK_VPN, seed=SEED)
    valid_triplets = build_triplets(valid_samples, task_id=TASK_VPN, seed=SEED + 1)
    test_triplets = build_triplets(test_samples, task_id=TASK_VPN, seed=SEED + 2)

    print("\n=== triplets ===")
    print("train triplets:", len(train_triplets))
    print("valid triplets:", len(valid_triplets))
    print("test  triplets:", len(test_triplets))

    write_jsonl(OUT_DIR / "train.txt", train_triplets)
    write_jsonl(OUT_DIR / "valid.txt", valid_triplets)
    write_jsonl(OUT_DIR / "test.txt", test_triplets)

    print(f"\nDone. Output saved to: {OUT_DIR}")


if __name__ == "__main__":
    main()