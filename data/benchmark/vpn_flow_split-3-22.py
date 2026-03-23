import re
import json
import random
import hashlib
from pathlib import Path
from collections import defaultdict, Counter

from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP, UDP

# =====================================================
# 0. 配置
# =====================================================
ROOT = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_raw")
OUT_DIR = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_pacrep")
OUT_DIR.mkdir(parents=True, exist_ok=True)

SEED = 2026
random.seed(SEED)

# 正式建议设为 None；调试时可改小
MAX_PACKETS_PER_PCAP = None

# 按 flow 切分，再把 flow 内 packet 还原成 packet 样本
TRAIN_RATIO = 0.8
VALID_RATIO = 0.1
TEST_RATIO = 0.1

# 若某应用族 flow 太少，无法同时覆盖 train/valid/test，则删除该应用族
MIN_FLOWS_PER_APP = 3

# 若想降低二分类任务中的“应用泄漏”，保留 VPN 和 NonVPN 两边都出现过的应用族
KEEP_BOTH_SIDED_APPS_ONLY = True

# 仅保留有 Raw 且属于 IP/TCP/UDP 的包
KEEP_RAW_ONLY = True

# PacRep 当前样例数据中标签槽位数
N_TASKS = 6

# task 0: VPN vs NonVPN
TASK_VPN = 0
LABEL_NONVPN = 0
LABEL_VPN = 1

# task 1: 原始应用族标签
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
    vpn_pcaps = []
    nonvpn_pcaps = []

    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in [".pcap", ".pcapng", ".cap"]:
            p_str = str(p).lower()
            if "nonvpn-pcap" in p_str or "nonvpn-pcaps" in p_str or "nonvpn" in p_str:
                nonvpn_pcaps.append(p)
            elif "vpn-pcap" in p_str or "vpn-pcaps" in p_str or "\\vpn" in p_str or "/vpn" in p_str:
                vpn_pcaps.append(p)

    random.shuffle(vpn_pcaps)
    random.shuffle(nonvpn_pcaps)
    return vpn_pcaps, nonvpn_pcaps


# =====================================================
# 2. 从文件名推断应用族
# =====================================================
def infer_raw_app_label_from_name(filename: str):
    name = filename.lower()

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
    return None


# =====================================================
# 3. packet -> token list
# =====================================================
def packet_to_tokens(pkt):
    text = repr(pkt)
    tokens = re.split(r"\\| ", text)

    clean_tokens = []
    for tok in tokens:
        if not tok:
            continue
        tok_lower = tok.lower()

        if ("src" in tok_lower) or ("dst" in tok_lower) or ("port" in tok_lower):
            continue
        if ("time" in tok_lower) or ("options" in tok_lower):
            continue

        clean_tokens.append(tok)
    return clean_tokens


# =====================================================
# 4. flow key
# =====================================================
def get_flow_key(pkt):
    if IP not in pkt:
        return None

    ip = pkt[IP]
    proto = int(ip.proto)

    if TCP in pkt:
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
    elif UDP in pkt:
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
    else:
        return None

    return (proto, ip.src, sport, ip.dst, dport)


# =====================================================
# 5. 从单个 pcap 提取 flow，再由 flow 持有 packet 样本
# =====================================================
def extract_flows_from_pcap(pcap_path: Path, vpn_label: int, app_label: int, max_packets_per_pcap=None):
    flows = {}

    try:
        pr = PcapReader(str(pcap_path))
    except Exception as e:
        print(f"[WARN] cannot open {pcap_path}: {e}")
        return []

    kept_packet_count = 0
    total_packet_count = 0

    while True:
        try:
            pkt = pr.read_packet()
            if pkt is None:
                break
        except EOFError:
            break
        except Exception:
            continue

        total_packet_count += 1

        if KEEP_RAW_ONLY and ('Raw' not in pkt):
            continue

        flow_key = get_flow_key(pkt)
        if flow_key is None:
            continue

        tokens = packet_to_tokens(pkt)
        if not tokens:
            continue

        label_dict = {i: None for i in range(N_TASKS)}
        label_dict[TASK_VPN] = vpn_label
        label_dict[TASK_APP] = app_label

        flow_hash = hashlib.md5(
            (str(pcap_path) + "|" + repr(flow_key)).encode("utf-8", errors="ignore")
        ).hexdigest()
        flow_id = f"{pcap_path.stem}__{flow_hash}"

        if flow_id not in flows:
            flows[flow_id] = {
                "flow_id": flow_id,
                "pcap_path": str(pcap_path),
                "pcap_name": pcap_path.name,
                "flow_key": flow_key,
                "vpn_label": vpn_label,
                "app_label": app_label,
                "packets": []
            }

        flows[flow_id]["packets"].append({
            "text": tokens,
            "label": label_dict,
            "flow_id": flow_id,
        })

        kept_packet_count += 1
        if max_packets_per_pcap is not None and kept_packet_count >= max_packets_per_pcap:
            break

    try:
        pr.close()
    except Exception:
        pass

    out = list(flows.values())
    for x in out:
        x["packet_count"] = len(x["packets"])
    return out


# =====================================================
# 6. 建立统一 flow 池
# =====================================================
def build_flow_pool(vpn_pcaps, nonvpn_pcaps, max_packets_per_pcap=None):
    flow_pool = []

    app_flow_count = defaultdict(int)
    vpn_flow_count = defaultdict(int)
    nonvpn_flow_count = defaultdict(int)

    app_packet_count = defaultdict(int)
    vpn_packet_count = defaultdict(int)
    nonvpn_packet_count = defaultdict(int)

    for p in vpn_pcaps:
        app_label = infer_raw_app_label_from_name(p.name)
        if app_label is None:
            print(f"[WARN] unknown raw app label for VPN file: {p.name}")
            continue

        flows = extract_flows_from_pcap(
            pcap_path=p,
            vpn_label=LABEL_VPN,
            app_label=app_label,
            max_packets_per_pcap=max_packets_per_pcap,
        )
        packet_num = sum(f["packet_count"] for f in flows)
        print(f"[VPN ] {p.name}: flows={len(flows)} packets={packet_num}")

        flow_pool.extend(flows)
        app_flow_count[app_label] += len(flows)
        vpn_flow_count[app_label] += len(flows)
        app_packet_count[app_label] += packet_num
        vpn_packet_count[app_label] += packet_num

    for p in nonvpn_pcaps:
        app_label = infer_raw_app_label_from_name(p.name)
        if app_label is None:
            print(f"[WARN] unknown raw app label for NonVPN file: {p.name}")
            continue

        flows = extract_flows_from_pcap(
            pcap_path=p,
            vpn_label=LABEL_NONVPN,
            app_label=app_label,
            max_packets_per_pcap=max_packets_per_pcap,
        )
        packet_num = sum(f["packet_count"] for f in flows)
        print(f"[NON ] {p.name}: flows={len(flows)} packets={packet_num}")

        flow_pool.extend(flows)
        app_flow_count[app_label] += len(flows)
        nonvpn_flow_count[app_label] += len(flows)
        app_packet_count[app_label] += packet_num
        nonvpn_packet_count[app_label] += packet_num

    print("\n=== raw app distribution in full flow pool ===")
    for app_id in sorted(app_flow_count.keys()):
        app_name = ID2RAW_APP[app_id]
        print(
            f"{app_name:12s} flow_total={app_flow_count[app_id]:7d} "
            f"vpn={vpn_flow_count[app_id]:7d} nonvpn={nonvpn_flow_count[app_id]:7d} "
            f"packet_total={app_packet_count[app_id]:9d}"
        )

    return flow_pool, vpn_flow_count, nonvpn_flow_count


# =====================================================
# 7. 过滤应用族
# =====================================================
def filter_apps(flow_pool, vpn_flow_count, nonvpn_flow_count):
    keep_app_ids = []
    drop_app_ids = []

    all_app_ids = sorted(set(list(vpn_flow_count.keys()) + list(nonvpn_flow_count.keys())))
    total_per_app = Counter(f["app_label"] for f in flow_pool)

    for app_id in all_app_ids:
        total_n = total_per_app[app_id]
        both_sided_ok = (vpn_flow_count[app_id] > 0 and nonvpn_flow_count[app_id] > 0)
        enough_flows = total_n >= MIN_FLOWS_PER_APP

        keep = enough_flows
        if KEEP_BOTH_SIDED_APPS_ONLY:
            keep = keep and both_sided_ok

        if keep:
            keep_app_ids.append(app_id)
        else:
            drop_app_ids.append(app_id)

    print("\n=== app filter on flow pool ===")
    print("keep:", [ID2RAW_APP[x] for x in keep_app_ids])
    print("drop:", [ID2RAW_APP[x] for x in drop_app_ids])

    filtered = [f for f in flow_pool if f["app_label"] in keep_app_ids]
    return filtered, keep_app_ids, drop_app_ids


# =====================================================
# 8. flow 级分层切分
# =====================================================
def split_counts(n, train_ratio=0.8, valid_ratio=0.1, test_ratio=0.1):
    if n < 3:
        return None

    n_train = int(n * train_ratio)
    n_valid = int(n * valid_ratio)
    n_test = n - n_train - n_valid

    if n_valid < 1:
        n_valid = 1
    if n_test < 1:
        n_test = 1
    n_train = n - n_valid - n_test

    if n_train < 1:
        return None
    return n_train, n_valid, n_test


def stratified_split_by_app_on_flows(flow_pool, seed=2026):
    rnd = random.Random(seed)
    by_app = defaultdict(list)
    for flow in flow_pool:
        by_app[flow["app_label"]].append(flow)

    train_flows, valid_flows, test_flows = [], [], []

    for app_id in sorted(by_app.keys()):
        items = by_app[app_id][:]
        rnd.shuffle(items)
        counts = split_counts(len(items), TRAIN_RATIO, VALID_RATIO, TEST_RATIO)
        if counts is None:
            print(f"[WARN] app {ID2RAW_APP[app_id]} has too few flows after filtering: {len(items)}")
            continue

        n_train, n_valid, n_test = counts
        train_flows.extend(items[:n_train])
        valid_flows.extend(items[n_train:n_train + n_valid])
        test_flows.extend(items[n_train + n_valid:n_train + n_valid + n_test])

    rnd.shuffle(train_flows)
    rnd.shuffle(valid_flows)
    rnd.shuffle(test_flows)
    return train_flows, valid_flows, test_flows


# =====================================================
# 9. flow -> packet samples
# =====================================================
def flatten_flow_packets(flows):
    packets = []
    for flow in flows:
        packets.extend(flow["packets"])
    return packets


# =====================================================
# 10. 打印统计
# =====================================================
def print_flow_stats(name, flows):
    by_app = defaultdict(int)
    by_vpn = defaultdict(int)
    packet_total = 0

    for f in flows:
        by_app[f["app_label"]] += 1
        by_vpn[f["vpn_label"]] += 1
        packet_total += f["packet_count"]

    print(f"\n=== {name} flow stats ===")
    print(f"flows: {len(flows)}")
    print(f"packets: {packet_total}")
    print(f"vpn_flows={by_vpn[LABEL_VPN]}, nonvpn_flows={by_vpn[LABEL_NONVPN]}")
    for app_id in sorted(by_app.keys()):
        print(f"{ID2RAW_APP[app_id]:12s}: {by_app[app_id]}")


def print_packet_stats(name, samples):
    by_app = defaultdict(int)
    by_vpn = defaultdict(int)
    for s in samples:
        by_app[s["label"][TASK_APP]] += 1
        by_vpn[s["label"][TASK_VPN]] += 1

    print(f"\n=== {name} packet stats ===")
    print(f"total: {len(samples)}")
    print(f"vpn={by_vpn[LABEL_VPN]}, nonvpn={by_vpn[LABEL_NONVPN]}")
    for app_id in sorted(by_app.keys()):
        print(f"{ID2RAW_APP[app_id]:12s}: {by_app[app_id]}")


# =====================================================
# 11. 构造 PacRep 三元组
# =====================================================
def build_triplets(samples, task_id=TASK_VPN, seed=2026):
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
            "negative": negative,
        })

    return triplets


# =====================================================
# 12. 写出 jsonl
# =====================================================
def write_jsonl(path: Path, items):
    with open(path, "w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")


# =====================================================
# 13. 主流程
# =====================================================
def main():
    vpn_pcaps, nonvpn_pcaps = collect_pcaps(ROOT)
    print("VPN pcaps:", len(vpn_pcaps))
    print("NonVPN pcaps:", len(nonvpn_pcaps))

    flow_pool, vpn_flow_count, nonvpn_flow_count = build_flow_pool(
        vpn_pcaps=vpn_pcaps,
        nonvpn_pcaps=nonvpn_pcaps,
        max_packets_per_pcap=MAX_PACKETS_PER_PCAP,
    )

    print(f"\nTotal flows in pool (before filtering): {len(flow_pool)}")
    print(f"Total packet samples in pool (before filtering): {sum(f['packet_count'] for f in flow_pool)}")

    flow_pool, keep_app_ids, drop_app_ids = filter_apps(flow_pool, vpn_flow_count, nonvpn_flow_count)
    print_flow_stats("filtered pool", flow_pool)

    train_flows, valid_flows, test_flows = stratified_split_by_app_on_flows(flow_pool, seed=SEED)

    print_flow_stats("train", train_flows)
    print_flow_stats("valid", valid_flows)
    print_flow_stats("test", test_flows)

    train_samples = flatten_flow_packets(train_flows)
    valid_samples = flatten_flow_packets(valid_flows)
    test_samples = flatten_flow_packets(test_flows)

    print_packet_stats("train", train_samples)
    print_packet_stats("valid", valid_samples)
    print_packet_stats("test", test_samples)

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
