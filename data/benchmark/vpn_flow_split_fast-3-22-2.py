import os
import re
import json
import random
import socket
from pathlib import Path
from collections import defaultdict, Counter
from multiprocessing import Pool, cpu_count

import dpkt

# =====================================================
# 0. 配置
# =====================================================
ROOT = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_raw")
OUT_DIR = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_pacrep")
OUT_DIR.mkdir(parents=True, exist_ok=True)

SEED = 2026
random.seed(SEED)

# 正式全量跑建议保持为 None
MAX_PACKETS_PER_PCAP = None

TRAIN_RATIO = 0.8
VALID_RATIO = 0.1
TEST_RATIO = 0.1

MIN_FLOWS_PER_APP = 3
KEEP_BOTH_SIDED_APPS_ONLY = True
KEEP_RAW_ONLY = True

N_TASKS = 6
TASK_VPN = 0
LABEL_NONVPN = 0
LABEL_VPN = 1
TASK_APP = 1

RAW_APP2ID = {
    "aim": 0, "bittorrent": 1, "email": 2, "facebook": 3,
    "ftps": 4, "gmail": 5, "hangouts": 6, "icq": 7,
    "netflix": 8, "scp": 9, "sftp": 10, "skype": 11,
    "spotify": 12, "vimeo": 13, "voipbuster": 14, "youtube": 15,
}
ID2RAW_APP = {v: k for k, v in RAW_APP2ID.items()}

TOKEN_SPLIT_RE = re.compile(r"\\| ")
SCP_RE = re.compile(r"(^|[_\-])scp")
DROP_TOKEN_HINTS = ("src", "dst", "port", "time", "options")

# =====================================================
# 1. 收集 pcap
# =====================================================
def collect_pcaps(root: Path):
    vpn_pcaps = []
    nonvpn_pcaps = []

    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
            continue

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
    if "bittorrent" in name: return RAW_APP2ID["bittorrent"]
    if "gmail" in name: return RAW_APP2ID["gmail"]
    if "voipbuster" in name: return RAW_APP2ID["voipbuster"]
    if "hangout" in name: return RAW_APP2ID["hangouts"]
    if "netflix" in name: return RAW_APP2ID["netflix"]
    if SCP_RE.search(name): return RAW_APP2ID["scp"]
    if "sftp" in name: return RAW_APP2ID["sftp"]
    if "ftps" in name: return RAW_APP2ID["ftps"]
    if "spotify" in name: return RAW_APP2ID["spotify"]
    if "youtube" in name: return RAW_APP2ID["youtube"]
    if "vimeo" in name: return RAW_APP2ID["vimeo"]
    if "skype" in name: return RAW_APP2ID["skype"]
    if "facebook" in name: return RAW_APP2ID["facebook"]
    if "email" in name or "mail" in name: return RAW_APP2ID["email"]
    if "icq" in name: return RAW_APP2ID["icq"]
    if "aim" in name: return RAW_APP2ID["aim"]
    return None

# =====================================================
# 3. 多进程 Worker: 利用 dpkt 极速提取 Flow
# =====================================================
def extract_flows_from_pcap_worker(args):
    pcap_path, vpn_label, app_label, max_packets_per_pcap = args
    flows = {}
    packet_counter = 0

    label_dict_template = {i: None for i in range(N_TASKS)}
    label_dict_template[TASK_VPN] = vpn_label
    label_dict_template[TASK_APP] = app_label

    try:
        with open(pcap_path, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip = eth.data
                    
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        l4 = ip.data
                        proto = 6
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        l4 = ip.data
                        proto = 17
                    else:
                        continue
                        
                    payload = l4.data
                    if KEEP_RAW_ONLY and not payload:
                        continue
                        
                    # 双向流漏洞防御：对端点进行严格排序
                    sport, dport = l4.sport, l4.dport
                    src_ip, dst_ip = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
                    
                    ep1 = (src_ip, sport)
                    ep2 = (dst_ip, dport)
                    if ep1 <= ep2:
                        flow_key = (proto, ep1[0], ep1[1], ep2[0], ep2[1])
                    else:
                        flow_key = (proto, ep2[0], ep2[1], ep1[0], ep1[1])
                        
                    # 直接对负载做文本化及分词过滤
                    text = repr(payload)
                    tokens = TOKEN_SPLIT_RE.split(text)
                    
                    out_tokens = []
                    for tok in tokens:
                        if not tok: continue
                        tok_lower = tok.lower()
                        if any(h in tok_lower for h in DROP_TOKEN_HINTS): continue
                        out_tokens.append(tok)
                        
                    if not out_tokens:
                        continue
                        
                    flow = flows.get(flow_key)
                    if flow is None:
                        flow_id = f"{Path(pcap_path).stem}__flow{len(flows)}"
                        flow = {
                            "flow_id": flow_id,
                            "pcap_path": str(pcap_path),
                            "pcap_name": Path(pcap_path).name,
                            "flow_key": flow_key,
                            "vpn_label": vpn_label,
                            "app_label": app_label,
                            "packets": [],
                        }
                        flows[flow_key] = flow
                        
                    flow["packets"].append({
                        "text": out_tokens,
                        "label": label_dict_template.copy(),
                        "flow_id": flow["flow_id"],
                    })
                    
                    packet_counter += 1
                    if max_packets_per_pcap is not None and packet_counter >= max_packets_per_pcap:
                        break
                        
                except Exception:
                    continue
    except Exception as e:
        print(f"[WARN] cannot open {pcap_path}: {e}")

    out = list(flows.values())
    for f in out:
        f["packet_count"] = len(f["packets"])
    return out

# =====================================================
# 4. 建立统一 flow 池 (多进程版)
# =====================================================
def build_flow_pool_multiprocess(vpn_pcaps, nonvpn_pcaps, max_packets_per_pcap=None):
    flow_pool = []
    app_flow_count = defaultdict(int)
    vpn_flow_count = defaultdict(int)
    nonvpn_flow_count = defaultdict(int)
    app_packet_count = defaultdict(int)

    tasks = []
    for p, vpn_label in [(x, LABEL_VPN) for x in vpn_pcaps] + [(x, LABEL_NONVPN) for x in nonvpn_pcaps]:
        app_label = infer_raw_app_label_from_name(p.name)
        if app_label is None:
            print(f"[WARN] unknown raw app label: {p.name}")
            continue
        tasks.append((p, vpn_label, app_label, max_packets_per_pcap))

    # 启用进程池，保留一个核心给系统后台
    num_cores = max(1, cpu_count() - 1)
    print(f"\n[INFO] Starting multiprocessing pool with {num_cores} workers...")
    
    with Pool(processes=num_cores) as pool:
        results = pool.map(extract_flows_from_pcap_worker, tasks)
        
    for task_info, flows in zip(tasks, results):
        p, vpn_label, app_label, _ = task_info
        packet_num = sum(f["packet_count"] for f in flows)
        side = "VPN " if vpn_label == LABEL_VPN else "NON "
        print(f"[{side}] {p.name}: flows={len(flows)} packets={packet_num}")

        flow_pool.extend(flows)
        app_flow_count[app_label] += len(flows)
        app_packet_count[app_label] += packet_num
        if vpn_label == LABEL_VPN:
            vpn_flow_count[app_label] += len(flows)
        else:
            nonvpn_flow_count[app_label] += len(flows)

    print("\n=== raw app distribution in full flow pool ===")
    for app_id in sorted(app_flow_count.keys()):
        print(
            f"{ID2RAW_APP[app_id]:12s} flow_total={app_flow_count[app_id]:7d} "
            f"vpn={vpn_flow_count[app_id]:7d} nonvpn={nonvpn_flow_count[app_id]:7d} "
            f"packet_total={app_packet_count[app_id]:9d}"
        )

    return flow_pool, vpn_flow_count, nonvpn_flow_count

# =====================================================
# 5. 过滤应用族
# =====================================================
def filter_apps(flow_pool, vpn_flow_count, nonvpn_flow_count):
    keep_app_ids = []
    drop_app_ids = []
    total_per_app = Counter(f["app_label"] for f in flow_pool)
    all_app_ids = sorted(total_per_app.keys())

    for app_id in all_app_ids:
        total_n = total_per_app[app_id]
        both_sided_ok = (vpn_flow_count[app_id] > 0 and nonvpn_flow_count[app_id] > 0)
        enough_flows = total_n >= MIN_FLOWS_PER_APP
        keep = enough_flows and ((not KEEP_BOTH_SIDED_APPS_ONLY) or both_sided_ok)
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
# 6. flow 级分层切分
# =====================================================
def split_counts(n, train_ratio=0.8, valid_ratio=0.1, test_ratio=0.1):
    if n < 3:
        return None

    n_train = int(n * train_ratio)
    n_valid = int(n * valid_ratio)
    n_test = n - n_train - n_valid

    if n_valid < 1: n_valid = 1
    if n_test < 1: n_test = 1
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
# 7. flow -> packet samples
# =====================================================
def flatten_flow_packets(flows):
    packets = []
    extend = packets.extend
    for flow in flows:
        extend(flow["packets"])
    return packets

# =====================================================
# 8. 统计数据打印
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
# 9. 构造 PacRep 三元组
# =====================================================
def build_triplets(samples, task_id=TASK_VPN, seed=2026):
    rnd = random.Random(seed)
    by_label = defaultdict(list)
    for s in samples:
        by_label[s["label"][task_id]].append(s)

    labels = list(by_label.keys())
    if len(labels) < 2:
        return []

    triplets = []
    if len(labels) == 2:
        lb0, lb1 = labels[0], labels[1]
        pool0 = by_label[lb0]
        pool1 = by_label[lb1]
        for anchor in samples:
            anchor_label = anchor["label"][task_id]
            pos_pool = by_label[anchor_label]
            neg_pool = pool1 if anchor_label == lb0 else pool0
            if len(pos_pool) < 2 or len(neg_pool) < 1:
                continue
            positive = anchor
            while positive is anchor:
                positive = rnd.choice(pos_pool)
            negative = rnd.choice(neg_pool)
            triplets.append({"anchor": anchor, "positive": positive, "negative": negative})
        return triplets

    all_pools = {lb: by_label[lb] for lb in labels}
    for anchor in samples:
        anchor_label = anchor["label"][task_id]
        pos_pool = all_pools[anchor_label]
        neg_pool = []
        for lb in labels:
            if lb != anchor_label:
                neg_pool.extend(all_pools[lb])
        if len(pos_pool) < 2 or len(neg_pool) < 1:
            continue
        positive = anchor
        while positive is anchor:
            positive = rnd.choice(pos_pool)
        negative = rnd.choice(neg_pool)
        triplets.append({"anchor": anchor, "positive": positive, "negative": negative})
    return triplets

# =====================================================
# 10. 写出 jsonl
# =====================================================
def write_jsonl(path: Path, items):
    with open(path, "w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

# =====================================================
# 11. 主流程
# =====================================================
def main():
    vpn_pcaps, nonvpn_pcaps = collect_pcaps(ROOT)
    print("VPN pcaps:", len(vpn_pcaps))
    print("NonVPN pcaps:", len(nonvpn_pcaps))

    # 使用多进程版本建立 flow 池，显著加快读取 28G 数据的速度
    flow_pool, vpn_flow_count, nonvpn_flow_count = build_flow_pool_multiprocess(
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