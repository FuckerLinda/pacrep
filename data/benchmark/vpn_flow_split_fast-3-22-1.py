import re
import json
import random
from pathlib import Path
from collections import defaultdict, Counter
from functools import lru_cache

from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

# =====================================================
# 0. 配置
# =====================================================
ROOT = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_raw")
OUT_DIR = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_pacrep")
TMP_DIR = OUT_DIR / "_tmp_packets"
OUT_DIR.mkdir(parents=True, exist_ok=True)
TMP_DIR.mkdir(parents=True, exist_ok=True)

SEED = 2026
random.seed(SEED)

# 调试时可设整数；正式跑建议 None
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

TOKEN_SPLIT_RE = re.compile(r"\\| ")
SCP_RE = re.compile(r"(^|[_\-])scp")
DROP_TOKEN_HINTS = ("src", "dst", "port", "time", "options")

SPLITS = ("train", "valid", "test")


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

        s = str(p).lower()
        if "nonvpn-pcap" in s or "nonvpn-pcaps" in s or "nonvpn" in s:
            nonvpn_pcaps.append(p)
        elif "vpn-pcap" in s or "vpn-pcaps" in s or "\\vpn" in s or "/vpn" in s:
            vpn_pcaps.append(p)

    random.shuffle(vpn_pcaps)
    random.shuffle(nonvpn_pcaps)
    return vpn_pcaps, nonvpn_pcaps


# =====================================================
# 2. 文件名 -> 应用族
# =====================================================
def infer_raw_app_label_from_name(filename: str):
    name = filename.lower()

    if "bittorrent" in name:
        return RAW_APP2ID["bittorrent"]
    if "gmail" in name:
        return RAW_APP2ID["gmail"]
    if "voipbuster" in name:
        return RAW_APP2ID["voipbuster"]
    if "hangout" in name:
        return RAW_APP2ID["hangouts"]
    if "netflix" in name:
        return RAW_APP2ID["netflix"]
    if SCP_RE.search(name):
        return RAW_APP2ID["scp"]
    if "sftp" in name:
        return RAW_APP2ID["sftp"]
    if "ftps" in name:
        return RAW_APP2ID["ftps"]
    if "spotify" in name:
        return RAW_APP2ID["spotify"]
    if "youtube" in name:
        return RAW_APP2ID["youtube"]
    if "vimeo" in name:
        return RAW_APP2ID["vimeo"]
    if "skype" in name:
        return RAW_APP2ID["skype"]
    if "facebook" in name:
        return RAW_APP2ID["facebook"]
    if "email" in name or "mail" in name:
        return RAW_APP2ID["email"]
    if "icq" in name:
        return RAW_APP2ID["icq"]
    if "aim" in name:
        return RAW_APP2ID["aim"]
    return None


# =====================================================
# 3. 双向 flow key
# =====================================================
def get_bidirectional_flow_key(pkt):
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

    ep1 = (ip.src, sport)
    ep2 = (ip.dst, dport)
    if ep1 <= ep2:
        return (proto, ep1[0], ep1[1], ep2[0], ep2[1])
    return (proto, ep2[0], ep2[1], ep1[0], ep1[1])


# =====================================================
# 4. packet -> token
# =====================================================
def packet_to_tokens(pkt):
    text = repr(pkt)
    toks = TOKEN_SPLIT_RE.split(text)

    out = []
    append = out.append
    for tok in toks:
        if not tok:
            continue
        t = tok.lower()
        if any(h in t for h in DROP_TOKEN_HINTS):
            continue
        append(tok)
    return out


# =====================================================
# 5. 扫描单个 pcap，第一阶段只建 flow 元信息
# =====================================================
def scan_pcap_build_flow_meta(pcap_path: Path, vpn_label: int, app_label: int, max_packets_per_pcap=None):
    flow_packet_count = defaultdict(int)
    seen_packets = 0

    try:
        pr = PcapReader(str(pcap_path))
    except Exception as e:
        print(f"[WARN] cannot open {pcap_path}: {e}")
        return flow_packet_count

    while True:
        try:
            pkt = pr.read_packet()
            if pkt is None:
                break
        except EOFError:
            break
        except Exception:
            continue

        if KEEP_RAW_ONLY and not pkt.haslayer(Raw):
            continue

        flow_key = get_bidirectional_flow_key(pkt)
        if flow_key is None:
            continue

        # 第一阶段不做 repr/token 化，只做计数
        flow_packet_count[flow_key] += 1

        seen_packets += 1
        if max_packets_per_pcap is not None and seen_packets >= max_packets_per_pcap:
            break

    try:
        pr.close()
    except Exception:
        pass

    return flow_packet_count


# =====================================================
# 6. 第一阶段：全量建立 flow 索引
# =====================================================
def phase1_build_flow_index(vpn_pcaps, nonvpn_pcaps, max_packets_per_pcap=None):
    flow_index = {}
    app_flow_count = Counter()
    vpn_flow_count = Counter()
    nonvpn_flow_count = Counter()
    app_packet_count = Counter()

    next_flow_id = 0

    jobs = [(p, LABEL_VPN) for p in vpn_pcaps] + [(p, LABEL_NONVPN) for p in nonvpn_pcaps]

    for pcap_path, vpn_label in jobs:
        app_label = infer_raw_app_label_from_name(pcap_path.name)
        if app_label is None:
            print(f"[WARN] unknown raw app label: {pcap_path.name}")
            continue

        local_counts = scan_pcap_build_flow_meta(
            pcap_path=pcap_path,
            vpn_label=vpn_label,
            app_label=app_label,
            max_packets_per_pcap=max_packets_per_pcap,
        )

        local_flow_num = 0
        local_packet_num = 0

        for flow_key, pkt_cnt in local_counts.items():
            local_flow_num += 1
            local_packet_num += pkt_cnt

            if flow_key not in flow_index:
                flow_id = f"{pcap_path.stem}__flow{next_flow_id}"
                next_flow_id += 1
                flow_index[flow_key] = {
                    "flow_id": flow_id,
                    "pcap_path": str(pcap_path),
                    "pcap_name": pcap_path.name,
                    "vpn_label": vpn_label,
                    "app_label": app_label,
                    "packet_count": pkt_cnt,
                    "split": None,
                }
            else:
                # 理论上同一个双向 flow 不应跨文件；若真的发生，这里合并计数
                flow_index[flow_key]["packet_count"] += pkt_cnt

        side = "VPN " if vpn_label == LABEL_VPN else "NON "
        print(f"[{side}] {pcap_path.name}: flows={local_flow_num} packets={local_packet_num}")

        app_flow_count[app_label] += local_flow_num
        app_packet_count[app_label] += local_packet_num
        if vpn_label == LABEL_VPN:
            vpn_flow_count[app_label] += local_flow_num
        else:
            nonvpn_flow_count[app_label] += local_flow_num

    print("\n=== raw app distribution in full flow pool ===")
    for app_id in sorted(app_flow_count.keys()):
        print(
            f"{ID2RAW_APP[app_id]:12s} flow_total={app_flow_count[app_id]:7d} "
            f"vpn={vpn_flow_count[app_id]:7d} nonvpn={nonvpn_flow_count[app_id]:7d} "
            f"packet_total={app_packet_count[app_id]:9d}"
        )

    return flow_index, vpn_flow_count, nonvpn_flow_count


# =====================================================
# 7. 过滤应用族
# =====================================================
def filter_apps_from_flow_index(flow_index, vpn_flow_count, nonvpn_flow_count):
    total_per_app = Counter(meta["app_label"] for meta in flow_index.values())

    keep_app_ids = []
    drop_app_ids = []

    for app_id in sorted(total_per_app.keys()):
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

    filtered_keys = [k for k, v in flow_index.items() if v["app_label"] in keep_app_ids]
    return filtered_keys, keep_app_ids, drop_app_ids


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


def assign_splits(flow_index, kept_flow_keys, seed=2026):
    rnd = random.Random(seed)
    by_app = defaultdict(list)

    for k in kept_flow_keys:
        by_app[flow_index[k]["app_label"]].append(k)

    split_flow_keys = {"train": [], "valid": [], "test": []}

    for app_id in sorted(by_app.keys()):
        keys = by_app[app_id][:]
        rnd.shuffle(keys)

        counts = split_counts(len(keys), TRAIN_RATIO, VALID_RATIO, TEST_RATIO)
        if counts is None:
            print(f"[WARN] app {ID2RAW_APP[app_id]} has too few flows after filtering: {len(keys)}")
            continue

        n_train, n_valid, n_test = counts

        train_keys = keys[:n_train]
        valid_keys = keys[n_train:n_train + n_valid]
        test_keys = keys[n_train + n_valid:n_train + n_valid + n_test]

        split_flow_keys["train"].extend(train_keys)
        split_flow_keys["valid"].extend(valid_keys)
        split_flow_keys["test"].extend(test_keys)

    for split_name in SPLITS:
        for k in split_flow_keys[split_name]:
            flow_index[k]["split"] = split_name

    return split_flow_keys


# =====================================================
# 9. flow 统计
# =====================================================
def print_flow_stats(name, flow_metas):
    by_app = Counter()
    by_vpn = Counter()
    packet_total = 0

    for meta in flow_metas:
        by_app[meta["app_label"]] += 1
        by_vpn[meta["vpn_label"]] += 1
        packet_total += meta["packet_count"]

    print(f"\n=== {name} flow stats ===")
    print(f"flows: {len(flow_metas)}")
    print(f"packets: {packet_total}")
    print(f"vpn_flows={by_vpn[LABEL_VPN]}, nonvpn_flows={by_vpn[LABEL_NONVPN]}")
    for app_id in sorted(by_app.keys()):
        print(f"{ID2RAW_APP[app_id]:12s}: {by_app[app_id]}")


# =====================================================
# 10. 第二阶段：按 split 导出 packet 样本到临时 jsonl
#     不把所有 packet/sample 常驻内存
# =====================================================
def phase2_dump_packet_samples(vpn_pcaps, nonvpn_pcaps, flow_index, max_packets_per_pcap=None):
    tmp_files = {}
    for split_name in SPLITS:
        tmp_path = TMP_DIR / f"{split_name}_packets.jsonl"
        if tmp_path.exists():
            tmp_path.unlink()
        tmp_files[split_name] = open(tmp_path, "ab")

    offsets = {split: [] for split in SPLITS}
    offsets_by_label = {split: defaultdict(list) for split in SPLITS}
    packet_stats_app = {split: Counter() for split in SPLITS}
    packet_stats_vpn = {split: Counter() for split in SPLITS}
    packet_total = {split: 0 for split in SPLITS}

    jobs = [(p, LABEL_VPN) for p in vpn_pcaps] + [(p, LABEL_NONVPN) for p in nonvpn_pcaps]

    for pcap_path, vpn_label in jobs:
        app_label = infer_raw_app_label_from_name(pcap_path.name)
        if app_label is None:
            continue

        try:
            pr = PcapReader(str(pcap_path))
        except Exception as e:
            print(f"[WARN] cannot reopen {pcap_path}: {e}")
            continue

        seen_packets = 0

        while True:
            try:
                pkt = pr.read_packet()
                if pkt is None:
                    break
            except EOFError:
                break
            except Exception:
                continue

            if KEEP_RAW_ONLY and not pkt.haslayer(Raw):
                continue

            flow_key = get_bidirectional_flow_key(pkt)
            if flow_key is None:
                continue

            meta = flow_index.get(flow_key)
            if meta is None:
                continue

            split_name = meta["split"]
            if split_name not in {"train", "valid", "test"}:
                continue

            tokens = packet_to_tokens(pkt)
            if not tokens:
                continue

            label_dict = {i: None for i in range(N_TASKS)}
            label_dict[TASK_VPN] = meta["vpn_label"]
            label_dict[TASK_APP] = meta["app_label"]

            record = {
                "text": tokens,
                "label": label_dict,
                "flow_id": meta["flow_id"],
            }

            line = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
            f = tmp_files[split_name]
            off = f.tell()
            f.write(line)

            offsets[split_name].append(off)
            offsets_by_label[split_name][meta["vpn_label"]].append(off)
            packet_stats_app[split_name][meta["app_label"]] += 1
            packet_stats_vpn[split_name][meta["vpn_label"]] += 1
            packet_total[split_name] += 1

            seen_packets += 1
            if max_packets_per_pcap is not None and seen_packets >= max_packets_per_pcap:
                break

        try:
            pr.close()
        except Exception:
            pass

    for split_name in SPLITS:
        tmp_files[split_name].close()

    for split_name in SPLITS:
        print(f"\n=== {split_name} packet stats ===")
        print(f"total: {packet_total[split_name]}")
        print(
            f"vpn={packet_stats_vpn[split_name][LABEL_VPN]}, "
            f"nonvpn={packet_stats_vpn[split_name][LABEL_NONVPN]}"
        )
        for app_id in sorted(packet_stats_app[split_name].keys()):
            print(f"{ID2RAW_APP[app_id]:12s}: {packet_stats_app[split_name][app_id]}")

    return offsets, offsets_by_label


# =====================================================
# 11. 第三阶段：从临时 packet 文件构造 triplet
#     仍然不把所有 packet 样本常驻内存
# =====================================================
def build_triplets_from_tmp(split_name, offsets, offsets_by_label, out_path: Path, seed=2026):
    rnd = random.Random(seed)
    tmp_path = TMP_DIR / f"{split_name}_packets.jsonl"

    label0 = LABEL_NONVPN
    label1 = LABEL_VPN
    pool0 = offsets_by_label[label0]
    pool1 = offsets_by_label[label1]

    if len(pool0) == 0 or len(pool1) == 0:
        with open(out_path, "w", encoding="utf-8") as fw:
            pass
        return 0

    fr = open(tmp_path, "rb")
    fw = open(out_path, "w", encoding="utf-8")

    @lru_cache(maxsize=20000)
    def read_record(offset):
        fr.seek(offset)
        line = fr.readline()
        return json.loads(line.decode("utf-8"))

    triplet_count = 0

    for anchor_off in offsets:
        anchor = read_record(anchor_off)
        anchor_label = anchor["label"][TASK_VPN]

        if anchor_label == label0:
            pos_pool = pool0
            neg_pool = pool1
        else:
            pos_pool = pool1
            neg_pool = pool0

        if len(pos_pool) < 2 or len(neg_pool) < 1:
            continue

        positive_off = anchor_off
        while positive_off == anchor_off:
            positive_off = rnd.choice(pos_pool)

        negative_off = rnd.choice(neg_pool)

        positive = read_record(positive_off)
        negative = read_record(negative_off)

        triplet = {
            "anchor": anchor,
            "positive": positive,
            "negative": negative,
        }
        fw.write(json.dumps(triplet, ensure_ascii=False) + "\n")
        triplet_count += 1

    fw.close()
    fr.close()
    return triplet_count


# =====================================================
# 12. 主流程
# =====================================================
def main():
    vpn_pcaps, nonvpn_pcaps = collect_pcaps(ROOT)
    print("VPN pcaps:", len(vpn_pcaps))
    print("NonVPN pcaps:", len(nonvpn_pcaps))

    # ---------- 第一阶段：只建 flow 索引 ----------
    flow_index, vpn_flow_count, nonvpn_flow_count = phase1_build_flow_index(
        vpn_pcaps=vpn_pcaps,
        nonvpn_pcaps=nonvpn_pcaps,
        max_packets_per_pcap=MAX_PACKETS_PER_PCAP,
    )

    print(f"\nTotal flows in pool (before filtering): {len(flow_index)}")
    print(f"Total packet samples in pool (before filtering): {sum(v['packet_count'] for v in flow_index.values())}")

    kept_flow_keys, keep_app_ids, drop_app_ids = filter_apps_from_flow_index(
        flow_index=flow_index,
        vpn_flow_count=vpn_flow_count,
        nonvpn_flow_count=nonvpn_flow_count,
    )

    filtered_flow_metas = [flow_index[k] for k in kept_flow_keys]
    print_flow_stats("filtered pool", filtered_flow_metas)

    split_flow_keys = assign_splits(flow_index, kept_flow_keys, seed=SEED)

    print_flow_stats("train", [flow_index[k] for k in split_flow_keys["train"]])
    print_flow_stats("valid", [flow_index[k] for k in split_flow_keys["valid"]])
    print_flow_stats("test", [flow_index[k] for k in split_flow_keys["test"]])

    # ---------- 第二阶段：重扫 pcap，按 split 落盘 packet ----------
    offsets, offsets_by_label = phase2_dump_packet_samples(
        vpn_pcaps=vpn_pcaps,
        nonvpn_pcaps=nonvpn_pcaps,
        flow_index=flow_index,
        max_packets_per_pcap=MAX_PACKETS_PER_PCAP,
    )

    # ---------- 第三阶段：由临时 packet 文件构 triplet ----------
    train_triplets = build_triplets_from_tmp(
        split_name="train",
        offsets=offsets["train"],
        offsets_by_label=offsets_by_label["train"],
        out_path=OUT_DIR / "train.txt",
        seed=SEED,
    )
    valid_triplets = build_triplets_from_tmp(
        split_name="valid",
        offsets=offsets["valid"],
        offsets_by_label=offsets_by_label["valid"],
        out_path=OUT_DIR / "valid.txt",
        seed=SEED + 1,
    )
    test_triplets = build_triplets_from_tmp(
        split_name="test",
        offsets=offsets["test"],
        offsets_by_label=offsets_by_label["test"],
        out_path=OUT_DIR / "test.txt",
        seed=SEED + 2,
    )

    print("\n=== triplets ===")
    print("train triplets:", train_triplets)
    print("valid triplets:", valid_triplets)
    print("test  triplets:", test_triplets)

    print(f"\nDone. Output saved to: {OUT_DIR}")
    print(f"Temporary packet files saved to: {TMP_DIR}")


if __name__ == "__main__":
    main()