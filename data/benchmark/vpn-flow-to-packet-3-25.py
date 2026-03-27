import re
import json
import random
import argparse
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
OUT_DIR = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_binary_fixed12")
TMP_DIR = OUT_DIR / "_tmp_packets"

OUT_DIR.mkdir(parents=True, exist_ok=True)
TMP_DIR.mkdir(parents=True, exist_ok=True)

FLOW_POOL_PATH = OUT_DIR / "flow_pool.jsonl"
TRAIN_FLOW_PATH = OUT_DIR / "train_flows.jsonl"
VALID_FLOW_PATH = OUT_DIR / "valid_flows.jsonl"
TEST_FLOW_PATH = OUT_DIR / "test_flows.jsonl"

SEED = 20260323
random.seed(SEED)

# -----------------------------------------------------
# 读取阶段就抽样：小 pcap 全读，大 pcap 早停
# -----------------------------------------------------
SMALL_PCAP_MB = 20
EARLY_PACKET_CAP_LARGE = 20000
EARLY_PACKET_CAP_SMALL = None

# 每条 flow 最多导出多少个 packet
MAX_PACKETS_PER_FLOW_EXPORT = 20

KEEP_RAW_ONLY = True

# 总体目标 8:1:1
TRAIN_RATIO = 0.8
VALID_RATIO = 0.1
TEST_RATIO = 0.1

# 第一步：flow 池抽样比例
FLOW_SAMPLE_RATIO = 0.1

# 大类按比例，小类按下限保底
FLOW_POOL_MIN_KEEP_PER_APP = 20

# split 时每类最低 flow 数
MIN_TRAIN_PER_APP = 1
MIN_VALID_PER_APP = 1
MIN_TEST_PER_APP = 1
MIN_TOTAL_PER_APP = MIN_TRAIN_PER_APP + MIN_VALID_PER_APP + MIN_TEST_PER_APP

# 固定 12 类
FIXED_APP_NAMES = [
    "aim",
    "email",
    "facebook",
    "ftps",
    "gmail",
    "hangouts",
    "icq",
    "bittorrent",
    "sftp",
    "skype",
    "vimeo",
    "youtube",
]
APP2ID = {name: idx for idx, name in enumerate(FIXED_APP_NAMES)}
ID2APP = {idx: name for name, idx in APP2ID.items()}

# PacRep 标签槽位
N_TASKS = 6

# task 0: VPN vs NonVPN
TASK_VPN = 0
LABEL_NONVPN = 0
LABEL_VPN = 1

# task 1: app
TASK_APP = 1

TOKEN_SPLIT_RE = re.compile(r"\\| ")
SCP_RE = re.compile(r"(^|[_\-])scp")


# =====================================================
# 1. 选择每个 pcap 的读取上限
# =====================================================
def choose_packet_cap_for_pcap(pcap_path: Path):
    size_mb = pcap_path.stat().st_size / (1024 * 1024)
    if size_mb <= SMALL_PCAP_MB:
        return EARLY_PACKET_CAP_SMALL
    return EARLY_PACKET_CAP_LARGE


# =====================================================
# 2. 收集 pcap
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
# 3. 文件名 -> 应用族
# =====================================================
def infer_raw_app_name_from_filename(filename: str):
    name = filename.lower()

    if "bittorrent" in name:
        return "bittorrent"
    elif "gmail" in name:
        return "gmail"
    elif "voipbuster" in name:
        return "voipbuster"
    elif "hangout" in name:
        return "hangouts"
    elif "netflix" in name:
        return "netflix"
    elif SCP_RE.search(name):
        return "scp"
    elif "sftp" in name:
        return "sftp"
    elif "ftps" in name:
        return "ftps"
    elif "spotify" in name:
        return "spotify"
    elif "youtube" in name:
        return "youtube"
    elif "vimeo" in name:
        return "vimeo"
    elif "skype" in name:
        return "skype"
    elif "facebook" in name:
        return "facebook"
    elif "email" in name or "mail" in name:
        return "email"
    elif "icq" in name:
        return "icq"
    elif "aim" in name:
        return "aim"
    else:
        return None


# =====================================================
# 4. packet -> token
# =====================================================
def packet_to_tokens(pkt):
    text = repr(pkt)
    tokens = TOKEN_SPLIT_RE.split(text)

    clean_tokens = []
    append = clean_tokens.append
    for tok in tokens:
        if not tok:
            continue
        tok_lower = tok.lower()
        if ("src" in tok_lower) or ("dst" in tok_lower) or ("port" in tok_lower):
            continue
        if ("time" in tok_lower) or ("options" in tok_lower):
            continue
        append(tok)
    return clean_tokens


# =====================================================
# 5. 双向 flow key
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
    else:
        return (proto, ep2[0], ep2[1], ep1[0], ep1[1])


# =====================================================
# 6. 第一阶段：扫描单个 pcap，建 flow 计数
# =====================================================
def scan_one_pcap_build_flow_meta(pcap_path: Path):
    flow_packet_count = defaultdict(int)
    count = 0

    packet_cap = choose_packet_cap_for_pcap(pcap_path)

    try:
        pr = PcapReader(str(pcap_path))
    except Exception as e:
        print(f"[WARN] cannot open {pcap_path}: {e}")
        return flow_packet_count, packet_cap

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

        flow_packet_count[flow_key] += 1

        count += 1
        if packet_cap is not None and count >= packet_cap:
            break

    try:
        pr.close()
    except Exception:
        pass

    return flow_packet_count, packet_cap


# =====================================================
# 7. 构建全量 flow 索引（未抽样）
# =====================================================
def build_full_flow_index(vpn_pcaps, nonvpn_pcaps):
    flow_index = {}
    next_flow_id = 0

    app_flow_count = Counter()
    app_packet_count = Counter()
    vpn_flow_count = Counter()
    nonvpn_flow_count = Counter()

    jobs = [(p, LABEL_VPN) for p in vpn_pcaps] + [(p, LABEL_NONVPN) for p in nonvpn_pcaps]

    for idx, (pcap_path, vpn_label) in enumerate(jobs, 1):
        raw_app_name = infer_raw_app_name_from_filename(pcap_path.name)
        if raw_app_name is None:
            print(f"[skip-unknown] {pcap_path.name}")
            continue

        if raw_app_name not in APP2ID:
            print(f"[skip-not-in-fixed12] {pcap_path.name} -> {raw_app_name}")
            continue

        app_id = APP2ID[raw_app_name]
        local_counts, packet_cap = scan_one_pcap_build_flow_meta(pcap_path)

        local_flow_num = 0
        local_packet_num = 0

        for flow_key, pkt_cnt in local_counts.items():
            local_flow_num += 1
            local_packet_num += pkt_cnt

            # 关键：pcap_path 也纳入全局 key，避免不同文件中的相同五元组被错并
            global_flow_key = (str(pcap_path), flow_key)

            flow_id = f"{pcap_path.stem}__flow{next_flow_id}"
            next_flow_id += 1

            flow_index[global_flow_key] = {
                "flow_id": flow_id,
                "pcap_path": str(pcap_path),
                "pcap_name": pcap_path.name,
                "vpn_label": vpn_label,
                "app_id": app_id,
                "packet_count": pkt_cnt,
            }

        app_flow_count[app_id] += local_flow_num
        app_packet_count[app_id] += local_packet_num
        if vpn_label == LABEL_VPN:
            vpn_flow_count[app_id] += local_flow_num
        else:
            nonvpn_flow_count[app_id] += local_flow_num

        side = "VPN " if vpn_label == LABEL_VPN else "NON "
        cap_msg = "ALL" if packet_cap is None else str(packet_cap)
        print(
            f"[phase1 {idx}/{len(jobs)}] [{side}] {pcap_path.name}: "
            f"flows={local_flow_num} packets={local_packet_num} cap={cap_msg}"
        )

    print("\n=== fixed12 app distribution in full flow pool ===")
    for app_name in FIXED_APP_NAMES:
        app_id = APP2ID[app_name]
        print(
            f"{app_name:12s} flow_total={app_flow_count[app_id]:7d} "
            f"vpn={vpn_flow_count[app_id]:7d} nonvpn={nonvpn_flow_count[app_id]:7d} "
            f"packet_total={app_packet_count[app_id]:9d}"
        )

    return flow_index


# =====================================================
# 8. 为落盘 flow_pool 记录补充 flow_key
# =====================================================
def rebuild_flow_pool_records_with_key(flow_index):
    records = []
    for (pcap_path, flow_key), meta in flow_index.items():
        proto, a1, a2, b1, b2 = flow_key
        rec = {
            "flow_id": meta["flow_id"],
            "pcap_path": pcap_path,
            "pcap_name": meta["pcap_name"],
            "vpn_label": meta["vpn_label"],
            "app_id": meta["app_id"],
            "packet_count": meta["packet_count"],
            "flow_key": [proto, a1, a2, b1, b2],
        }
        records.append(rec)
    return records


# =====================================================
# 9. flow 池抽样：大类按 1:10，小类按下限保底
# =====================================================
def choose_sample_size_per_app(n_total):
    n_keep = int(round(n_total * FLOW_SAMPLE_RATIO))
    n_keep = max(n_keep, FLOW_POOL_MIN_KEEP_PER_APP)
    n_keep = max(n_keep, MIN_TOTAL_PER_APP)
    n_keep = min(n_keep, n_total)
    return n_keep


def build_and_save_flow_pool_from_records(all_records, flow_pool_path: Path):
    by_app = defaultdict(list)
    for rec in all_records:
        by_app[rec["app_id"]].append(rec)

    sampled = []
    sampled_count_per_app = {}

    for app_name in FIXED_APP_NAMES:
        app_id = APP2ID[app_name]
        items = by_app.get(app_id, [])
        n = len(items)

        if n < MIN_TOTAL_PER_APP:
            raise RuntimeError(
                f"应用类 {app_name} 的 flow 数只有 {n}，无法保证后续 train/valid/test 都有样本。"
            )

        random.shuffle(items)
        n_keep = choose_sample_size_per_app(n)
        chosen = items[:n_keep]

        sampled_count_per_app[app_id] = n_keep
        sampled.extend(chosen)

    print("\n=== after building sampled flow_pool ===")
    for app_id in sorted(sampled_count_per_app.keys()):
        print(f"{ID2APP[app_id]:12s}: kept_flows={sampled_count_per_app[app_id]}")

    with open(flow_pool_path, "w", encoding="utf-8") as fw:
        for rec in sampled:
            fw.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"\nSaved flow pool to: {flow_pool_path}")


def load_flow_pool(flow_pool_path: Path):
    if not flow_pool_path.exists():
        raise FileNotFoundError(f"flow pool file not found: {flow_pool_path}")

    records = []
    with open(flow_pool_path, "r", encoding="utf-8") as fr:
        for line in fr:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


# =====================================================
# 10. 从 flow_pool 切 train/valid/test
# =====================================================
def split_counts_for_one_app(n):
    if n < MIN_TOTAL_PER_APP:
        raise RuntimeError(f"n={n} 太小，无法切分")

    n_valid = max(MIN_VALID_PER_APP, int(round(n * VALID_RATIO)))
    n_test = max(MIN_TEST_PER_APP, int(round(n * TEST_RATIO)))
    n_train = n - n_valid - n_test

    if n_train < MIN_TRAIN_PER_APP:
        while n_train < MIN_TRAIN_PER_APP:
            if n_valid > MIN_VALID_PER_APP:
                n_valid -= 1
                n_train += 1
            elif n_test > MIN_TEST_PER_APP:
                n_test -= 1
                n_train += 1
            else:
                raise RuntimeError(f"n={n} 无法满足 train/valid/test 最低要求")

    return n_train, n_valid, n_test


def split_flow_pool(flow_pool_records):
    by_app = defaultdict(list)
    for rec in flow_pool_records:
        by_app[rec["app_id"]].append(rec)

    train_flows = []
    valid_flows = []
    test_flows = []

    for app_name in FIXED_APP_NAMES:
        app_id = APP2ID[app_name]
        items = by_app[app_id][:]
        random.shuffle(items)

        n_train, n_valid, n_test = split_counts_for_one_app(len(items))

        train_part = items[:n_train]
        valid_part = items[n_train:n_train + n_valid]
        test_part = items[n_train + n_valid:n_train + n_valid + n_test]

        train_flows.extend(train_part)
        valid_flows.extend(valid_part)
        test_flows.extend(test_part)

        print(
            f"[split] {app_name:12s} total={len(items):6d} "
            f"train={len(train_part):6d} valid={len(valid_part):6d} test={len(test_part):6d}"
        )

    with open(TRAIN_FLOW_PATH, "w", encoding="utf-8") as fw:
        for rec in train_flows:
            fw.write(json.dumps(rec, ensure_ascii=False) + "\n")
    with open(VALID_FLOW_PATH, "w", encoding="utf-8") as fw:
        for rec in valid_flows:
            fw.write(json.dumps(rec, ensure_ascii=False) + "\n")
    with open(TEST_FLOW_PATH, "w", encoding="utf-8") as fw:
        for rec in test_flows:
            fw.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"\nSaved split flow files to:\n  {TRAIN_FLOW_PATH}\n  {VALID_FLOW_PATH}\n  {TEST_FLOW_PATH}")

    return train_flows, valid_flows, test_flows


# =====================================================
# 11. flow 统计
# =====================================================
def print_flow_stats(name, flow_metas):
    by_app = Counter()
    by_vpn = Counter()
    packet_total = 0

    for meta in flow_metas:
        by_app[meta["app_id"]] += 1
        by_vpn[meta["vpn_label"]] += 1
        packet_total += meta["packet_count"]

    print(f"\n=== {name} flow stats ===")
    print(f"flows: {len(flow_metas)}")
    print(f"packets: {packet_total}")
    print(f"vpn_flows={by_vpn[LABEL_VPN]}, nonvpn_flows={by_vpn[LABEL_NONVPN]}")
    for app_id in sorted(by_app.keys()):
        print(f"{ID2APP[app_id]:12s}: {by_app[app_id]}")


# =====================================================
# 12. 建立 split lookup
# =====================================================
def make_split_lookup(train_flows, valid_flows, test_flows):
    lookup = {}

    for split_name, records in [
        ("train", train_flows),
        ("valid", valid_flows),
        ("test", test_flows),
    ]:
        for rec in records:
            fk = tuple(rec["flow_key"])
            global_flow_key = (rec["pcap_path"], fk)
            rec2 = {
                "flow_id": rec["flow_id"],
                "pcap_path": rec["pcap_path"],
                "pcap_name": rec["pcap_name"],
                "vpn_label": rec["vpn_label"],
                "app_id": rec["app_id"],
                "packet_count": rec["packet_count"],
                "split": split_name,
            }
            lookup[global_flow_key] = rec2

    return lookup


# =====================================================
# 13. 第二阶段：按 split 重扫 pcap，导出 packet 到临时 jsonl
# =====================================================
def dump_packets_to_tmp(vpn_pcaps, nonvpn_pcaps, split_lookup):
    tmp_files = {}
    for split_name in ("train", "valid", "test"):
        tmp_path = TMP_DIR / f"{split_name}_packets.jsonl"
        if tmp_path.exists():
            tmp_path.unlink()
        tmp_files[split_name] = open(tmp_path, "ab")

    offsets = {split: [] for split in ("train", "valid", "test")}
    offsets_by_label = {split: defaultdict(list) for split in ("train", "valid", "test")}
    packet_stats_app = {split: Counter() for split in ("train", "valid", "test")}
    packet_stats_vpn = {split: Counter() for split in ("train", "valid", "test")}
    packet_total = {split: 0 for split in ("train", "valid", "test")}
    exported_per_flow = defaultdict(int)

    jobs = [(p, LABEL_VPN) for p in vpn_pcaps] + [(p, LABEL_NONVPN) for p in nonvpn_pcaps]

    for idx, (pcap_path, vpn_label) in enumerate(jobs, 1):
        raw_app_name = infer_raw_app_name_from_filename(pcap_path.name)
        if raw_app_name is None or raw_app_name not in APP2ID:
            continue

        packet_cap = choose_packet_cap_for_pcap(pcap_path)

        try:
            pr = PcapReader(str(pcap_path))
        except Exception as e:
            print(f"[WARN] cannot reopen {pcap_path}: {e}")
            continue

        local_written = 0
        local_seen = 0

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

            global_flow_key = (str(pcap_path), flow_key)
            meta = split_lookup.get(global_flow_key)
            if meta is None:
                continue

            split_name = meta["split"]

            flow_id = meta["flow_id"]
            if MAX_PACKETS_PER_FLOW_EXPORT is not None and exported_per_flow[flow_id] >= MAX_PACKETS_PER_FLOW_EXPORT:
                continue

            tokens = packet_to_tokens(pkt)
            if not tokens:
                continue

            # 关键：label 用字符串键 dict，兼容 PacRep 原训练代码
            label_dict = {str(i): None for i in range(N_TASKS)}
            label_dict[str(TASK_VPN)] = meta["vpn_label"]
            label_dict[str(TASK_APP)] = meta["app_id"]

            rec = {
                "text": tokens,
                "label": label_dict,
                "flow_id": flow_id,
            }

            line = (json.dumps(rec, ensure_ascii=False) + "\n").encode("utf-8")
            fw = tmp_files[split_name]
            off = fw.tell()
            fw.write(line)

            offsets[split_name].append(off)
            offsets_by_label[split_name][meta["vpn_label"]].append(off)
            packet_stats_app[split_name][meta["app_id"]] += 1
            packet_stats_vpn[split_name][meta["vpn_label"]] += 1
            packet_total[split_name] += 1
            exported_per_flow[flow_id] += 1

            local_written += 1
            local_seen += 1

            if local_written % 10000 == 0:
                fw.flush()
                print(
                    f"[phase2 {idx}/{len(jobs)}] {pcap_path.name}: "
                    f"written_packets={local_written}"
                )

            if packet_cap is not None and local_seen >= packet_cap:
                break

        try:
            pr.close()
        except Exception:
            pass

        cap_msg = "ALL" if packet_cap is None else str(packet_cap)
        print(f"[phase2 {idx}/{len(jobs)}] {pcap_path.name}: final_written={local_written} cap={cap_msg}")

    for split_name in ("train", "valid", "test"):
        tmp_files[split_name].flush()
        tmp_files[split_name].close()

    for split_name in ("train", "valid", "test"):
        print(f"\n=== {split_name} packet stats ===")
        print(f"total: {packet_total[split_name]}")
        print(
            f"vpn={packet_stats_vpn[split_name][LABEL_VPN]}, "
            f"nonvpn={packet_stats_vpn[split_name][LABEL_NONVPN]}"
        )
        for app_id in sorted(packet_stats_app[split_name].keys()):
            print(f"{ID2APP[app_id]:12s}: {packet_stats_app[split_name][app_id]}")

    for split_name in ("valid", "test"):
        missing = []
        for app_name in FIXED_APP_NAMES:
            app_id = APP2ID[app_name]
            if packet_stats_app[split_name][app_id] <= 0:
                missing.append(app_name)
        if missing:
            raise RuntimeError(f"{split_name} 中以下类没有 packet 样本: {missing}")

    return offsets, offsets_by_label


# =====================================================
# 14. 第三阶段：从临时文件构造二分类 triplet
#     关键修复：先打乱 offsets，再写 triplet，避免前 1200 条局部单类
# =====================================================
def build_triplets_from_tmp(split_name, offsets, offsets_by_label, out_path: Path, seed=2026):
    rnd = random.Random(seed)
    tmp_path = TMP_DIR / f"{split_name}_packets.jsonl"

    pool_nonvpn = offsets_by_label[LABEL_NONVPN]
    pool_vpn = offsets_by_label[LABEL_VPN]

    if len(pool_nonvpn) == 0 or len(pool_vpn) == 0:
        with open(out_path, "w", encoding="utf-8") as fw:
            pass
        return 0

    offsets = offsets[:]
    rnd.shuffle(offsets)

    fr = open(tmp_path, "rb")
    fw = open(out_path, "w", encoding="utf-8")

    @lru_cache(maxsize=50000)
    def read_record(offset):
        fr.seek(offset)
        line = fr.readline()
        return json.loads(line.decode("utf-8"))

    triplet_count = 0
    total_anchor = len(offsets)

    for idx, anchor_off in enumerate(offsets, 1):
        anchor = read_record(anchor_off)
        anchor_label = anchor["label"][str(TASK_VPN)]

        if anchor_label == LABEL_NONVPN:
            pos_pool = pool_nonvpn
            neg_pool = pool_vpn
        else:
            pos_pool = pool_vpn
            neg_pool = pool_nonvpn

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

        if idx % 50000 == 0:
            fw.flush()
            print(f"[phase3-{split_name}] anchor={idx}/{total_anchor} triplets={triplet_count}")

    fw.flush()
    fw.close()
    fr.close()
    return triplet_count


# =====================================================
# 15. 主流程
# =====================================================
def parse_args():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--build-flow-pool", action="store_true", help="从原始 pcap 构建并保存 flow_pool.jsonl")
    group.add_argument("--skip-build-flow-pool", action="store_true", help="跳过构建 flow_pool，直接读取已有 flow_pool.jsonl")
    return parser.parse_args()


def main():
    args = parse_args()

    vpn_pcaps, nonvpn_pcaps = collect_pcaps(ROOT)
    print("VPN pcaps:", len(vpn_pcaps))
    print("NonVPN pcaps:", len(nonvpn_pcaps))

    # ---------- 第一步：构建或读取 flow_pool ----------
    if args.skip_build_flow_pool:
        print("\n[step1] skip building flow_pool, load existing file.")
        flow_pool_records = load_flow_pool(FLOW_POOL_PATH)
    else:
        print("\n[step1] build flow_pool from raw pcaps.")
        flow_index = build_full_flow_index(vpn_pcaps, nonvpn_pcaps)
        full_records = rebuild_flow_pool_records_with_key(flow_index)
        build_and_save_flow_pool_from_records(full_records, FLOW_POOL_PATH)
        flow_pool_records = load_flow_pool(FLOW_POOL_PATH)

    print_flow_stats("flow_pool", flow_pool_records)

    # ---------- 第二步：从 flow_pool 切 split ----------
    print("\n[step2] split flow_pool into train/valid/test.")
    train_flows, valid_flows, test_flows = split_flow_pool(flow_pool_records)

    print_flow_stats("train", train_flows)
    print_flow_stats("valid", valid_flows)
    print_flow_stats("test", test_flows)

    # ---------- 第三步：读取 split flow，导出 packet ----------
    print("\n[step3] export packets from selected flows.")
    split_lookup = make_split_lookup(train_flows, valid_flows, test_flows)
    offsets, offsets_by_label = dump_packets_to_tmp(vpn_pcaps, nonvpn_pcaps, split_lookup)

    # ---------- 第四步：构造二分类 triplet ----------
    print("\n[step4] build binary triplets.")
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
    print(f"Flow pool file: {FLOW_POOL_PATH}")
    print(f"Temporary packet files saved to: {TMP_DIR}")


if __name__ == "__main__":
    main()