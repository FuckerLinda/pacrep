import os
import io
import dpkt
import json
import math
import random
import socket
import hashlib
import re
from pathlib import Path
from collections import defaultdict, Counter
from functools import lru_cache

# =========================================================
# 0. 配置
# =========================================================
ROOT = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_raw")
OUT_DIR = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_binary_fixed12")
TMP_DIR = OUT_DIR / "_tmp_packets"
OUT_DIR.mkdir(parents=True, exist_ok=True)
TMP_DIR.mkdir(parents=True, exist_ok=True)

SEED = 20260323
random.seed(SEED)

# ----------- 固定 12 类 -----------
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

# ----------- 抽样与切分 -----------
TRAIN_RATIO = 0.8
VALID_RATIO = 0.1
TEST_RATIO = 0.1

# 大类按比例，小类保底
# 如果 SAMPLE_RATIO = 1.0，表示不做全局缩样，只做保底切分
# 如果 SAMPLE_RATIO = 0.2，表示每类大致保留 20% 的 flow，小类按下限保底
SAMPLE_RATIO = 1.0

# 每个 app 至少要能分到 train / valid / test
MIN_TRAIN_PER_APP = 1
MIN_VALID_PER_APP = 1
MIN_TEST_PER_APP = 1
MIN_TOTAL_PER_APP = MIN_TRAIN_PER_APP + MIN_VALID_PER_APP + MIN_TEST_PER_APP

# 可选：限制单个 pcap 最多读取多少个有效 packet。None 表示不限制
MAX_PACKETS_PER_PCAP = None

# 可选：导出 packet 时，每条 flow 最多保留多少个 packet。None 表示不限制
MAX_PACKETS_PER_FLOW_EXPORT = None

# 只保留有 Raw payload 的 TCP/UDP 包
KEEP_RAW_ONLY = True

# ----------- 标签配置 -----------
N_TASKS = 6
TASK_VPN = 0
TASK_APP = 1

LABEL_NONVPN = 0
LABEL_VPN = 1

# ----------- 文本化配置 -----------
TOKEN_SPLIT_RE = re.compile(r"\\| ")
SCP_RE = re.compile(r"(^|[_\-])scp")
DROP_TOKEN_HINTS = ("src", "dst", "port", "time", "options")

# =========================================================
# 1. pcap / pcapng Reader
# =========================================================
def open_dpkt_reader(path: Path):
    f = open(path, "rb")
    head = f.read(4)
    f.seek(0)

    # pcapng magic
    if head == b"\x0a\x0d\x0d\x0a":
        return f, dpkt.pcapng.Reader(f)

    return f, dpkt.pcap.Reader(f)


# =========================================================
# 2. 文件收集
# =========================================================
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


# =========================================================
# 3. 文件名 -> app
# =========================================================
def infer_raw_app_name_from_filename(filename: str):
    name = filename.lower()

    if "bittorrent" in name:
        return "bittorrent"
    if "gmail" in name:
        return "gmail"
    if "voipbuster" in name:
        return "voipbuster"
    if "hangout" in name:
        return "hangouts"
    if "netflix" in name:
        return "netflix"
    if SCP_RE.search(name):
        return "scp"
    if "sftp" in name:
        return "sftp"
    if "ftps" in name:
        return "ftps"
    if "spotify" in name:
        return "spotify"
    if "youtube" in name:
        return "youtube"
    if "vimeo" in name:
        return "vimeo"
    if "skype" in name:
        return "skype"
    if "facebook" in name:
        return "facebook"
    if "email" in name or "mail" in name:
        return "email"
    if "icq" in name:
        return "icq"
    if "aim" in name:
        return "aim"
    return None


# =========================================================
# 4. IPv4/UDP/TCP 解析
# =========================================================
def inet_to_str(x):
    return socket.inet_ntoa(x)


def parse_transport_packet(buf):
    """
    返回:
        flow_key, payload_bytes
    若不是 IPv4 的 TCP/UDP 包，返回 (None, None)
    """
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except Exception:
        return None, None

    ip = eth.data
    if not isinstance(ip, dpkt.ip.IP):
        return None, None

    trans = ip.data
    if isinstance(trans, dpkt.tcp.TCP):
        proto = 6
        sport = int(trans.sport)
        dport = int(trans.dport)
        payload = bytes(trans.data)
    elif isinstance(trans, dpkt.udp.UDP):
        proto = 17
        sport = int(trans.sport)
        dport = int(trans.dport)
        payload = bytes(trans.data)
    else:
        return None, None

    if KEEP_RAW_ONLY and len(payload) == 0:
        return None, None

    src_ip = inet_to_str(ip.src)
    dst_ip = inet_to_str(ip.dst)

    # 双向规范化 key
    ep1 = (src_ip, sport)
    ep2 = (dst_ip, dport)
    if ep1 <= ep2:
        flow_key = (proto, ep1[0], ep1[1], ep2[0], ep2[1])
    else:
        flow_key = (proto, ep2[0], ep2[1], ep1[0], ep1[1])

    return flow_key, payload


# =========================================================
# 5. payload -> tokens
# =========================================================
def payload_to_tokens(payload: bytes):
    # 尽量保留和你旧代码接近的“字符串化后切 token”风格
    text = repr(payload)
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


# =========================================================
# 6. 第一阶段：只建 flow 索引，不存 packet tokens
# =========================================================
def scan_one_pcap_build_flow_meta(pcap_path: Path, vpn_label: int, app_id: int):
    flow_packet_count = defaultdict(int)
    seen = 0

    f, reader = open_dpkt_reader(pcap_path)
    try:
        for _, buf in reader:
            flow_key, payload = parse_transport_packet(buf)
            if flow_key is None:
                continue

            # 第一阶段不做 token 化，只计数
            flow_packet_count[flow_key] += 1

            seen += 1
            if MAX_PACKETS_PER_PCAP is not None and seen >= MAX_PACKETS_PER_PCAP:
                break
    finally:
        f.close()

    return flow_packet_count


def build_flow_index(vpn_pcaps, nonvpn_pcaps):
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
        local_counts = scan_one_pcap_build_flow_meta(pcap_path, vpn_label, app_id)

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
                    "app_id": app_id,
                    "packet_count": pkt_cnt,
                    "split": None,
                }
            else:
                # 理论上一般不会跨文件重合；若重合，这里合并计数
                flow_index[flow_key]["packet_count"] += pkt_cnt

        app_flow_count[app_id] += local_flow_num
        app_packet_count[app_id] += local_packet_num
        if vpn_label == LABEL_VPN:
            vpn_flow_count[app_id] += local_flow_num
        else:
            nonvpn_flow_count[app_id] += local_flow_num

        side = "VPN " if vpn_label == LABEL_VPN else "NON "
        print(f"[phase1 {idx}/{len(jobs)}] [{side}] {pcap_path.name}: flows={local_flow_num} packets={local_packet_num}")

    print("\n=== fixed12 app distribution in full flow pool ===")
    for app_id in sorted(app_flow_count.keys()):
        print(
            f"{ID2APP[app_id]:12s} flow_total={app_flow_count[app_id]:7d} "
            f"vpn={vpn_flow_count[app_id]:7d} nonvpn={nonvpn_flow_count[app_id]:7d} "
            f"packet_total={app_packet_count[app_id]:9d}"
        )

    return flow_index


# =========================================================
# 7. 大类按比例，小类保底：先在 flow 层抽样
# =========================================================
def choose_sample_size_per_app(n_total):
    """
    大类按比例，小类保底。
    SAMPLE_RATIO=1.0 时，相当于不缩样，只走保底逻辑。
    """
    n_keep = int(round(n_total * SAMPLE_RATIO))
    n_keep = max(n_keep, MIN_TOTAL_PER_APP)
    n_keep = min(n_keep, n_total)
    return n_keep


def sample_flows_by_app(flow_index):
    by_app = defaultdict(list)
    for flow_key, meta in flow_index.items():
        by_app[meta["app_id"]].append(flow_key)

    sampled_keys = []
    sampled_count_per_app = {}

    for app_name in FIXED_APP_NAMES:
        app_id = APP2ID[app_name]
        keys = by_app.get(app_id, [])
        n = len(keys)

        if n < MIN_TOTAL_PER_APP:
            raise RuntimeError(
                f"应用类 {app_name} 的 flow 数只有 {n}，无法保证 train/valid/test 都有样本。"
            )

        random.shuffle(keys)
        n_keep = choose_sample_size_per_app(n)
        sampled = keys[:n_keep]

        sampled_keys.extend(sampled)
        sampled_count_per_app[app_id] = n_keep

    print("\n=== after flow sampling ===")
    for app_id in sorted(sampled_count_per_app.keys()):
        print(f"{ID2APP[app_id]:12s}: kept_flows={sampled_count_per_app[app_id]}")

    return sampled_keys


# =========================================================
# 8. 8:1:1 是总体目标，不要求每个小类严格精确
#    这里做法：每类内部切分，但 valid/test 至少 1
# =========================================================
def split_counts_for_one_app(n):
    if n < MIN_TOTAL_PER_APP:
        raise RuntimeError(f"n={n} 太小，无法切分")

    n_valid = max(MIN_VALID_PER_APP, int(round(n * VALID_RATIO)))
    n_test = max(MIN_TEST_PER_APP, int(round(n * TEST_RATIO)))
    n_train = n - n_valid - n_test

    if n_train < MIN_TRAIN_PER_APP:
        # 从 valid/test 借一点回来
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


def assign_splits_binary(sampled_flow_keys, flow_index):
    by_app = defaultdict(list)
    for k in sampled_flow_keys:
        by_app[flow_index[k]["app_id"]].append(k)

    split_flow_keys = {"train": [], "valid": [], "test": []}

    for app_name in FIXED_APP_NAMES:
        app_id = APP2ID[app_name]
        keys = by_app[app_id][:]
        random.shuffle(keys)

        n_train, n_valid, n_test = split_counts_for_one_app(len(keys))

        train_keys = keys[:n_train]
        valid_keys = keys[n_train:n_train + n_valid]
        test_keys = keys[n_train + n_valid:n_train + n_valid + n_test]

        split_flow_keys["train"].extend(train_keys)
        split_flow_keys["valid"].extend(valid_keys)
        split_flow_keys["test"].extend(test_keys)

        print(
            f"[split] {app_name:12s} total={len(keys):6d} "
            f"train={len(train_keys):6d} valid={len(valid_keys):6d} test={len(test_keys):6d}"
        )

    for split_name, keys in split_flow_keys.items():
        for k in keys:
            flow_index[k]["split"] = split_name

    return split_flow_keys


# =========================================================
# 9. flow 统计
# =========================================================
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


# =========================================================
# 10. 第二阶段：重扫 pcap，按 split 导出 packet 样本到临时 jsonl
# =========================================================
def dump_packets_to_tmp(vpn_pcaps, nonvpn_pcaps, flow_index):
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

        f, reader = open_dpkt_reader(pcap_path)
        local_written = 0
        local_seen = 0

        try:
            for _, buf in reader:
                flow_key, payload = parse_transport_packet(buf)
                if flow_key is None:
                    continue

                meta = flow_index.get(flow_key)
                if meta is None:
                    continue

                split_name = meta["split"]
                if split_name not in {"train", "valid", "test"}:
                    continue

                flow_id = meta["flow_id"]
                if MAX_PACKETS_PER_FLOW_EXPORT is not None and exported_per_flow[flow_id] >= MAX_PACKETS_PER_FLOW_EXPORT:
                    continue

                tokens = payload_to_tokens(payload)
                if not tokens:
                    continue

                label_dict = {i: None for i in range(N_TASKS)}
                label_dict[TASK_VPN] = meta["vpn_label"]
                label_dict[TASK_APP] = meta["app_id"]

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

                if MAX_PACKETS_PER_PCAP is not None and local_seen >= MAX_PACKETS_PER_PCAP:
                    break
        finally:
            f.close()

        print(f"[phase2 {idx}/{len(jobs)}] {pcap_path.name}: written_packets={local_written}")

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

    # 额外检查：所有类 valid/test 都有 packet 样本
    for split_name in ("valid", "test"):
        missing = []
        for app_name in FIXED_APP_NAMES:
            app_id = APP2ID[app_name]
            if packet_stats_app[split_name][app_id] <= 0:
                missing.append(app_name)
        if missing:
            raise RuntimeError(f"{split_name} 中以下类没有 packet 样本: {missing}")

    return offsets, offsets_by_label


# =========================================================
# 11. 从 tmp 构造二分类 triplet
# =========================================================
def build_triplets_from_tmp(split_name, offsets, offsets_by_label, out_path: Path, seed=2026):
    rnd = random.Random(seed)
    tmp_path = TMP_DIR / f"{split_name}_packets.jsonl"

    pool_nonvpn = offsets_by_label[LABEL_NONVPN]
    pool_vpn = offsets_by_label[LABEL_VPN]

    if len(pool_nonvpn) == 0 or len(pool_vpn) == 0:
        with open(out_path, "w", encoding="utf-8") as fw:
            pass
        return 0

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
        anchor_label = anchor["label"][TASK_VPN]

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


# =========================================================
# 12. 主流程：当前只做二分类预处理
# =========================================================
def main():
    vpn_pcaps, nonvpn_pcaps = collect_pcaps(ROOT)
    print("VPN pcaps:", len(vpn_pcaps))
    print("NonVPN pcaps:", len(nonvpn_pcaps))

    # ---------- 第一阶段：全量建 flow 索引 ----------
    flow_index = build_flow_index(vpn_pcaps, nonvpn_pcaps)

    full_flow_metas = list(flow_index.values())
    print_flow_stats("full fixed12 pool", full_flow_metas)

    # ---------- 第二阶段之前：flow 抽样 ----------
    sampled_flow_keys = sample_flows_by_app(flow_index)
    sampled_flow_metas = [flow_index[k] for k in sampled_flow_keys]
    print_flow_stats("sampled pool", sampled_flow_metas)

    # ---------- split ----------
    split_flow_keys = assign_splits_binary(sampled_flow_keys, flow_index)

    print_flow_stats("train", [flow_index[k] for k in split_flow_keys["train"]])
    print_flow_stats("valid", [flow_index[k] for k in split_flow_keys["valid"]])
    print_flow_stats("test", [flow_index[k] for k in split_flow_keys["test"]])

    # ---------- 第二阶段：重扫 pcap，导出 packet ----------
    offsets, offsets_by_label = dump_packets_to_tmp(vpn_pcaps, nonvpn_pcaps, flow_index)

    # ---------- 第三阶段：构造二分类 triplet ----------
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