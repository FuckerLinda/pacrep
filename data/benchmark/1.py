from pathlib import Path
from collections import defaultdict
import re
import csv

from scapy.all import PcapReader


ROOT = Path("./iscxvpn_raw")

PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}

# 是否只统计带 Raw 负载的包
# True  = 更接近你现在 vpn.py 的样本抽取口径
# False = 统计 pcap 中全部包数
ONLY_RAW = False

# 是否限制每个 pcap 最多读取多少包
# None 表示不限制，完整统计
MAX_PACKETS_PER_PCAP = None


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


def infer_side_from_path(p: Path) -> str:
    s = str(p).lower()
    if "nonvpn-pcap" in s or "nonvpn-pcaps" in s or "nonvpn" in s:
        return "nonvpn"
    if "vpn-pcap" in s or "vpn-pcaps" in s or "\\vpn" in s or "/vpn" in s:
        return "vpn"
    return "unknown"


def infer_raw_app_label_from_name(filename: str):
    """
    沿用你当前 vpn.py 的规则
    """
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
    elif re.search(r"(^|[_\-])scp", name):
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
        return "unknown"


def count_packets_in_pcap(pcap_path: Path, only_raw=False, max_packets=None) -> int:
    count = 0
    pr = None
    try:
        pr = PcapReader(str(pcap_path))
        while True:
            try:
                pkt = pr.read_packet()
                if pkt is None:
                    break
            except EOFError:
                break
            except Exception:
                continue

            if only_raw and ("Raw" not in pkt):
                continue

            count += 1
            if max_packets is not None and count >= max_packets:
                break

    except Exception as e:
        print(f"[WARN] cannot open {pcap_path}: {e}")
        return 0
    finally:
        if pr is not None:
            try:
                pr.close()
            except Exception:
                pass

    return count


def main():
    if not ROOT.exists():
        raise FileNotFoundError(f"Directory not found: {ROOT.resolve()}")

    pcap_files = sorted(
        p for p in ROOT.rglob("*")
        if p.is_file() and p.suffix.lower() in PCAP_SUFFIXES
    )

    print(f"Found {len(pcap_files)} pcap files under: {ROOT.resolve()}")
    print(f"ONLY_RAW = {ONLY_RAW}")
    print(f"MAX_PACKETS_PER_PCAP = {MAX_PACKETS_PER_PCAP}")

    total_packets = 0
    by_side = defaultdict(int)
    by_app = defaultdict(int)
    by_side_app = defaultdict(int)
    by_topdir = defaultdict(int)

    per_file_rows = []

    for i, p in enumerate(pcap_files, 1):
        side = infer_side_from_path(p)
        app = infer_raw_app_label_from_name(p.name)

        # 取 iscxvpn_raw 下的第一层子目录名
        try:
            rel = p.relative_to(ROOT)
            topdir = rel.parts[0] if len(rel.parts) > 1 else "."
        except Exception:
            topdir = "."

        pkt_cnt = count_packets_in_pcap(
            p,
            only_raw=ONLY_RAW,
            max_packets=MAX_PACKETS_PER_PCAP
        )

        total_packets += pkt_cnt
        by_side[side] += pkt_cnt
        by_app[app] += pkt_cnt
        by_side_app[(side, app)] += pkt_cnt
        by_topdir[topdir] += pkt_cnt

        per_file_rows.append({
            "file": str(p),
            "topdir": topdir,
            "side": side,
            "app": app,
            "packet_count": pkt_cnt,
        })

        print(f"[{i:4d}/{len(pcap_files):4d}] {p.name:35s} side={side:7s} app={app:12s} packets={pkt_cnt}")

    print("\n========== OVERALL ==========")
    print(f"Total packets: {total_packets}")

    print("\n========== BY SIDE ==========")
    for k in sorted(by_side):
        print(f"{k:10s}: {by_side[k]}")

    print("\n========== BY TOP-LEVEL SUBDIR ==========")
    for k in sorted(by_topdir):
        print(f"{k:25s}: {by_topdir[k]}")

    print("\n========== BY APP ==========")
    for k in sorted(by_app):
        print(f"{k:12s}: {by_app[k]}")

    print("\n========== BY SIDE + APP ==========")
    for side, app in sorted(by_side_app):
        print(f"{side:7s} | {app:12s}: {by_side_app[(side, app)]}")

    # 导出详细结果
    out_csv = Path("iscxvpn_packet_stats.csv")
    with out_csv.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["file", "topdir", "side", "app", "packet_count"]
        )
        writer.writeheader()
        writer.writerows(per_file_rows)

    print(f"\nDetailed per-file stats saved to: {out_csv.resolve()}")


if __name__ == "__main__":
    main()