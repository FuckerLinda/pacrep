from pathlib import Path

ROOT = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_raw")

# 这里的键就是你想检测的“类别关键词”
KEYWORDS = [
    "aim",
    "bittorrent",
    "email",
    "facebook",
    "ftps",
    "gmail",
    "hangout",
    "icq",
    "netflix",
    "scp",
    "sftp",
    "skype",
    "spotify",
    "vimeo",
    "voipbuster",
    "youtube",
]

VALID_SUFFIX = {".pcap", ".pcapng", ".cap"}


def collect_pcaps(root: Path):
    files = []
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in VALID_SUFFIX:
            files.append(p)
    return sorted(files)


def detect_keywords(filename: str, keywords):
    name = filename.lower()
    matched = [kw for kw in keywords if kw in name]
    return matched


def main():
    files = collect_pcaps(ROOT)

    print(f"Total pcap files: {len(files)}\n")

    multi_hit = []
    zero_hit = []

    for p in files:
        matched = detect_keywords(p.name, KEYWORDS)

        # 打印相对路径 + 命中关键词
        rel = p.relative_to(ROOT)
        print(f"{rel} -> {matched}")

        if len(matched) == 0:
            zero_hit.append(rel)
        elif len(matched) > 1:
            multi_hit.append((rel, matched))

    print("\n" + "=" * 80)
    print("Files with ZERO keyword match:")
    for item in zero_hit:
        print(item)

    print("\n" + "=" * 80)
    print("Files with MULTIPLE keyword matches:")
    for item, matched in multi_hit:
        print(f"{item} -> {matched}")

    print("\n" + "=" * 80)
    print(f"Zero-match count   : {len(zero_hit)}")
    print(f"Multi-match count  : {len(multi_hit)}")


if __name__ == "__main__":
    main()