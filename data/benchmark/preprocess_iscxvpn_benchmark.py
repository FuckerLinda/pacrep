import os
import re
import json
import math
import random
import argparse
from pathlib import Path
from typing import Dict, List, Iterable, Tuple

from scapy.all import PcapReader  # type: ignore
from tqdm import tqdm


RAW_DIRNAME = "iscxvpn_raw"
OUTPUT_DIRNAME = "iscxvpn_binary_fixed12"
TEXT_LEN_LIMIT = None  # 可设为整数，例如 256；None 表示不截断
RANDOM_SEED = 2026


PCAP_SUFFIXES = (".pcap", ".pcapng", ".cap")
VPN_KEYWORDS = ["vpn"]
NONVPN_KEYWORDS = ["nonvpn", "non-vpn", "non_vpn", "novpn"]


def is_pcap_file(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in PCAP_SUFFIXES


def find_pcap_files(folder: Path) -> List[Path]:
    files: List[Path] = []
    for p in folder.rglob("*"):
        if is_pcap_file(p):
            files.append(p)
    return sorted(files)


def infer_group_from_dirname(dirname: str) -> str:
    """
    根据目录名判断属于 vpn 还是 nonvpn。
    优先匹配 nonvpn，再匹配 vpn，避免 nonvpn 被 vpn 误判。
    """
    name = dirname.lower()
    if any(k in name for k in NONVPN_KEYWORDS):
        return "nonvpn"
    if any(k in name for k in VPN_KEYWORDS):
        return "vpn"
    raise ValueError(f"无法从目录名判断类别，请检查目录名: {dirname}")


def choose_subset(files: List[Path], denominator: int, seed: int) -> List[Path]:
    if not files:
        return []
    rng = random.Random(seed)
    files = files[:]
    rng.shuffle(files)
    k = max(1, len(files) // denominator)
    return sorted(files[:k])


def packet_to_repr_lines(pcap_path: Path) -> Iterable[str]:
    try:
        reader = PcapReader(str(pcap_path))
    except Exception as e:
        print(f"[WARN] 打开失败: {pcap_path} -> {e}")
        return

    with reader:
        while True:
            try:
                pkt = reader.read_packet()
            except EOFError:
                break
            except Exception as e:
                print(f"[WARN] 读取报文失败: {pcap_path} -> {e}")
                break

            if pkt is None:
                break

            try:
                if 'Raw' in pkt:
                    yield repr(pkt)
            except Exception:
                continue


def clean_and_tokenize(pkt_repr: str, text_len_limit: int = None) -> List[str]:
    """
    与 demo 思路保持一致：
    1. 先对 repr(pkt) 进行 re.split(r'\\| ', line)
    2. 去掉 src/dst/port 相关 token
    3. 过滤空串
    """
    parts = re.split(r'\\| ', pkt_repr)
    cleaned: List[str] = []
    for token in parts:
        if not token:
            continue
        lower = token.lower()
        if 'src' in lower or 'dst' in lower or 'port' in lower:
            continue
        cleaned.append(token)

    if text_len_limit is not None and text_len_limit > 0:
        cleaned = cleaned[:text_len_limit]
    return cleaned


def make_triplet_record(tokens: List[str], label_value: int) -> str:
    tmp = {
        "text": tokens,
        "label": {0: label_value, 1: None, 2: None, 3: None, 4: None, 5: None},
    }
    tr = {"anchor": tmp, "positive": tmp, "negative": tmp}
    return json.dumps(tr, ensure_ascii=False)


def write_class_texts(
    raw_root: Path,
    output_root: Path,
    denominator: int,
    seed: int,
    text_len_limit: int = None,
) -> Dict[str, int]:
    """
    第一步：从原始 pcap 提取文本，分别写成 nonvpn.txt / vpn.txt。
    这里按“文件级别”做 1/30 抽样：每个原始子目录只抽取约 1/30 的 pcap 文件。
    """
    stats = {"vpn_packets": 0, "nonvpn_packets": 0, "vpn_pcaps": 0, "nonvpn_pcaps": 0}
    grouped_records: Dict[str, List[str]] = {"vpn": [], "nonvpn": []}

    subdirs = [p for p in raw_root.iterdir() if p.is_dir()]
    if not subdirs:
        raise FileNotFoundError(f"在 {raw_root} 下没有找到子目录")

    for subdir in sorted(subdirs):
        group = infer_group_from_dirname(subdir.name)
        all_pcaps = find_pcap_files(subdir)
        chosen_pcaps = choose_subset(all_pcaps, denominator=denominator, seed=seed)
        print(f"[INFO] {subdir.name}: 共 {len(all_pcaps)} 个 pcap，抽取 {len(chosen_pcaps)} 个，类别={group}")

        if group == "vpn":
            stats["vpn_pcaps"] += len(chosen_pcaps)
        else:
            stats["nonvpn_pcaps"] += len(chosen_pcaps)

        label_value = 1 if group == "vpn" else 0

        for pcap_path in tqdm(chosen_pcaps, desc=f"extract-{subdir.name}"):
            for pkt_repr in packet_to_repr_lines(pcap_path):
                tokens = clean_and_tokenize(pkt_repr, text_len_limit=text_len_limit)
                if not tokens:
                    continue
                grouped_records[group].append(make_triplet_record(tokens, label_value))
                if group == "vpn":
                    stats["vpn_packets"] += 1
                else:
                    stats["nonvpn_packets"] += 1

    (output_root / "vpn.txt").write_text("\n".join(grouped_records["vpn"]), encoding="utf-8")
    (output_root / "nonvpn.txt").write_text("\n".join(grouped_records["nonvpn"]), encoding="utf-8")
    return stats


def read_jsonl_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f if line.strip()]


def stratified_split(
    vpn_lines: List[str],
    nonvpn_lines: List[str],
    train_ratio: float,
    valid_ratio: float,
    test_ratio: float,
    seed: int,
) -> Tuple[List[str], List[str], List[str]]:
    total_ratio = train_ratio + valid_ratio + test_ratio
    if not math.isclose(total_ratio, 1.0, rel_tol=1e-6, abs_tol=1e-6):
        raise ValueError("train_ratio + valid_ratio + test_ratio 必须等于 1")

    rng = random.Random(seed)

    def split_one_class(lines: List[str]) -> Tuple[List[str], List[str], List[str]]:
        lines = lines[:]
        rng.shuffle(lines)
        n = len(lines)
        n_train = int(n * train_ratio)
        n_valid = int(n * valid_ratio)
        n_test = n - n_train - n_valid

        # 尽量避免某个集合为空；样本太少时允许为空
        if n >= 3:
            n_train = max(1, n_train)
            n_valid = max(1, n_valid)
            n_test = max(1, n - n_train - n_valid)
            while n_train + n_valid + n_test > n:
                if n_train >= n_valid and n_train >= n_test and n_train > 1:
                    n_train -= 1
                elif n_valid >= n_train and n_valid >= n_test and n_valid > 1:
                    n_valid -= 1
                elif n_test > 1:
                    n_test -= 1
                else:
                    break
            while n_train + n_valid + n_test < n:
                n_train += 1

        train = lines[:n_train]
        valid = lines[n_train:n_train + n_valid]
        test = lines[n_train + n_valid:n_train + n_valid + n_test]
        return train, valid, test

    n_train, n_valid, n_test = split_one_class(nonvpn_lines)
    v_train, v_valid, v_test = split_one_class(vpn_lines)

    train = n_train + v_train
    valid = n_valid + v_valid
    test = n_test + v_test
    rng.shuffle(train)
    rng.shuffle(valid)
    rng.shuffle(test)
    return train, valid, test


def write_splits(split_root: Path, train: List[str], valid: List[str], test: List[str]) -> None:
    split_root.mkdir(parents=True, exist_ok=True)
    (split_root / "train.txt").write_text("\n".join(train), encoding="utf-8")
    (split_root / "valid.txt").write_text("\n".join(valid), encoding="utf-8")
    (split_root / "test.txt").write_text("\n".join(test), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Preprocess ISCXVPN raw pcaps for PacRep-style reproduction")
    parser.add_argument("--data-root", type=str, default="./data/benchmark", help="benchmark 根目录")
    parser.add_argument("--raw-dir", type=str, default=RAW_DIRNAME, help="原始 pcap 目录名")
    parser.add_argument("--out-dir", type=str, default=OUTPUT_DIRNAME, help="输出目录名")
    parser.add_argument("--sample-denominator", type=int, default=30, help="抽样分母；30 表示抽 1/30")
    parser.add_argument("--train-ratio", type=float, default=0.8, help="训练集比例")
    parser.add_argument("--valid-ratio", type=float, default=0.1, help="验证集比例")
    parser.add_argument("--test-ratio", type=float, default=0.1, help="测试集比例")
    parser.add_argument("--seed", type=int, default=RANDOM_SEED, help="随机种子")
    parser.add_argument("--text-len-limit", type=int, default=0, help="token 截断长度；0 表示不截断")
    args = parser.parse_args()

    benchmark_root = Path(args.data_root)
    raw_root = benchmark_root / args.raw_dir
    output_root = benchmark_root / args.out_dir
    split_root = output_root / "data"

    output_root.mkdir(parents=True, exist_ok=True)
    split_root.mkdir(parents=True, exist_ok=True)

    text_len_limit = args.text_len_limit if args.text_len_limit > 0 else None

    print(f"[INFO] raw_root    = {raw_root.resolve()}")
    print(f"[INFO] output_root = {output_root.resolve()}")
    print(f"[INFO] split_root  = {split_root.resolve()}")
    print(f"[INFO] sample 1/{args.sample_denominator}")

    stats = write_class_texts(
        raw_root=raw_root,
        output_root=output_root,
        denominator=args.sample_denominator,
        seed=args.seed,
        text_len_limit=text_len_limit,
    )

    vpn_lines = read_jsonl_lines(output_root / "vpn.txt")
    nonvpn_lines = read_jsonl_lines(output_root / "nonvpn.txt")

    train, valid, test = stratified_split(
        vpn_lines=vpn_lines,
        nonvpn_lines=nonvpn_lines,
        train_ratio=args.train_ratio,
        valid_ratio=args.valid_ratio,
        test_ratio=args.test_ratio,
        seed=args.seed,
    )
    write_splits(split_root, train, valid, test)

    print("\n[INFO] ===== 统计信息 =====")
    print(f"vpn pcap 数      : {stats['vpn_pcaps']}")
    print(f"nonvpn pcap 数   : {stats['nonvpn_pcaps']}")
    print(f"vpn 报文数       : {stats['vpn_packets']}")
    print(f"nonvpn 报文数    : {stats['nonvpn_packets']}")
    print(f"train 样本数     : {len(train)}")
    print(f"valid 样本数     : {len(valid)}")
    print(f"test 样本数      : {len(test)}")
    print(f"类别文件目录     : {output_root.resolve()}")
    print(f"切分文件目录     : {split_root.resolve()}")


if __name__ == "__main__":
    main()