import json
import random
import shutil
from pathlib import Path
from collections import Counter

SEED = 2026
random.seed(SEED)

# 原始数据目录
SRC_DIR = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_pacrep")

# 平衡后的新目录
DST_DIR = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_pacrep_balanced")
DST_DIR.mkdir(parents=True, exist_ok=True)

TRAIN_SRC = SRC_DIR / "train.txt"
VALID_SRC = SRC_DIR / "valid.txt"
TEST_SRC  = SRC_DIR / "test.txt"

TRAIN_DST = DST_DIR / "train.txt"
VALID_DST = DST_DIR / "valid.txt"
TEST_DST  = DST_DIR / "test.txt"


def read_jsonl(path: Path):
    """
    读取 jsonl 文件。
    输入:
        path: jsonl 文件路径
    输出:
        items: list[dict]
    """
    items = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            items.append(json.loads(line))
    return items


def write_jsonl(path: Path, items):
    """
    写出 jsonl 文件。
    输入:
        path: 输出路径
        items: list[dict]
    """
    with open(path, "w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")


def get_anchor_binary_label(item):
    """
    从一个 triplet JSON 中取 anchor 的二分类标签。
    约定:
        item["anchor"]["label"]["0"] 或 item["anchor"]["label"][0]
    输出:
        0 / 1
    """
    label = item["anchor"]["label"]
    if "0" in label:
        return label["0"]
    return label[0]


def main():
    print(f"Reading train from: {TRAIN_SRC}")
    train_items = read_jsonl(TRAIN_SRC)

    # 按 anchor 的二分类标签分组
    by_label = {0: [], 1: []}
    for item in train_items:
        y = get_anchor_binary_label(item)
        by_label[y].append(item)

    print("Original train counts:")
    print(f"label 0: {len(by_label[0])}")
    print(f"label 1: {len(by_label[1])}")

    # 取较小类数量，做下采样平衡
    target = min(len(by_label[0]), len(by_label[1]))
    print(f"Balanced target per class: {target}")

    random.shuffle(by_label[0])
    random.shuffle(by_label[1])

    balanced_train = by_label[0][:target] + by_label[1][:target]
    random.shuffle(balanced_train)

    # 写出新的 train.txt
    write_jsonl(TRAIN_DST, balanced_train)

    # valid/test 原封不动复制
    shutil.copy2(VALID_SRC, VALID_DST)
    shutil.copy2(TEST_SRC, TEST_DST)

    # 再检查一次
    new_counts = Counter(get_anchor_binary_label(x) for x in balanced_train)

    print("\nBalanced train counts:")
    print(dict(new_counts))
    print(f"Balanced train total: {len(balanced_train)}")

    print(f"\nDone. New dataset saved to: {DST_DIR}")
    print("Files:")
    print(f"  {TRAIN_DST}")
    print(f"  {VALID_DST}")
    print(f"  {TEST_DST}")


if __name__ == "__main__":
    main()