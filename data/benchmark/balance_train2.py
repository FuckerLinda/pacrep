import json
import random
from pathlib import Path
from collections import Counter

SEED = 2026
random.seed(SEED)

# 原始数据目录
SRC_DIR = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_pacrep")

# 平衡后的新目录
DST_DIR = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_pacrep_balanced2")
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


def balance_items_by_binary_label(items, split_name="dataset"):
    """
    按 anchor 的二分类标签做下采样平衡。
    输入:
        items: list[dict]
        split_name: 数据集名称，仅用于打印日志
    输出:
        balanced_items: 平衡后的 list[dict]
    """
    by_label = {0: [], 1: []}
    for item in items:
        y = get_anchor_binary_label(item)
        by_label[y].append(item)

    print(f"\nOriginal {split_name} counts:")
    print(f"label 0: {len(by_label[0])}")
    print(f"label 1: {len(by_label[1])}")

    if len(by_label[0]) == 0 or len(by_label[1]) == 0:
        raise ValueError(
            f"{split_name} 中某一类样本数为 0，无法做二分类平衡。"
            f" label0={len(by_label[0])}, label1={len(by_label[1])}"
        )

    # 取较小类数量，做下采样平衡
    target = min(len(by_label[0]), len(by_label[1]))
    print(f"Balanced target per class for {split_name}: {target}")

    random.shuffle(by_label[0])
    random.shuffle(by_label[1])

    balanced_items = by_label[0][:target] + by_label[1][:target]
    random.shuffle(balanced_items)

    new_counts = Counter(get_anchor_binary_label(x) for x in balanced_items)

    print(f"Balanced {split_name} counts:")
    print(dict(new_counts))
    print(f"Balanced {split_name} total: {len(balanced_items)}")

    return balanced_items


def main():
    print(f"Reading train from: {TRAIN_SRC}")
    print(f"Reading valid from: {VALID_SRC}")
    print(f"Reading test  from: {TEST_SRC}")

    train_items = read_jsonl(TRAIN_SRC)
    valid_items = read_jsonl(VALID_SRC)
    test_items  = read_jsonl(TEST_SRC)

    # 对 train / valid / test 都做二分类平衡
    balanced_train = balance_items_by_binary_label(train_items, split_name="train")
    balanced_valid = balance_items_by_binary_label(valid_items, split_name="valid")
    balanced_test  = balance_items_by_binary_label(test_items,  split_name="test")

    # 写出新的 train / valid / test
    write_jsonl(TRAIN_DST, balanced_train)
    write_jsonl(VALID_DST, balanced_valid)
    write_jsonl(TEST_DST, balanced_test)

    print(f"\nDone. New dataset saved to: {DST_DIR}")
    print("Files:")
    print(f"  {TRAIN_DST}")
    print(f"  {VALID_DST}")
    print(f"  {TEST_DST}")


if __name__ == "__main__":
    main()