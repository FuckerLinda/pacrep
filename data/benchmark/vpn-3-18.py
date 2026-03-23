import re
import json
import random
from pathlib import Path
from collections import defaultdict

from scapy.all import PcapReader

# =====================================================
# 0. 配置
# =====================================================
ROOT = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_raw")
OUT_DIR = Path(r"C:\dl\PacRep\data\benchmark\iscxvpn_pacrep")
OUT_DIR.mkdir(parents=True, exist_ok=True)

SEED = 2026
random.seed(SEED)

# PacRep 论文中 ISXW2016/ISCXVPN 的 packet 数量设置
# train: 191541, valid: 600, test: 600
TARGET_TRAIN = 191541
TARGET_VALID = 600
TARGET_TEST = 600

# 调试阶段建议保留上限；正式全量可改成 None
MAX_PACKETS_PER_PCAP = 5000

# PacRep 当前样例数据里标签槽位数是 6
N_TASKS = 6

# task 0: VPN vs NonVPN
TASK_VPN = 0
LABEL_NONVPN = 0
LABEL_VPN = 1

# task 1: 原始应用族标签（先完整保留，后续再决定如何映射成论文里的 12 类）
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
    """
    作用：
        递归扫描 root 目录，收集所有 pcap / pcapng / cap 文件，
        并按文件路径中是否包含 VPN / NonVPN 相关字符串分成两组。

    输入：
        root: Path
            ISCXVPN 原始数据根目录，例如：
            C:\\dl\\PacRep\\data\\benchmark\\iscxvpn_raw

    输出：
        vpn_pcaps, nonvpn_pcaps: tuple[list[Path], list[Path]]
            两个列表，分别存放 VPN 和 NonVPN 对应的 pcap 文件路径。

    大致流程：
        1. 遍历 root 下所有文件
        2. 只保留扩展名属于 .pcap / .pcapng / .cap 的文件
        3. 根据文件路径字符串判断它属于 VPN 还是 NonVPN
        4. 随机打乱两个列表后返回

    注意：
        这里先判断 nonvpn，再判断 vpn，
        是为了避免字符串 "nonvpn" 被 "vpn" 的子串规则误分类。
    """
    vpn_pcaps = []
    nonvpn_pcaps = []

    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in [".pcap", ".pcapng", ".cap"]:
            p_str = str(p).lower()
            # 先判断 nonvpn，避免 "nonvpn" 被 "vpn" 子串误匹配
            if "nonvpn-pcap" in p_str or "nonvpn-pcaps" in p_str or "nonvpn" in p_str:
                nonvpn_pcaps.append(p)
            elif "vpn-pcap" in p_str or "vpn-pcaps" in p_str or "\\vpn" in p_str:
                vpn_pcaps.append(p)

    random.shuffle(vpn_pcaps)
    random.shuffle(nonvpn_pcaps)
    return vpn_pcaps, nonvpn_pcaps


# =====================================================
# 2. 从文件名中推断“原始应用族”
# =====================================================
def infer_raw_app_label_from_name(filename: str):
    """
    作用：
        根据 pcap 文件名中的关键词，推断该文件属于哪个“原始应用族”。

    输入：
        filename: str
            单个 pcap 文件名，例如：
            'vpn_skype_audio1.pcap'、'facebookchat1.pcapng'

    输出：
        int 或 None
            若成功识别，则返回 RAW_APP2ID 中对应的整数标签；
            若无法识别，则返回 None。

    大致流程：
        1. 把文件名转成小写
        2. 按预设关键词依次匹配
        3. 匹配成功则返回对应应用族 id
        4. 若没有任何关键词命中，则返回 None

    说明：
        这里的“原始应用族”不是论文里的 12 类最终标签，
        而是为了先把原始信息尽量保留下来，
        方便后续再映射成二分类/多分类任务。
    """
    name = filename.lower()

    if "aim" in name:
        return RAW_APP2ID["aim"]
    elif "bittorrent" in name:
        return RAW_APP2ID["bittorrent"]
    elif "email" in name or "mail" in name:
        return RAW_APP2ID["email"]
    elif "facebook" in name:
        return RAW_APP2ID["facebook"]
    elif "ftps" in name:
        return RAW_APP2ID["ftps"]
    elif "gmail" in name:
        return RAW_APP2ID["gmail"]
    elif "hangout" in name:
        return RAW_APP2ID["hangouts"]
    elif "icq" in name:
        return RAW_APP2ID["icq"]
    elif "netflix" in name:
        return RAW_APP2ID["netflix"]
    elif re.search(r"(^|[_\-])scp", name):
        return RAW_APP2ID["scp"]
    elif "sftp" in name:
        return RAW_APP2ID["sftp"]
    elif "skype" in name:
        return RAW_APP2ID["skype"]
    elif "spotify" in name:
        return RAW_APP2ID["spotify"]
    elif "vimeo" in name:
        return RAW_APP2ID["vimeo"]
    elif "voipbuster" in name:
        return RAW_APP2ID["voipbuster"]
    elif "youtube" in name:
        return RAW_APP2ID["youtube"]
    else:
        return None


# =====================================================
# 3. packet -> token list
#    当前沿用 preprocess_exp.py 的粗粒度思路
# =====================================================
def packet_to_tokens(pkt):
    """
    作用：
        把单个 scapy packet 转成 PacRep 后续可用的 token 列表。

    输入：
        pkt:
            一个由 scapy 读出来的 packet 对象。

    输出：
        clean_tokens: list[str]
            清洗后的 token 列表。

    大致流程：
        1. 用 repr(pkt) 得到数据包的字符串表示
        2. 按反斜杠和空格进行粗粒度切分
        3. 删除明显泄漏标签的信息字段（如 src/dst/port）
        4. 删除部分高变化字段（如 time/options）
        5. 返回剩余 token 列表

    说明：
        这是一个“较粗糙但够用”的 token 化方式，
        主要目的是先让 PacRep 跑通。
        后续若追求更高质量复现，可以再优化这里的切分规则。
    """
    text = repr(pkt)
    tokens = re.split(r"\\| ", text)

    clean_tokens = []
    for tok in tokens:
        if not tok:
            continue
        tok_lower = tok.lower()

        # 去掉明显泄漏字段
        if ("src" in tok_lower) or ("dst" in tok_lower) or ("port" in tok_lower):
            continue

        # 去掉部分高变字段（可按需再调）
        if ("time" in tok_lower) or ("options" in tok_lower):
            continue

        clean_tokens.append(tok)

    return clean_tokens


# =====================================================
# 4. 从单个 pcap 提取 packet 样本
# =====================================================
def extract_samples_from_pcap(pcap_path: Path, vpn_label: int, app_label: int, max_packets_per_pcap=None):
    """
    作用：
        从单个 pcap 文件中读取 packet，过滤并转换为“样本列表”。

    输入：
        pcap_path: Path
            单个 pcap 文件路径。
        vpn_label: int
            当前文件所属 VPN/NonVPN 标签（0 或 1）。
        app_label: int
            当前文件所属原始应用族标签。
        max_packets_per_pcap: int 或 None
            每个 pcap 最多保留多少个 packet 样本。
            若为 None，则不限制。

    输出：
        samples: list[dict]
            样本列表。每个元素形如：
            {
                "text": [...],
                "label": {0: vpn_label, 1: app_label, 其余任务为 None}
            }

    大致流程：
        1. 用 PcapReader 打开 pcap
        2. 逐包读取
        3. 只保留含 Raw 层的包
        4. 调用 packet_to_tokens() 生成 token 列表
        5. 为每个 packet 构造统一样本字典
        6. 达到 max_packets_per_pcap 时提前停止
        7. 返回该 pcap 的所有样本

    说明：
        这里是“pcap -> packet 样本”的核心转换函数。
        后面 train/valid/test 的构造，都是基于这里产出的样本池。
    """
    samples = []

    try:
        pr = PcapReader(str(pcap_path))
    except Exception as e:
        print(f"[WARN] cannot open {pcap_path}: {e}")
        return samples

    count = 0
    while True:
        try:
            pkt = pr.read_packet()
            if pkt is None:
                break
        except EOFError:
            break
        except Exception:
            continue

        # 先沿用 demo 逻辑：只保留有 Raw 的包
        if 'Raw' not in pkt:
            continue

        tokens = packet_to_tokens(pkt)
        if not tokens:
            continue

        label_dict = {i: None for i in range(N_TASKS)}
        label_dict[TASK_VPN] = vpn_label
        label_dict[TASK_APP] = app_label

        samples.append({
            "text": tokens,
            "label": label_dict
        })

        count += 1
        if max_packets_per_pcap is not None and count >= max_packets_per_pcap:
            break

    try:
        pr.close()
    except Exception:
        pass

    return samples


# =====================================================
# 5. 建立统一 packet 样本池
# =====================================================
def build_sample_pool(vpn_pcaps, nonvpn_pcaps, max_packets_per_pcap=None):
    """
    作用：
        把所有 VPN / NonVPN pcap 逐个读取，并汇总成一个统一的 packet 样本池。

    输入：
        vpn_pcaps: list[Path]
            所有 VPN pcap 文件路径列表。
        nonvpn_pcaps: list[Path]
            所有 NonVPN pcap 文件路径列表。
        max_packets_per_pcap: int 或 None
            单个 pcap 的最大 packet 样本数上限。

    输出：
        pool: list[dict]
            所有 packet 样本组成的统一列表。

    大致流程：
        1. 遍历所有 VPN pcap
           - 从文件名推断应用族标签
           - 调 extract_samples_from_pcap() 提取样本
           - 把样本加入总池
           - 更新统计计数
        2. 遍历所有 NonVPN pcap，重复同样流程
        3. 打印各原始应用族在总样本池中的分布
        4. 返回样本池

    说明：
        这是“构建总样本池”的函数。
        后续 split（train/valid/test）不直接基于 pcap 文件，
        而是基于这里产出的 packet 样本池来做。
    """
    pool = []

    app_count = defaultdict(int)
    vpn_count = defaultdict(int)
    nonvpn_count = defaultdict(int)

    for p in vpn_pcaps:
        app_label = infer_raw_app_label_from_name(p.name)
        if app_label is None:
            print(f"[WARN] unknown raw app label for VPN file: {p.name}")
            continue

        samples = extract_samples_from_pcap(
            pcap_path=p,
            vpn_label=LABEL_VPN,
            app_label=app_label,
            max_packets_per_pcap=max_packets_per_pcap
        )
        print(f"[VPN ] {p.name}: {len(samples)}")
        pool.extend(samples)

        app_count[app_label] += len(samples)
        vpn_count[app_label] += len(samples)

    for p in nonvpn_pcaps:
        app_label = infer_raw_app_label_from_name(p.name)
        if app_label is None:
            print(f"[WARN] unknown raw app label for NonVPN file: {p.name}")
            continue

        samples = extract_samples_from_pcap(
            pcap_path=p,
            vpn_label=LABEL_NONVPN,
            app_label=app_label,
            max_packets_per_pcap=max_packets_per_pcap
        )
        print(f"[NON ] {p.name}: {len(samples)}")
        pool.extend(samples)

        app_count[app_label] += len(samples)
        nonvpn_count[app_label] += len(samples)

    print("\n=== raw app distribution in full pool ===")
    for app_id in sorted(app_count.keys()):
        app_name = ID2RAW_APP[app_id]
        print(
            f"{app_name:12s} total={app_count[app_id]:7d} "
            f"vpn={vpn_count[app_id]:7d} nonvpn={nonvpn_count[app_id]:7d}"
        )

    return pool


# =====================================================
# 6. 按原始应用族分层抽样
#    更贴近 PacRep “基于多分类标签随机抽取训练集”的描述
# =====================================================
def stratified_split_by_raw_app(samples, n_train, n_valid, n_test, seed=2026):
    """
    作用：
        按“原始应用族标签”做分层抽样，把统一样本池划分成 train/valid/test。

    输入：
        samples: list[dict]
            build_sample_pool() 生成的统一 packet 样本池。
        n_train: int
            训练集目标样本数。
        n_valid: int
            验证集目标样本数。
        n_test: int
            测试集目标样本数。
        seed: int
            随机种子，保证划分可复现。

    输出：
        train, valid, test: tuple[list[dict], list[dict], list[dict]]
            三个 split 的样本列表。

    大致流程：
        1. 先按 label[1]（原始应用族）把样本分桶
        2. 每个桶内部打乱
        3. 为每个应用族分配基础 quota：
           - train_quota
           - valid_quota
           - test_quota
        4. 先按 quota 从每类取样本
        5. 剩余样本汇总为 leftovers
        6. 再用 leftovers 把 train/valid/test 补足到目标大小
        7. 最后打乱三个 split 并返回

    说明：
        这是“总样本池 -> train/valid/test”的核心函数。
        它试图让各 split 都尽量保留多种应用族，而不是完全随机切分。
    """
    rnd = random.Random(seed)

    by_app = defaultdict(list)
    for s in samples:
        app = s["label"][TASK_APP]
        by_app[app].append(s)

    for app in by_app:
        rnd.shuffle(by_app[app])

    train, valid, test = [], [], []

    app_ids = sorted(by_app.keys())
    n_classes = len(app_ids)

    train_quota = max(1, n_train // n_classes)
    valid_quota = max(1, n_valid // n_classes)
    test_quota = max(1, n_test // n_classes)

    leftovers = []

    for app in app_ids:
        items = by_app[app]

        t = items[:train_quota]
        v = items[train_quota:train_quota + valid_quota]
        te = items[train_quota + valid_quota:train_quota + valid_quota + test_quota]
        rest = items[train_quota + valid_quota + test_quota:]

        train.extend(t)
        valid.extend(v)
        test.extend(te)
        leftovers.extend(rest)

    rnd.shuffle(leftovers)

    def fill_to_target(target_list, target_size, leftovers_list):
        """
        作用：
            用 leftovers 补足某个 split 到目标大小。

        输入：
            target_list: list
                当前 split 的样本列表。
            target_size: int
                该 split 期望达到的样本总数。
            leftovers_list: list
                还未分配的剩余样本。

        输出：
            leftovers_list: list
                去掉已分配部分后的剩余样本列表。

        流程：
            1. 计算还差多少个样本
            2. 从 leftovers 前面切出 need 个补进去
            3. 返回剩余 leftovers
        """
        need = target_size - len(target_list)
        if need > 0:
            target_list.extend(leftovers_list[:need])
            leftovers_list = leftovers_list[need:]
        return leftovers_list

    leftovers = fill_to_target(train, n_train, leftovers)
    leftovers = fill_to_target(valid, n_valid, leftovers)
    leftovers = fill_to_target(test, n_test, leftovers)

    rnd.shuffle(train)
    rnd.shuffle(valid)
    rnd.shuffle(test)

    return train[:n_train], valid[:n_valid], test[:n_test]


# =====================================================
# 7. 统计 split 分布
# =====================================================
def print_split_stats(name, samples):
    """
    作用：
        打印某个 split（train/valid/test）的样本分布统计。

    输入：
        name: str
            split 名称，例如 "train" / "valid" / "test"
        samples: list[dict]
            该 split 的样本列表

    输出：
        无显式返回值（返回 None）
        主要通过 print 打印统计结果。

    大致流程：
        1. 统计每个原始应用族的样本数
        2. 统计 VPN 与 NonVPN 的样本数
        3. 打印总量、二分类分布、应用族分布

    作用说明：
        这是一个纯诊断/检查函数，
        用于快速判断 split 是否极端失衡、是否丢类。
    """
    by_app = defaultdict(int)
    by_vpn = defaultdict(int)

    for s in samples:
        by_app[s["label"][TASK_APP]] += 1
        by_vpn[s["label"][TASK_VPN]] += 1

    print(f"\n=== {name} stats ===")
    print(f"total: {len(samples)}")
    print(f"vpn={by_vpn[LABEL_VPN]}, nonvpn={by_vpn[LABEL_NONVPN]}")

    for app_id in sorted(by_app.keys()):
        print(f"{ID2RAW_APP[app_id]:12s}: {by_app[app_id]}")


# =====================================================
# 8. 构造 PacRep 三元组
#    当前先按 task0（二分类）构造，便于你先跑 VPN vs NonVPN
# =====================================================
def build_triplets(samples, task_id=TASK_VPN, seed=2026):
    """
    作用：
        把普通样本列表转换成 PacRep 所需的三元组格式：
        anchor / positive / negative。

    输入：
        samples: list[dict]
            普通样本列表。每个元素至少包含：
            - text
            - label
        task_id: int
            用哪个任务标签来定义“同类/异类”。
            当前默认用 TASK_VPN（VPN 二分类）来构造 triplet。
        seed: int
            随机种子，保证 triplet 构造可复现。

    输出：
        triplets: list[dict]
            每个元素形如：
            {
                "anchor": {...},
                "positive": {...},
                "negative": {...}
            }

    大致流程：
        1. 按 task_id 对样本分桶
        2. 对每个 anchor：
           - 从同标签桶里随机抽一个 positive
           - 从异标签桶里随机抽一个 negative
        3. 组成 triplet 结构并保存

    说明：
        这是为 PacRep 的对比学习/三元组训练接口服务的。
        你后续若转向 ASNet，可能不再需要这一层 triplet，
        但当前复现 PacRep 时必须保留。
    """
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
            "negative": negative
        })

    return triplets


# =====================================================
# 9. 写出 jsonl
# =====================================================
def write_jsonl(path: Path, items):
    """
    作用：
        把样本/三元组列表按 JSON Lines 格式写入磁盘。

    输入：
        path: Path
            输出文件路径，例如 train.txt / valid.txt / test.txt
        items: list[dict]
            要写入的样本列表。每个元素会被写成一行 JSON。

    输出：
        无显式返回值（返回 None）

    大致流程：
        1. 以 utf-8 打开目标文件
        2. 遍历 items
        3. 每个元素用 json.dumps 序列化
        4. 每个元素写一行

    说明：
        PacRep 当前读取的就是这种一行一个 JSON 的文本格式。
    """
    with open(path, "w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")


# =====================================================
# 10. 主流程
# =====================================================
def main():
    """
    作用：
        串联整个预处理流程，最终生成 PacRep 可直接读取的：
        - train.txt
        - valid.txt
        - test.txt

    输入：
        无显式参数（直接使用全局配置）

    输出：
        无显式返回值（返回 None）
        最终在 OUT_DIR 下写出三个 jsonl 文件。

    大致流程：
        1. 收集 VPN / NonVPN 的所有 pcap 文件
        2. 从所有 pcap 构建统一 packet 样本池
        3. 按原始应用族对样本池分层抽样，得到 train/valid/test
        4. 打印三个 split 的分布统计
        5. 按 VPN 二分类任务构造 triplet
        6. 把 triplet 写成 train.txt / valid.txt / test.txt

    说明：
        main() 是整个脚本的总入口。
        你运行 `python vpn.py` 时，实际执行的就是这里。
    """
    vpn_pcaps, nonvpn_pcaps = collect_pcaps(ROOT)
    print("VPN pcaps:", len(vpn_pcaps))
    print("NonVPN pcaps:", len(nonvpn_pcaps))

    pool = build_sample_pool(
        vpn_pcaps=vpn_pcaps,
        nonvpn_pcaps=nonvpn_pcaps,
        max_packets_per_pcap=MAX_PACKETS_PER_PCAP
    )

    print("\nTotal packet samples in pool:", len(pool))

    train_samples, valid_samples, test_samples = stratified_split_by_raw_app(
        pool,
        n_train=TARGET_TRAIN,
        n_valid=TARGET_VALID,
        n_test=TARGET_TEST,
        seed=SEED
    )

    print_split_stats("train", train_samples)
    print_split_stats("valid", valid_samples)
    print_split_stats("test", test_samples)

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