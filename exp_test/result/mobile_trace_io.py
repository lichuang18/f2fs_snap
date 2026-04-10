#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
估算版移动端 I/O size 直方图

说明：
1. 这不是对 GitHub 原始 trace 的逐条统计。
2. 这版是基于论文公开的汇总统计做近似重建：
   - total commands
   - avg/sd write req size [pages]
   - avg/sd read req size [pages]
   - read ratio
3. 论文里 page size 按 4KB 处理，因此这里把 page -> KB 换算为 * 4。

输出：
- mobile_io_histogram_estimated.png
- mobile_io_histogram_estimated_summary.csv
- mobile_io_histogram_estimated_by_app.csv
"""

import math
import pandas as pd
import matplotlib.pyplot as plt


# -------------------------------------------------------------------
# 论文 Table 2 的公开汇总统计
# 字段：
# app, total commands, avg/sd write req size [pages], avg/sd read req size [pages], read ratio
#
# 注：
# - write/read req size 单位是 pages
# - 这里按 1 page = 4KB 换算
# -------------------------------------------------------------------
APPS = [
    ("Call of Duty",   2496029, 28.9, 60.7, 11.3, 28.6, 0.91),
    ("Diablo",         1898152, 4.5,  12.6, 5.3,  17.2, 0.82),
    ("Genshin Impact", 1022753, 42.0, 56.4, 11.8, 24.9, 0.94),
    ("Pubg",            658321, 12.4, 31.2, 6.3,  32.0, 0.48),
    ("Slideshow",      4609251, 38.1, 31.6, 4.3,   8.4, 0.94),
    ("Telegram",       1538672, 4.4,  20.1, 15.3, 61.2, 0.24),
    ("YouCut",         8167619, 80.9, 58.2, 29.7,  7.6, 0.99),
]

# 你关心的桶，单位 KB
BUCKET_EDGES_KB = [0, 4, 16, 32, 64, 256, 1024, float("inf")]
BUCKET_LABELS = ["<=4K", "4-16K", "16-32K", "32-64K", "64-256K", "256K-1M", ">1M"]


def lognormal_params(mean: float, sd: float):
    """
    用给定均值/标准差反推对数正态分布参数 mu / sigma。
    """
    var = sd ** 2
    sigma2 = math.log(1 + var / (mean ** 2))
    sigma = math.sqrt(sigma2)
    mu = math.log(mean) - sigma2 / 2
    return mu, sigma


def lognormal_cdf(x: float, mean: float, sd: float):
    """
    对数正态分布 CDF。
    """
    if x <= 0:
        return 0.0
    mu, sigma = lognormal_params(mean, sd)
    z = (math.log(x) - mu) / (sigma * math.sqrt(2))
    return 0.5 * (1 + math.erf(z))


def bucket_probs_from_pages(mean_pages: float, sd_pages: float):
    """
    把请求大小分布映射到 size bucket 上。
    输入单位：pages
    输出：每个 bucket 的概率
    """
    # 论文按 4KB/page
    page_edges = [e / 4 if math.isfinite(e) else float("inf") for e in BUCKET_EDGES_KB]

    probs = []
    for lo, hi in zip(page_edges[:-1], page_edges[1:]):
        c_lo = lognormal_cdf(lo, mean_pages, sd_pages) if lo > 0 else 0.0
        c_hi = 1.0 if not math.isfinite(hi) else lognormal_cdf(hi, mean_pages, sd_pages)
        probs.append(max(0.0, c_hi - c_lo))

    # 数值误差下做一次归一化
    s = sum(probs)
    if s > 0:
        probs = [p / s for p in probs]
    return probs


def infer_read_write_command_split(total_cmds: int, w_avg: float, r_avg: float, read_ratio: float):
    """
    根据 read ratio 反推读命令数 / 写命令数。

    设：
      read_pages  = R * r_avg
      write_pages = W * w_avg
      R + W = total_cmds
      read_ratio = read_pages / (read_pages + write_pages)

    可解出 R 占比。
    """
    read_cmd_frac = (read_ratio * w_avg) / (r_avg * (1 - read_ratio) + read_ratio * w_avg)
    read_cmds = total_cmds * read_cmd_frac
    write_cmds = total_cmds - read_cmds
    return read_cmd_frac, read_cmds, write_cmds


def main():
    rows = []

    overall_all = [0.0] * len(BUCKET_LABELS)
    overall_read = [0.0] * len(BUCKET_LABELS)
    overall_write = [0.0] * len(BUCKET_LABELS)

    for app, total_cmds, w_avg, w_sd, r_avg, r_sd, read_ratio in APPS:
        read_cmd_frac, read_cmds, write_cmds = infer_read_write_command_split(
            total_cmds, w_avg, r_avg, read_ratio
        )

        read_probs = bucket_probs_from_pages(r_avg, r_sd)
        write_probs = bucket_probs_from_pages(w_avg, w_sd)

        read_counts = [read_cmds * p for p in read_probs]
        write_counts = [write_cmds * p for p in write_probs]
        all_counts = [r + w for r, w in zip(read_counts, write_counts)]

        overall_all = [a + b for a, b in zip(overall_all, all_counts)]
        overall_read = [a + b for a, b in zip(overall_read, read_counts)]
        overall_write = [a + b for a, b in zip(overall_write, write_counts)]

        row = {
            "app": app,
            "estimated_total_cmds": total_cmds,
            "estimated_read_cmd_frac": read_cmd_frac,
            "estimated_write_cmd_frac": 1 - read_cmd_frac,
        }

        total_all = sum(all_counts)
        total_read = sum(read_counts)
        total_write = sum(write_counts)

        for label, value in zip(BUCKET_LABELS, all_counts):
            row[f"all_{label}"] = value / total_all if total_all > 0 else 0.0
        for label, value in zip(BUCKET_LABELS, read_counts):
            row[f"read_{label}"] = value / total_read if total_read > 0 else 0.0
        for label, value in zip(BUCKET_LABELS, write_counts):
            row[f"write_{label}"] = value / total_write if total_write > 0 else 0.0

        rows.append(row)

    summary = pd.DataFrame({
        "bucket": BUCKET_LABELS,
        "overall_share": [x / sum(overall_all) for x in overall_all],
        "read_share": [x / sum(overall_read) for x in overall_read],
        "write_share": [x / sum(overall_write) for x in overall_write],
    })

    app_level = pd.DataFrame(rows)

    # 保存 CSV
    summary.to_csv("mobile_io_histogram_estimated_summary.csv", index=False)
    app_level.to_csv("mobile_io_histogram_estimated_by_app.csv", index=False)

    # 画图
    x = range(len(BUCKET_LABELS))
    width = 0.35  # 调整宽度，因为现在只有两个柱子

    # 设置字体为 Times New Roman，大小为 18
    plt.rcParams['font.family'] = 'Times New Roman'
    plt.rcParams['font.size'] = 18

    plt.figure(figsize=(10, 5.5))
    # 只保留 Read 和 Write，使用浅色柔和系颜色并添加斜线填充，添加黑色边框
    plt.bar([i - width/2 for i in x], summary["read_share"], width=width,
            label="Read", color='#B0E0E0', hatch='\\', edgecolor='black')
    plt.bar([i + width/2 for i in x], summary["write_share"], width=width,
            label="Write", color='#FFDAB9', hatch='/', edgecolor='black')

    plt.xticks(list(x), BUCKET_LABELS)
    plt.ylabel("Percentage")
    plt.xlabel("I/O size bucket")
    # 移除了标题 plt.title()
    plt.legend()
    plt.tight_layout()
    plt.savefig("mobile_io_histogram_estimated.png", dpi=200)
    plt.savefig('mobile_io_histogram_estimated.pdf', dpi=300, bbox_inches='tight')
    plt.close()

    print("\n=== Summary ===")
    print(summary.round(4).to_string(index=False))
    print("\n已生成：")
    print("  - mobile_io_histogram_estimated.png")
    print("  - mobile_io_histogram_estimated_summary.csv")
    print("  - mobile_io_histogram_estimated_by_app.csv")


if __name__ == "__main__":
    main()
