#!/usr/bin/env python3
"""
绘制TPCC测试结果的学术风格图表
"""
import numpy as np
import matplotlib.pyplot as plt

# 设置学术风格 - Times New Roman字体
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman']
plt.rcParams['font.size'] = 18
plt.rcParams['axes.labelsize'] = 18
plt.rcParams['xtick.labelsize'] = 18
plt.rcParams['ytick.labelsize'] = 18
plt.rcParams['legend.fontsize'] = 18

def read_tpcc_data(filename):
    """读取TPCC数据"""
    systems = []
    avg_latency = []
    p95_latency = []
    p99_latency = []
    max_latency = []
    tpmc = []

    with open(filename, 'r') as f:
        # 跳过标题行
        next(f)
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 6:
                systems.append(parts[0])
                avg_latency.append(float(parts[1]))
                p95_latency.append(float(parts[2]))
                p99_latency.append(float(parts[3]))
                max_latency.append(float(parts[4]))
                tpmc.append(float(parts[5]))

    return systems, avg_latency, p95_latency, p99_latency, max_latency, tpmc

def plot_tpcc_latency():
    """绘制延迟指标的柱状图"""
    systems, avg_latency, p95_latency, p99_latency, max_latency, tpmc = read_tpcc_data('tpcc.txt')

    # 重新排序为学术常用的顺序: F2FS, SnapFS, Btrfs, Ext4, LVM+Ext4
    order = ['f2fs', 'snapfs', 'btrfs', 'ext4', 'lvm+ext4']
    indices = [systems.index(s) for s in order]

    systems_ordered = [systems[i] for i in indices]
    avg_ordered = [avg_latency[i] for i in indices]
    p95_ordered = [p95_latency[i] for i in indices]
    p99_ordered = [p99_latency[i] for i in indices]
    max_ordered = [max_latency[i] for i in indices]
    tpmc_ordered = [tpmc[i] for i in indices]

    # 创建延迟图表
    fig, ax1 = plt.subplots(1, 1, figsize=(8, 6))

    x = np.arange(len(systems_ordered))
    width = 0.25

    # 使用浅色柔和系颜色和斜线网格填充
    bars1 = ax1.bar(x - width, avg_ordered, width, label='Avg Latency',
                    color='#D6EAF8', hatch='//', edgecolor='black')
    bars2 = ax1.bar(x, p95_ordered, width, label='P95 Latency',
                    color='#FADBD8', hatch='\\\\', edgecolor='black')
    bars3 = ax1.bar(x + width, p99_ordered, width, label='P99 Latency',
                    color='#D5F5E3', hatch='/', edgecolor='black')

    ax1.set_ylabel('Latency (ms)', fontsize=18)
    ax1.set_xticks(x)
    ax1.set_xticklabels(['F2FS', 'SnapFS', 'Btrfs', 'Ext4', 'LVM+Ext4'])
    ax1.legend()
    ax1.grid(True, alpha=0.3, axis='y')

    # 在柱子上添加数值标签 - 注释掉这部分
    # for bars in [bars1, bars2, bars3]:
    #     for bar in bars:
    #         height = bar.get_height()
    #         ax1.text(bar.get_x() + bar.get_width()/2., height,
    #                 f'{height:.1f}',
    #                 ha='center', va='bottom', fontsize=14)

    plt.tight_layout()
    plt.savefig('tpcc_latency.pdf', dpi=300, bbox_inches='tight')
    plt.savefig('tpcc_latency.png', dpi=300, bbox_inches='tight')
    print("延迟图表已保存: tpcc_latency.pdf 和 tpcc_latency.png")

    # 创建TpmC性能图表
    fig, ax2 = plt.subplots(1, 1, figsize=(8, 6))

    colors_tpmc = ['#D6EAF8', '#D5F5E3', '#FADBD8', '#FCF3CF', '#EBDEF0']
    hatches_tpmc = ['/', '\\', '..', '//', '\\\\']

    bars4 = ax2.bar(x, tpmc_ordered, color=colors_tpmc, hatch=hatches_tpmc[0], edgecolor='black')
    # 为每个柱子设置不同的hatch
    for i, bar in enumerate(bars4):
        bar.set_hatch(hatches_tpmc[i])

    ax2.set_ylabel('TpmC (Transactions/min)', fontsize=18)
    ax2.set_xticks(x)
    ax2.set_xticklabels(['F2FS', 'SnapFS', 'Btrfs', 'Ext4', 'LVM+Ext4'])
    ax2.grid(True, alpha=0.3, axis='y')

    # 在柱子上添加数值标签 - 注释掉这部分
    # for bar in bars4:
    #     height = bar.get_height()
    #     ax2.text(bar.get_x() + bar.get_width()/2., height,
    #             f'{height:.1f}',
    #             ha='center', va='bottom', fontsize=14)

    plt.tight_layout()
    plt.savefig('tpcc_throughput.pdf', dpi=300, bbox_inches='tight')
    plt.savefig('tpcc_throughput.png', dpi=300, bbox_inches='tight')
    print("吞吐量图表已保存: tpcc_throughput.pdf 和 tpcc_throughput.png")

    # 打印数据摘要
    print("\nTPCC性能数据摘要:")
    print("="*80)
    print(f"{'System':<12} {'Avg(ms)':<10} {'P95(ms)':<10} {'P99(ms)':<10} {'Max(ms)':<10} {'TpmC':<10}")
    print("="*80)
    for i, sys in enumerate(systems_ordered):
        print(f"{sys:<12} {avg_ordered[i]:<10.1f} {p95_ordered[i]:<10.1f} "
              f"{p99_ordered[i]:<10.1f} {max_ordered[i]:<10.1f} {tpmc_ordered[i]:<10.1f}")

def plot_tpcc_normalized():
    """绘制归一化性能对比图"""
    systems, avg_latency, p95_latency, p99_latency, max_latency, tpmc = read_tpcc_data('tpcc.txt')

    # 以F2FS为基准进行归一化
    f2fs_idx = systems.index('f2fs')
    f2fs_avg = avg_latency[f2fs_idx]
    f2fs_tpmc = tpmc[f2fs_idx]

    # 归一化延迟（越低越好）
    norm_avg = [avg/f2fs_avg for avg in avg_latency]
    norm_p95 = [p95/p95_latency[f2fs_idx] for p95 in p95_latency]
    norm_p99 = [p99/p99_latency[f2fs_idx] for p99 in p99_latency]

    # 归一化TpmC（越高越好）
    norm_tpmc = [tp/f2fs_tpmc for tp in tpmc]

    # 重新排序
    order = ['f2fs', 'snapfs', 'btrfs', 'ext4', 'lvm+ext4']
    indices = [systems.index(s) for s in order]

    systems_ordered = [systems[i] for i in indices]
    norm_avg_ordered = [norm_avg[i] for i in indices]
    norm_p95_ordered = [norm_p95[i] for i in indices]
    norm_p99_ordered = [norm_p99[i] for i in indices]
    norm_tpmc_ordered = [norm_tpmc[i] for i in indices]

    # 创建图表
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # 子图1: 归一化延迟
    x = np.arange(len(systems_ordered))
    width = 0.25

    bars1 = ax1.bar(x - width, norm_avg_ordered, width, label='Avg Latency', color='#4472C4')
    bars2 = ax1.bar(x, norm_p95_ordered, width, label='P95 Latency', color='#ED7D31')
    bars3 = ax1.bar(x + width, norm_p99_ordered, width, label='P99 Latency', color='#A5A5A5')

    ax1.set_xlabel('File System', fontsize=16)
    ax1.set_ylabel('Normalized Latency (F2FS=1.0)', fontsize=16)
    ax1.set_xticks(x)
    ax1.set_xticklabels(['F2FS', 'SnapFS', 'Btrfs', 'Ext4', 'LVM+Ext4'])
    ax1.legend()
    ax1.grid(True, alpha=0.3, axis='y')
    ax1.axhline(y=1.0, color='red', linestyle='--', alpha=0.5, label='F2FS Baseline')

    # 子图2: 归一化TpmC
    colors_tpmc = ['#4472C4', '#70AD47', '#ED7D31', '#FFC000', '#5B9BD5']

    bars4 = ax2.bar(x, norm_tpmc_ordered, color=colors_tpmc)
    ax2.set_xlabel('File System', fontsize=16)
    ax2.set_ylabel('Normalized Throughput (F2FS=1.0)', fontsize=16)
    ax2.set_xticks(x)
    ax2.set_xticklabels(['F2FS', 'SnapFS', 'Btrfs', 'Ext4', 'LVM+Ext4'])
    ax2.grid(True, alpha=0.3, axis='y')
    ax2.axhline(y=1.0, color='red', linestyle='--', alpha=0.5, label='F2FS Baseline')

    plt.tight_layout()
    plt.savefig('tpcc_normalized_performance.pdf', dpi=300, bbox_inches='tight')
    plt.savefig('tpcc_normalized_performance.png', dpi=300, bbox_inches='tight')
    print("\n归一化图表已保存: tpcc_normalized_performance.pdf 和 tpcc_normalized_performance.png")

    plt.show()

if __name__ == '__main__':
    # 绘制延迟图表
    plot_tpcc_latency()