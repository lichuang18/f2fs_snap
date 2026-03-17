#!/usr/bin/env python3
"""
绘制多个文件系统性能数据的CDF图
"""
import numpy as np
import matplotlib.pyplot as plt

# 设置全局字体为Times New Roman和18号字体
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman']
plt.rcParams['font.size'] = 18
plt.rcParams['axes.labelsize'] = 18
plt.rcParams['xtick.labelsize'] = 18
plt.rcParams['ytick.labelsize'] = 18
plt.rcParams['legend.fontsize'] = 18

def read_latency_data(filename):
    """读取延迟数据"""
    data = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    # 第二列是延迟值
                    latency = float(parts[1])
                    data.append(latency)
    except FileNotFoundError:
        print(f"警告: 文件 {filename} 不存在")
        return []
    return data

def plot_multiple_cdf():
    """绘制多个文件系统的CDF图"""
    # 定义文件和对应的标签（调整SnapFS和Btrfs的位置）
    files_labels = [
        ('f2fs.log', 'F2FS'),
        ('snapfs.log', 'SnapFS'),
        ('btrfs.log', 'Btrfs'),
        ('ext4.log', 'Ext4'),
        ('lvm_ext4.log', 'LVM+Ext4')
    ]

    plt.figure(figsize=(12, 8))

    all_data = []
    valid_files = []

    # 读取所有数据
    for filename, label in files_labels:
        data = read_latency_data(filename)
        if data:
            all_data.append(data)
            valid_files.append((filename, label, data))
            print(f"{label} ({filename}): {len(data)} 个数据点")
        else:
            print(f"跳过 {label} ({filename}): 无数据")

    if not valid_files:
        print("没有有效的数据文件!")
        return

    # 找到所有数据的99百分位，用于设置x轴范围
    all_latencies = np.concatenate([data for _, _, data in valid_files])
    x_max = np.percentile(all_latencies, 99) * 1.1

    # 绘制每个文件系统的CDF
    colors = ['blue', 'green', 'red', 'orange', 'purple']

    linestyles = ['-', '--', '-.', ':', (0,(5,2))]

    for i, (filename, label, data) in enumerate(valid_files):
        color = colors[i % len(colors)]
        linestyle=linestyles[i % len(linestyles)]
        sorted_data = np.sort(data)
        cdf = np.arange(1, len(sorted_data) + 1) / len(sorted_data)
        plt.plot(sorted_data, cdf, linewidth=2, label=label, color=color, linestyle=linestyle)

        # 打印统计信息
        print(f"\n{label} 统计信息:")
        print(f"  数据点数: {len(data)}")
        print(f"  最小延迟: {np.min(data):.2f} ms")
        print(f"  最大延迟: {np.max(data):.2f} ms")
        print(f"  平均延迟: {np.mean(data):.2f} ms")
        print(f"  中位数延迟: {np.median(data):.2f} ms")
        print(f"  P90: {np.percentile(data, 90):.2f} ms")
        print(f"  P95: {np.percentile(data, 95):.2f} ms")
        print(f"  P99: {np.percentile(data, 99):.2f} ms")

    plt.xlabel('Latency (ms)', fontsize=18)
    plt.ylabel('Cumulative Probability', fontsize=18)
    plt.grid(True, alpha=0.3)
    plt.xlim(0, x_max)
    plt.legend(fontsize=18)
    plt.tight_layout()

    # 保存图表
    plt.savefig('filesystem_cdf.pdf', dpi=300, bbox_inches='tight')
    plt.savefig('filesystem_cdf.png', dpi=300, bbox_inches='tight')
    print(f"\n图表已保存: filesystem_cdf.pdf 和 filesystem_cdf.png")

    plt.show()

if __name__ == '__main__':
    plot_multiple_cdf()