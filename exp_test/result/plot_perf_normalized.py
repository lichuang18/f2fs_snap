import matplotlib.pyplot as plt
import numpy as np
import matplotlib as mpl

# 设置学术风格 - 确保所有字体都是 Times New Roman 18号
mpl.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Times New Roman'],
    'font.size': 18,
    'axes.labelsize': 18,
    'axes.titlesize': 18,
    'xtick.labelsize': 18,
    'ytick.labelsize': 18,
    'legend.fontsize': 18,
    'text.usetex': False,  # 不使用 LaTeX，直接使用系统字体
})

# 数据
rand_block_sizes = ['4K', '16K', '64K']
seq_block_sizes = ['256K', '512K', '1M']

# 随机读 IOPS
rand_read_iops = {
    'f2fs': [242, 124, 39.5],
    'snapfs': [241, 122, 39.3],
    'snapfs-snap': [241, 122, 39.3],
}

# 随机写 IOPS
rand_write_iops = {
    'f2fs': [304, 152, 42.1],
    'snapfs': [288, 149, 41.5],
    'snapfs-snap': [286, 147, 41.9],
}

# 顺序读带宽
seq_read_bw = {
    'f2fs': [3435, 3444, 3434],
    'snapfs': [3435, 3433, 3433],
    'snapfs-snap': [3435, 3437, 3435],
}

# 顺序写带宽
seq_write_bw = {
    'f2fs': [2604, 2627, 2644],
    'snapfs': [2576, 2571, 2566],
    'snapfs-snap': [2573, 2589, 2544],
}

# 归一化函数：以f2fs为基准（100%）
def normalize(data_dict, baseline_key='f2fs'):
    baseline = np.array(data_dict[baseline_key])
    normalized = {}
    for key, values in data_dict.items():
        normalized[key] = [v / b * 100 for v, b in zip(values, baseline)]
    return normalized

# 归一化所有数据
rand_read_norm = normalize(rand_read_iops)
rand_write_norm = normalize(rand_write_iops)
seq_read_norm = normalize(seq_read_bw)
seq_write_norm = normalize(seq_write_bw)

x_rand = np.arange(len(rand_block_sizes))
x_seq = np.arange(len(seq_block_sizes))
width = 0.25

# 创建4个子图 - 1x4布局
fig, axes = plt.subplots(1, 4, figsize=(20, 5))

# 柔和的浅色系配色
colors = {
    'f2fs': '#BAC8D3',      # 淡天蓝
    'snapfs': '#D5E8D4',    # 淡薄荷绿
    'snapfs-snap': '#F5B7B1' # 淡玫瑰红
}

# 柱子填充图案 - 使用不同的hatch pattern
hatches = {
    'f2fs': '/',      # 斜线填充
    'snapfs': '//',    # 点状填充
    'snapfs-snap': '\\\\' # 叉形填充
}

# 公用图例标签
legend_labels = ['F2FS (baseline)', 'SnapFS', 'SnapFS with snapshot']

# 随机读 IOPS
ax1 = axes[0]
for i, (fs, data) in enumerate(rand_read_norm.items()):
    offset = (i - 1) * width
    ax1.bar(x_rand + offset, data, width, label=fs, color=colors[fs], alpha=0.85,
            edgecolor='black', linewidth=0.5, hatch=hatches[fs])
# ax1.set_xlabel('Block Size')
ax1.set_ylabel('Normalized IOPS (%)')
ax1.text(0.5, -0.18, '(a) Random Read IOPS', transform=ax1.transAxes, ha='center', fontweight='bold', family='Times New Roman')
ax1.set_xticks(x_rand)
ax1.set_xticklabels(rand_block_sizes, family='Times New Roman')
# 三种网格：主网格（实线）、次网格（虚线）、背景网格
ax1.grid(True, which='major', axis='y', alpha=0.7, linestyle='-', linewidth=0.8, color='gray')
ax1.grid(True, which='minor', axis='y', alpha=0.5, linestyle='--', linewidth=0.5, color='lightgray')
ax1.minorticks_on()
ax1.set_ylim(95, 105)

# 随机写 IOPS
ax2 = axes[1]
for i, (fs, data) in enumerate(rand_write_norm.items()):
    offset = (i - 1) * width
    ax2.bar(x_rand + offset, data, width, label=fs, color=colors[fs], alpha=0.85,
            edgecolor='black', linewidth=0.5, hatch=hatches[fs])
# ax2.set_xlabel('Block Size')
ax2.set_ylabel('Normalized IOPS (%)')
ax2.text(0.5, -0.18, '(b) Random Write IOPS', transform=ax2.transAxes, ha='center', fontweight='bold', family='Times New Roman')
ax2.set_xticks(x_rand)
ax2.set_xticklabels(rand_block_sizes, family='Times New Roman')
ax2.grid(True, which='major', axis='y', alpha=0.7, linestyle='-', linewidth=0.8, color='gray')
ax2.grid(True, which='minor', axis='y', alpha=0.5, linestyle='--', linewidth=0.5, color='lightgray')
ax2.minorticks_on()
ax2.set_ylim(90, 105)

# 顺序读带宽
ax3 = axes[2]
for i, (fs, data) in enumerate(seq_read_norm.items()):
    offset = (i - 1) * width
    ax3.bar(x_seq + offset, data, width, label=fs, color=colors[fs], alpha=0.85,
            edgecolor='black', linewidth=0.5, hatch=hatches[fs])
# ax3.set_xlabel('Block Size')
ax3.set_ylabel('Normalized Bandwidth (%)')
ax3.text(0.5, -0.18, '(c) Sequential Read Bandwidth', transform=ax3.transAxes, ha='center', fontweight='bold', family='Times New Roman')
ax3.set_xticks(x_seq)
ax3.set_xticklabels(seq_block_sizes, family='Times New Roman')
ax3.grid(True, which='major', axis='y', alpha=0.7, linestyle='-', linewidth=0.8, color='gray')
ax3.grid(True, which='minor', axis='y', alpha=0.5, linestyle='--', linewidth=0.5, color='lightgray')
ax3.minorticks_on()
ax3.set_ylim(99, 101)

# 顺序写带宽
ax4 = axes[3]
for i, (fs, data) in enumerate(seq_write_norm.items()):
    offset = (i - 1) * width
    ax4.bar(x_seq + offset, data, width, label=fs, color=colors[fs], alpha=0.85,
            edgecolor='black', linewidth=0.5, hatch=hatches[fs])
# ax4.set_xlabel('Block Size')
ax4.set_ylabel('Normalized Bandwidth (%)')
ax4.text(0.5, -0.18, '(d) Sequential Write Bandwidth', transform=ax4.transAxes, ha='center', fontweight='bold', family='Times New Roman')
ax4.set_xticks(x_seq)
ax4.set_xticklabels(seq_block_sizes, family='Times New Roman')
ax4.grid(True, which='major', axis='y', alpha=0.7, linestyle='-', linewidth=0.8, color='gray')
ax4.grid(True, which='minor', axis='y', alpha=0.5, linestyle='--', linewidth=0.5, color='lightgray')
ax4.minorticks_on()
ax4.set_ylim(90, 102)

# 创建公用图例在顶部
handles = [plt.Rectangle((0,0),1,1, facecolor=colors['f2fs'],  hatch=hatches['f2fs'], edgecolor='black', linewidth=1),
           plt.Rectangle((0,0),1,1, facecolor=colors['snapfs'], alpha=0.85, hatch=hatches['snapfs'], edgecolor='black', linewidth=1),
           plt.Rectangle((0,0),1,1, facecolor=colors['snapfs-snap'], alpha=0.85, hatch=hatches['snapfs-snap'], edgecolor='black', linewidth=1)]
fig.legend(handles, legend_labels, loc='upper center', bbox_to_anchor=(0.5, 1.05), ncol=3, prop={'family': 'Times New Roman'})

plt.tight_layout(rect=[0, 0, 1, 0.95])
plt.savefig('/home/lch/workspace/f2fs_snap/exp_test/result/perf_comparison.pdf',
            format='pdf', dpi=600, bbox_inches='tight')
plt.savefig('/home/lch/workspace/f2fs_snap/exp_test/result/perf_comparison.png',
            format='png', dpi=600, bbox_inches='tight')
print("图表已保存为 perf_comparison.pdf 和 perf_comparison.png")
plt.show()