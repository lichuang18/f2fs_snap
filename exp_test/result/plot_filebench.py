#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# 设置全局字体为 Times New Roman
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman']
plt.rcParams['font.size'] = 18
plt.rcParams['axes.labelsize'] = 18
plt.rcParams['xtick.labelsize'] = 18
plt.rcParams['ytick.labelsize'] = 18
plt.rcParams['legend.fontsize'] = 18

# 读取数据
data = pd.read_csv('filebench', sep='\t')

# 将ext4放在最左侧
order = ['ext4', 'f2fs', 'snapfs', 'lvm+f2fs', 'lvm+ext4', 'btrfs']
data = data.set_index(data.columns[0]).reindex(order)

# 创建对应的显示标签
display_labels = {
    'ext4': 'Ext4',
    'f2fs': 'F2FS',
    'snapfs': 'SnapFS',
    'lvm+f2fs': 'LVM+F2FS',
    'lvm+ext4': 'LVM+Ext4',
    'btrfs': 'Btrfs'
}

# 归一化：以ext4为基准1
normalized_data = data.div(data.loc['ext4'])

# 转置，让workload作为x轴
normalized_data = normalized_data.T

# 浅色柔和系颜色（调得更浅更柔和）
colors = {
    'ext4': '#D9E2EC',      # 浅紫灰
    'f2fs': '#C5E8D4',      # 浅绿
    'snapfs': '#F0F4C3',    # 浅黄绿
    'lvm+f2fs': '#FFE0CC',  # 浅橙
    'lvm+ext4': '#FFD1CC',  # 浅红
    'btrfs': '#E8D5D5'      # 浅褐红
}

# 不同的斜线网格填充图案（不同密度和方向）
hatch_patterns = [
    '/',           # ext4 - 普通斜线
    '//',         # f2fs - 更密的斜线
    '\\\\',        # snapfs - 反斜线
    '..',           # lvm+f2fs - 交叉斜线
    'xx',         # lvm+ext4 - 更密的交叉斜线
    '\\\\\\',      # btrfs - 更密的反斜线（与snapfs同向，密度不同）
]

# 创建图表
fig, ax = plt.subplots(figsize=(10, 6))

workloads = normalized_data.index
x = np.arange(len(workloads))
width = 0.13

# 绘制柱状图
for i, fs in enumerate(order):
    offset = (i - len(order)/2 + 0.5) * width
    bar = ax.bar(x + offset, normalized_data[fs], width,
                 label=display_labels[fs], color=colors[fs], edgecolor='black',
                 hatch=hatch_patterns[i % len(hatch_patterns)],
                 alpha=0.9)

# 设置图表标签
ax.set_xlabel('Filebench Workloads', fontweight='normal')
ax.set_ylabel('Normalized Performance (Ext4 = 1.0)', fontweight='normal')
ax.set_xticks(x)
ax.set_xticklabels(workloads)
ax.legend(loc='upper center', bbox_to_anchor=(0.5, 1.25), ncol=3, framealpha=0.9)
ax.set_ylim(0, max(normalized_data.values.flatten()) * 1.2)

# 添加网格
ax.grid(axis='y', alpha=0.3, linestyle='--')
ax.set_axisbelow(True)

plt.tight_layout()
plt.savefig('filebench_normalized.png', dpi=300, bbox_inches='tight')
plt.savefig('filebench_normalized.pdf', bbox_inches='tight')
print("图表已保存为 filebench_normalized.png 和 filebench_normalized.pdf")