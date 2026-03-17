#!/usr/bin/env python3
"""
绘图脚本：归一化处理directory_structure.txt数据并生成图表
以snapfs列为基准(base 1)，生成PNG和PDF格式的图表
"""

import matplotlib.pyplot as plt
import numpy as np

# 设置Times New Roman字体
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman']
plt.rcParams['font.size'] = 18
plt.rcParams['axes.labelsize'] = 18
plt.rcParams['xtick.labelsize'] = 18
plt.rcParams['ytick.labelsize'] = 18
plt.rcParams['legend.fontsize'] = 18

# 读取数据
with open('directory_structure.txt', 'r') as f:
    lines = f.readlines()

data = np.array([
    [34.0, 40.0, 249.0],  # Flat
    [34.0, 36.0, 258.0],  # Deep
    [36.0, 36.0, 262.0],  # Wide
    [25.0, 24.0, 241.0]   # Mix
])

# 获取行名
row_names = ['Flat', 'Deep', 'Wide', 'Mix']
col_names = ['SnapFS', 'Btrfs', 'LVM']

# 归一化：以snapfs列为基准(base 1)
normalized_data = np.zeros_like(data)
for i in range(len(data)):
    base = data[i, 0]  # snapfs列作为基准
    normalized_data[i, :] = data[i, :] / base

# 设置图表样式
fig, ax = plt.subplots(figsize=(10, 6))

# 设置柱状图参数
x = np.arange(len(row_names))
width = 0.25

# 创建柱状图 - 使用浅色柔和系
colors = ['#D6EAF8', '#FADBD8', '#D5F5E3']  # 浅蓝、浅粉、浅绿
hatch_patterns = ['//', '\\\\', '\\']  # 斜线网格填充
bars = []
for i, (col_name, color) in enumerate(zip(col_names, colors)):
    offset = (i - 1) * width
    bars.append(ax.bar(x + offset, normalized_data[:, i], width,
                       label=col_name, color=color, edgecolor='black',
                       hatch=hatch_patterns[i % len(hatch_patterns)], linewidth=0.8))

# 设置坐标轴和标签
ax.set_ylabel('Normalized Time (SnapFS = 1.0)', fontweight='normal', fontsize=18)
ax.set_xticks(x)
ax.set_xticklabels(row_names, fontsize=18)
ax.set_ylim(0, max(normalized_data.flatten()) * 1.1)

# 添加网格
ax.grid(True, axis='y', linestyle='--', alpha=0.3)

# 添加图例到图表最上方
ax.legend(loc='upper center', bbox_to_anchor=(0.5, 1.15),
          ncol=3, frameon=False, fontsize=18)

# 删除了数据标签代码

# 调整布局，为上方图例留出空间
plt.tight_layout(rect=[0, 0, 1, 0.90])

# 保存为PNG和PDF
plt.savefig('directory_structure_normalized.png', dpi=300, bbox_inches='tight')
plt.savefig('directory_structure_normalized.pdf', bbox_inches='tight')

print("图表已生成:")
print("  - directory_structure_normalized.png")
print("  - directory_structure_normalized.pdf")
print("\n归一化后的数据:")
print(f"{'Type':<8} {'snapfs':>10} {'btrfs':>10} {'lvm':>10}")
print("-" * 40)
for i, name in enumerate(row_names):
    print(f"{name:<8} {normalized_data[i, 0]:>10.2f} {normalized_data[i, 1]:>10.2f} {normalized_data[i, 2]:>10.2f}")