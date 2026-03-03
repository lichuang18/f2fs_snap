#!/usr/bin/env python3
"""
绘图脚本：归一化处理directory_structure.txt数据并生成图表
以snapfs列为基准(base 1)，生成PNG和PDF格式的图表
"""

import matplotlib.pyplot as plt
import numpy as np

# 设置Times New Roman字体
plt.rcParams['font.family'] = 'Times New Roman'
plt.rcParams['font.size'] = 14

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
col_names = ['snapfs', 'btrfs', 'lvm']

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

# 创建柱状图 - 使用中等柔和的浅色系
colors = ['#88C28A', '#7FB3D5', '#F8B195']  # 柔和的绿色、蓝色、橙色
bars = []
for i, (col_name, color) in enumerate(zip(col_names, colors)):
    offset = (i - 1) * width
    bars.append(ax.bar(x + offset, normalized_data[:, i], width,
                       label=col_name, color=color, edgecolor='white', linewidth=0.5))

# 设置坐标轴和标签
ax.set_ylabel('Normalized Time (snapfs = 1.0)', fontweight='bold', fontsize=15)
ax.set_xticks(x)
ax.set_xticklabels(row_names, fontsize=14)
ax.set_ylim(0, max(normalized_data.flatten()) * 1.1)

# 添加网格
ax.grid(True, axis='y', linestyle='--', alpha=0.3)

# 添加图例到图表最上方
ax.legend(loc='upper center', bbox_to_anchor=(0.5, 1.15),
          ncol=3, frameon=False, fontsize=13)

# 添加数值标签
for i, bar_group in enumerate(bars):
    for j, bar in enumerate(bar_group):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2., height,
                f'{height:.2f}',
                ha='center', va='bottom', fontsize=11)

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