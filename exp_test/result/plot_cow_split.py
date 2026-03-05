import matplotlib.pyplot as plt
import numpy as np

# 设置字体为 Times New Roman
plt.rcParams['font.family'] = 'Times New Roman'
plt.rcParams['font.size'] = 12

# 读取数据
sizes_small = ['100M', '500M', '1G']
sizes_large = ['10G', '20G']

snap_1 = [8340936, 41985752, 85348237, 897979575, 1852390735]
snap_2 = [14928628, 74829626, 152428921, 1554292888, 3183526351]
snap_4 = [30973714, 158544681, 327125151, 3439593312, 7535826075]

# 转换为 ms（ns / 1e6）
snap_1_ms = [x / 1e6 for x in snap_1]
snap_2_ms = [x / 1e6 for x in snap_2]
snap_4_ms = [x / 1e6 for x in snap_4]

# 分离大小文件数据
snap_1_small = snap_1_ms[:3]
snap_2_small = snap_2_ms[:3]
snap_4_small = snap_4_ms[:3]

snap_1_large = snap_1_ms[3:]
snap_2_large = snap_2_ms[3:]
snap_4_large = snap_4_ms[3:]

# 定义颜色
colors = ['#82B366', '#F9F7ED', '#E1D5E7']

# 创建两个子图
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

# 小文件图
x1 = np.arange(len(sizes_small))
width = 0.25

bars1 = ax1.bar(x1 - width, snap_1_small, width, label='1 snapshot', color=colors[0])
bars2 = ax1.bar(x1, snap_2_small, width, label='2 snapshots', color=colors[1], edgecolor='black', linewidth=0.5)
bars3 = ax1.bar(x1 + width, snap_4_small, width, label='4 snapshots', color=colors[2])

def add_value_labels(bars, ax):
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.1f}',
                ha='center', va='bottom', fontsize=9)

add_value_labels(bars1, ax1)
add_value_labels(bars2, ax1)
add_value_labels(bars3, ax1)

ax1.set_xlabel('File Size', fontsize=14)
ax1.set_ylabel('Activation Latency (ms)', fontsize=14)
ax1.set_title('Small Files', fontsize=14)
ax1.set_xticks(x1)
ax1.set_xticklabels(sizes_small)
ax1.legend()
ax1.grid(axis='y', alpha=0.3, linestyle='--')

# 大文件图
x2 = np.arange(len(sizes_large))

bars4 = ax2.bar(x2 - width, snap_1_large, width, label='1 snapshot', color=colors[0])
bars5 = ax2.bar(x2, snap_2_large, width, label='2 snapshots', color=colors[1], edgecolor='black', linewidth=0.5)
bars6 = ax2.bar(x2 + width, snap_4_large, width, label='4 snapshots', color=colors[2])

add_value_labels(bars4, ax2)
add_value_labels(bars5, ax2)
add_value_labels(bars6, ax2)

ax2.set_xlabel('File Size', fontsize=14)
ax2.set_ylabel('Activation Latency (ms)', fontsize=14)
ax2.set_title('Large Files', fontsize=14)
ax2.set_xticks(x2)
ax2.set_xticklabels(sizes_large)
ax2.legend()
ax2.grid(axis='y', alpha=0.3, linestyle='--')

plt.tight_layout()
plt.savefig('cow_latency_split.pdf', format='pdf', dpi=300, bbox_inches='tight')
plt.savefig('cow_latency_split.png', format='png', dpi=300, bbox_inches='tight')
print("Split plot saved as cow_latency_split.pdf and cow_latency_split.png")
plt.show()