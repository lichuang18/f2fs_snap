import matplotlib.pyplot as plt
import numpy as np

# 设置字体为 Times New Roman
plt.rcParams['font.family'] = 'Times New Roman'
plt.rcParams['font.size'] = 12

# 读取数据
sizes = ['100M', '500M', '1G', '10G', '20G']
snap_1 = [8340936, 41985752, 85348237, 897979575, 1852390735]
snap_2 = [14928628, 74829626, 152428921, 1554292888, 3183526351]
snap_4 = [30973714, 158544681, 327125151, 3439593312, 7535826075]

# 转换为 ms（ns / 1e6）
snap_1_ms = [x / 1e6 for x in snap_1]
snap_2_ms = [x / 1e6 for x in snap_2]
snap_4_ms = [x / 1e6 for x in snap_4]

# 创建图表
fig, ax = plt.subplots(figsize=(10, 6))

x = np.arange(len(sizes))
width = 0.25

bars1 = ax.bar(x - width, snap_1_ms, width, label='1 snapshot', color='#1f77b4')
bars2 = ax.bar(x, snap_2_ms, width, label='2 snapshots', color='#ff7f0e')
bars3 = ax.bar(x + width, snap_4_ms, width, label='4 snapshots', color='#2ca02c')

# 在柱状图上添加数值标签
def add_value_labels(bars, ax):
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.1f}',
                ha='center', va='bottom', fontsize=9)

add_value_labels(bars1, ax)
add_value_labels(bars2, ax)
add_value_labels(bars3, ax)

ax.set_xlabel('File Size', fontsize=14)
ax.set_ylabel('Activation Latency (ms)', fontsize=14)
ax.set_title('CoW Activation Latency vs File Size with Different Snapshots', fontsize=14, pad=20)
ax.set_xticks(x)
ax.set_xticklabels(sizes)
ax.legend()
ax.grid(axis='y', alpha=0.3, linestyle='--')

plt.tight_layout()
plt.savefig('cow_latency.pdf', format='pdf', dpi=300, bbox_inches='tight')
plt.savefig('cow_latency.png', format='png', dpi=300, bbox_inches='tight')
print("Plot saved as cow_latency.pdf and cow_latency.png")
plt.show()