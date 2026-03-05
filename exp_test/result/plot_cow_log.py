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

# 定义颜色
colors = ['#FFCCCC', '#F9F7ED', '#E1D5E7']

# 创建图表
fig, ax = plt.subplots(figsize=(10, 6))

x = np.arange(len(sizes))
width = 0.25

bars1 = ax.bar(x - width, snap_1_ms, width, label='1 snapshot', color=colors[0])
bars2 = ax.bar(x, snap_2_ms, width, label='2 snapshots', color=colors[1], edgecolor='black', linewidth=0.5)
bars3 = ax.bar(x + width, snap_4_ms, width, label='4 snapshots', color=colors[2])

# 移除了数值标签的添加代码

ax.set_xlabel('Data per Snapshot', fontsize=14)
ax.set_ylabel('Activation Latency (ms)', fontsize=14)
# 删除了 title
ax.set_xticks(x)
ax.set_xticklabels(sizes)
ax.legend()
ax.grid(axis='y', alpha=0.3, linestyle='--')

# 使用对数刻度
ax.set_yscale('log')

plt.tight_layout()
plt.savefig('cow_latency_log.pdf', format='pdf', dpi=300, bbox_inches='tight')
plt.savefig('cow_latency_log.png', format='png', dpi=300, bbox_inches='tight')
print("Log scale plot saved as cow_latency_log.pdf and cow_latency_log.png")
plt.show()