import matplotlib.pyplot as plt
import numpy as np
from matplotlib import rcParams

# 设置全局字体为Times New Roman
rcParams['font.family'] = 'serif'
rcParams['font.serif'] = ['Times New Roman']
rcParams['font.size'] = 18

# 读取数据
data = []
with open('gc.txt', 'r') as f:
    lines = f.readlines()[1:]  # 跳过第一行

for line in lines:
    parts = line.strip().split()
    if len(parts) >= 3:
        time = int(parts[0])  # 时间戳（秒）
        # k单位直接使用，不需要转换
        snapfs_val = float(parts[1].replace('k', ''))  # K IOPS
        f2fs_val = float(parts[2].replace('k', ''))    # K IOPS
        data.append([time, snapfs_val, f2fs_val])

data = np.array(data)
timestamps = data[:, 0]
snapfs_iops = data[:, 1]
f2fs_iops = data[:, 2]

# 创建图形
fig, ax = plt.subplots(figsize=(10, 6))

# 使用浅色柔和的配色
snapfs_color = '#000000'  # 天蓝色
f2fs_color = '#D55E00'    # 浅鲑鱼色

# 绘制两条线：Snapfs用实线，F2FS用虚线
ax.plot(timestamps, snapfs_iops, color=snapfs_color, linewidth=2,
        label='SnapFS', linestyle='-')
ax.plot(timestamps, f2fs_iops, color=f2fs_color, linewidth=2,
        label='F2FS', linestyle='--')

# 设置坐标轴标签
ax.set_xlabel('Time (seconds)')
ax.set_ylabel('IOPS (K)')

# 设置网格
ax.grid(True, linestyle='--', alpha=0.3, linewidth=0.5)

# 设置图例
ax.legend(loc='best', frameon=True, fancybox=True, shadow=False,
          facecolor='white', edgecolor='gray', framealpha=0.9)

# 设置刻度
ax.tick_params(axis='both', which='major', labelsize=18, width=1, length=5)

# 调整边距
plt.tight_layout()

# 保存为高分辨率PDF和PNG
plt.savefig('gc_performance.pdf', dpi=300, bbox_inches='tight')
plt.savefig('gc_performance.png', dpi=300, bbox_inches='tight')

print("GC performance plot generated: gc_performance.pdf and gc_performance.png")