#!/usr/bin/env python3
import matplotlib.pyplot as plt
import numpy as np

# TPCC 数据
tpcc_nosnap = [2.720109054, 6.54, 31.1248, 4445.36]
tpcc_snap = [2.73027163, 6.6, 31.6476, 4432]

# 归一化：以 No Snap 为基准 = 1.0
norm = [tpcc_snap[i] / tpcc_nosnap[i] for i in range(4)]

fig, ax = plt.subplots(figsize=(10, 6))
metrics = ['WA', 'Avg', 'P99', 'Perf']
x = np.arange(len(metrics))
width = 0.35

# No Snap = 1.0 基准线
bars1 = ax.bar(x - width/2, [1.0]*4, width, label='No Snap', color='steelblue', edgecolor='black')
# With Snap 归一化值
bars2 = ax.bar(x + width/2, norm, width, label='With Snap', color='coral', edgecolor='black')

ax.axhline(y=1, color='gray', linestyle='--', linewidth=1.5)
ax.set_ylabel('Normalized (No Snap = 1.0)')
ax.set_title('TPCC: F2FS-Snapshot vs F2FS')
ax.set_xticks(x)
ax.set_xticklabels(metrics)
ax.legend()
ax.grid(axis='y', alpha=0.3)
ax.set_ylim(0.97, 1.03)

for bar, val in zip(bars1, [1.0]*4):
    ax.annotate(f'{val:.3f}', xy=(bar.get_x() + bar.get_width()/2, val + 0.002),
                ha='center', va='bottom', fontsize=9, color='steelblue', fontweight='bold')
for bar, val in zip(bars2, norm):
    color = 'green' if val < 1 else ('red' if val > 1 else 'gray')
    ax.annotate(f'{val:.3f}', xy=(bar.get_x() + bar.get_width()/2, val + 0.002),
                ha='center', va='bottom', fontsize=9, color=color, fontweight='bold')

plt.tight_layout()
plt.savefig('/home/lch/workspace/f2fs_snap/exp_test/result/buchong_tpcc.png', dpi=150, bbox_inches='tight')
plt.close()

print("图表已保存: buchong_tpcc.png")
