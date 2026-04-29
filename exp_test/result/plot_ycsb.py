#!/usr/bin/env python3
import matplotlib.pyplot as plt
import numpy as np

# YCSB-A 数据: wa, update avg, update 99, perf, read avg, read 99
ycsb_a_nosnap = [3.877493838, 1771.132971, 3391.666667, 997.5816013, 220.4438451, 621.3333333]
ycsb_a_snap = [3.902385499, 1769.360677, 3349, 997.5288759, 219.9081159, 629.3333333]

# YCSB-F 数据: wa, update avg, update 99, perf, rmw avg, rmw 99, read avg, read 99
ycsb_f_nosnap = [3.881102035, 1783.355319, 3326.333333, 908.9844533, 1989.346527, 3683.666667, 203.7064033, 559]
ycsb_f_snap = [3.901082756, 1679.945296, 3081, 954.2506968, 1883.141465, 3385, 201.1453367, 491.6666667]

# YCSB-A: 取 wa, update avg, update 99, perf (去掉 read)
norm_a = [ycsb_a_snap[i] / ycsb_a_nosnap[i] for i in range(4)]

# YCSB-F: 取 wa, update avg, update 99, perf, rmw avg, rmw 99 (去掉 read)
norm_f = [ycsb_f_snap[i] / ycsb_f_nosnap[i] for i in range(6)]

# ===== YCSB-A =====
fig1, ax1 = plt.subplots(figsize=(10, 6))
metrics_a = ['WA', 'Update\nAvg', 'Update\nP99', 'Perf']
x1 = np.arange(len(metrics_a))
width = 0.35

no_snap_a = [1.0] * 4
snap_a = norm_a

bars1 = ax1.bar(x1 - width/2, no_snap_a, width, label='No Snap', color='steelblue', edgecolor='black')
bars2 = ax1.bar(x1 + width/2, snap_a, width, label='With Snap', color='coral', edgecolor='black')
ax1.axhline(y=1, color='gray', linestyle='--', linewidth=1.5)
ax1.set_ylabel('Normalized (No Snap = 1.0)')
ax1.set_title('YCSB-A')
ax1.set_xticks(x1)
ax1.set_xticklabels(metrics_a)
ax1.set_ylim(0.92, 1.08)
ax1.legend()
ax1.grid(axis='y', alpha=0.3)

for bar, val in zip(bars1, no_snap_a):
    ax1.annotate(f'{val:.3f}', xy=(bar.get_x() + bar.get_width()/2, val + 0.003),
                ha='center', va='bottom', fontsize=9, color='steelblue', fontweight='bold')
for bar, val in zip(bars2, snap_a):
    color = 'green' if val < 1 else ('red' if val > 1 else 'gray')
    ax1.annotate(f'{val:.3f}', xy=(bar.get_x() + bar.get_width()/2, val + 0.003),
                ha='center', va='bottom', fontsize=9, color=color, fontweight='bold')

plt.tight_layout()
plt.savefig('/home/lch/workspace/f2fs_snap/exp_test/result/buchong_ycsb_a.png', dpi=150, bbox_inches='tight')
plt.close()

# ===== YCSB-F =====
fig2, ax2 = plt.subplots(figsize=(12, 6))
metrics_f = ['WA', 'Update\nAvg', 'Update\nP99', 'Perf', 'RMW\nAvg', 'RMW\nP99']
x2 = np.arange(len(metrics_f))

no_snap_f = [1.0] * 6
snap_f = norm_f

bars3 = ax2.bar(x2 - width/2, no_snap_f, width, label='No Snap', color='steelblue', edgecolor='black')
bars4 = ax2.bar(x2 + width/2, snap_f, width, label='With Snap', color='coral', edgecolor='black')
ax2.axhline(y=1, color='gray', linestyle='--', linewidth=1.5)
ax2.set_ylabel('Normalized (No Snap = 1.0)')
ax2.set_title('YCSB-F')
ax2.set_xticks(x2)
ax2.set_xticklabels(metrics_f)
ax2.set_ylim(0.82, 1.08)
ax2.legend()
ax2.grid(axis='y', alpha=0.3)

for bar, val in zip(bars3, no_snap_f):
    ax2.annotate(f'{val:.3f}', xy=(bar.get_x() + bar.get_width()/2, val + 0.003),
                ha='center', va='bottom', fontsize=9, color='steelblue', fontweight='bold')
for bar, val in zip(bars4, snap_f):
    color = 'green' if val < 1 else ('red' if val > 1 else 'gray')
    ax2.annotate(f'{val:.3f}', xy=(bar.get_x() + bar.get_width()/2, val + 0.003),
                ha='center', va='bottom', fontsize=9, color=color, fontweight='bold')

plt.tight_layout()
plt.savefig('/home/lch/workspace/f2fs_snap/exp_test/result/buchong_ycsb_f.png', dpi=150, bbox_inches='tight')
plt.close()

print("图表已保存:")
print("  - buchong_ycsb_a.png (YCSB-A)")
print("  - buchong_ycsb_f.png (YCSB-F)")
