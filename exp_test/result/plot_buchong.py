#!/usr/bin/env python3
import matplotlib.pyplot as plt
import numpy as np

# 原始数据
# no snap seq-w, snap seq-w, no snap rand-w, snap rand-w
data = {
    'WA':        [1.003313407, 1.010985402, 1.003001066, 1.022146304],
    'Avg (μs)':  [7.396,       7,           94.16,      75.884],
    'P99 (μs)':  [15.4,        12.4,        115.6,      90.6],
    'P99.9 (ms)':[24,          16.2,        579.8,      938.6],
    'Perf (MB/s)':[2166,       1969.4,      662.4,      709.2],
}

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
fig.suptitle('F2FS Snapshot Performance (Normalized to No-Snapshot)', fontsize=14, fontweight='bold')

metrics = list(data.keys())
x = np.arange(len(metrics))
width = 0.35

# 左图：顺序写
no_snap_seq = [data[k][0] for k in metrics]
snap_seq = [data[k][1] for k in metrics]

# 归一化：以无快照为基准
norm_seq = [snap_seq[i] / no_snap_seq[i] for i in range(len(metrics))]

bars1 = ax1.bar(x - width/2, [1.0]*5, width, label='No Snap', color='steelblue', edgecolor='black')
bars2 = ax1.bar(x + width/2, norm_seq, width, label='With Snap', color='coral', edgecolor='black')

ax1.axhline(y=1, color='gray', linestyle='--', linewidth=1)
ax1.set_ylabel('Normalized (No Snap = 1.0)')
ax1.set_title('Sequential Write')
ax1.set_xticks(x)
ax1.set_xticklabels(metrics)
ax1.legend()
ax1.set_ylim(0.5, 1.2)

# 标注数值
for bar, val in zip(bars2, norm_seq):
    color = 'green' if val < 1 else 'red'
    ax1.annotate(f'{val:.2f}', xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                ha='center', va='bottom', fontsize=9, color=color, fontweight='bold')

# 右图：随机写
no_snap_rand = [data[k][2] for k in metrics]
snap_rand = [data[k][3] for k in metrics]

norm_rand = [snap_rand[i] / no_snap_rand[i] for i in range(len(metrics))]

bars3 = ax2.bar(x - width/2, [1.0]*5, width, label='No Snap', color='steelblue', edgecolor='black')
bars4 = ax2.bar(x + width/2, norm_rand, width, label='With Snap', color='coral', edgecolor='black')

ax2.axhline(y=1, color='gray', linestyle='--', linewidth=1)
ax2.set_ylabel('Normalized (No Snap = 1.0)')
ax2.set_title('Random Write')
ax2.set_xticks(x)
ax2.set_xticklabels(metrics)
ax2.legend()
ax2.set_ylim(0.5, 1.6)

# 标注数值
for bar, val in zip(bars4, norm_rand):
    color = 'green' if val < 1 else 'red'
    va = 'bottom' if val <= 1.1 else 'top'
    offset = 0.02 if val <= 1.1 else -0.06
    ax2.annotate(f'{val:.2f}', xy=(bar.get_x() + bar.get_width()/2, bar.get_height() + offset),
                ha='center', va=va, fontsize=9, color=color, fontweight='bold')

plt.tight_layout()
plt.savefig('/home/lch/workspace/f2fs_snap/exp_test/result/buchong_perf.png', dpi=150, bbox_inches='tight')
plt.close()

print("图表已保存: buchong_perf.png")

# 打印数据表格
print("\n=== 归一化数据 ===")
print(f"{'Metric':<12} {'Seq NoSnap':>10} {'Seq Snap':>10} {'Seq Ratio':>10} | {'Rand NoSnap':>12} {'Rand Snap':>10} {'Rand Ratio':>10}")
print("-" * 80)
for k in metrics:
    ns, ss, nr, sr = data[k]
    print(f"{k:<12} {ns:>10.2f} {ss:>10.2f} {ss/ns:>10.2f} | {nr:>12.2f} {sr:>10.2f} {sr/nr:>10.2f}")