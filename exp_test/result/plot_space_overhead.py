# -*- coding: utf-8 -*-
import matplotlib.pyplot as plt
import numpy as np

# Set font to Times New Roman
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman']
plt.rcParams['font.size'] = 18
plt.rcParams['axes.labelsize'] = 18
plt.rcParams['xtick.labelsize'] = 18
plt.rcParams['ytick.labelsize'] = 18
plt.rcParams['legend.fontsize'] = 18

# Data
modify_ratios = ['0', '10%', '20%', '50%', '100%']
btrfs_values = [32, 1200236, 2369384, 5890452, 11698620]
snapfs_values = [4, 1010320, 2010320, 5010320, 10010320]

# Normalize to snapfs baseline (snapfs = 1.0)
btrfs_normalized = [b / s for b, s in zip(btrfs_values, snapfs_values)]
snapfs_normalized = [1.0] * len(snapfs_values)

# Create figure with broken y-axis
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(8, 6),
                               sharex=True,
                               gridspec_kw={'height_ratios': [1, 1.5]})  # Ratio matches y-axis ranges (1:1.5 for 1:1.5)

# Set bar positions
x = np.arange(len(modify_ratios))
width = 0.35

# Colors (light and soft)
colors = ['#A8DADC', '#F1FAEE']
hatches = ['//', '\\\\']

# Upper subplot: show values from 7.5 to 8.5 (range of 1)
bars1_upper = ax1.bar(x - width/2, btrfs_normalized, width, color=colors[0], alpha=0.8, hatch=hatches[0], edgecolor='black', linewidth=1.2)
bars2_upper = ax1.bar(x + width/2, snapfs_normalized, width, color=colors[1], alpha=0.8, hatch=hatches[1], edgecolor='black', linewidth=1.2)
ax1.set_ylim(7.5, 8.5)
ax1.set_yticks([8])  # Interval of 1

# Lower subplot: show values from 0 to 1.5 (all normal values)
bars1_lower = ax2.bar(x - width/2, btrfs_normalized, width, color=colors[0], alpha=0.8, hatch=hatches[0], edgecolor='black', linewidth=1.2)
bars2_lower = ax2.bar(x + width/2, snapfs_normalized, width, color=colors[1], alpha=0.8, hatch=hatches[1], edgecolor='black', linewidth=1.2)
ax2.set_ylim(0, 1.5)
ax2.set_yticks([0, 1])  # Interval of 1

# Set labels (no title)
ax2.set_xlabel('Modification Ratio')
# Remove individual ylabels and add centered one on left
ax2.set_ylabel('')
ax1.set_ylabel('')
fig.text(0.005, 0.5, 'Normalized Space Usage', ha='center', va='center', rotation='vertical', fontsize=18)

ax1.set_xticks(x)
ax1.set_xticklabels([])
ax2.set_xticks(x)
ax2.set_xticklabels(modify_ratios)

# Combine legends
handles = [plt.Rectangle((0,0),1,1, facecolor=colors[i], hatch=hatches[i], edgecolor='black', linewidth=1.2) for i in range(2)]
labels = ['Btrfs', 'SnapFS']
ax1.legend(handles, labels, loc='upper right')

# Add grid
ax1.grid(axis='y', alpha=0.3, linestyle=':')
ax2.grid(axis='y', alpha=0.3, linestyle=':')
ax1.set_axisbelow(True)
ax2.set_axisbelow(True)

# Hide spines between plots
ax1.spines['bottom'].set_visible(False)
ax2.spines['top'].set_visible(False)
ax1.xaxis.tick_top()
ax1.tick_params(labeltop=False)
ax2.xaxis.tick_bottom()

# Add diagonal break lines
d = .015
kwargs = dict(transform=ax1.transAxes, color='k', clip_on=False)
ax1.plot((-d, +d), (-d, +d), **kwargs)
ax1.plot((1 - d, 1 + d), (-d, +d), **kwargs)

kwargs = dict(transform=ax2.transAxes, color='k', clip_on=False)
ax2.plot((-d, +d), (1 - d, 1 + d), **kwargs)
ax2.plot((1 - d, 1 + d), (1 - d, 1 + d), **kwargs)

# Adjust layout
plt.tight_layout()
plt.savefig('space_overhead_normalized.pdf', bbox_inches='tight')
plt.savefig('space_overhead_normalized.png', bbox_inches='tight')
print('Space overhead chart saved as space_overhead_normalized.pdf and space_overhead_normalized.png')

# Print normalized data
print(f"\n归一化后的数据:")
print(f"修改比例\tbtrfs\t\tsnapfs")
for i, ratio in enumerate(modify_ratios):
    print(f"{ratio}\t\t{btrfs_normalized[i]:.2f}x\t\t{snapfs_normalized[i]:.2f}x")

plt.show()