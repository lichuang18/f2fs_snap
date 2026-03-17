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

# Read data file (skip first column which contains file size labels)
data = np.loadtxt('motivation.txt', skiprows=1, usecols=(1, 2, 3))

# Extract data
file_sizes = ['4K', '16K', '64K', '256K']  # File size labels
snapfs = data[:, 0]  # snapfs-snapshot
btrfs = data[:, 1]   # btrfs-snapshot
lvm = data[:, 2]     # lvm+ext4-snapshot

# Create figure with broken y-axis (single chart, broken axis)
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 6),
                               sharex=True,
                               gridspec_kw={'height_ratios': [1.5, 4]})  # Ratio matches y-axis ranges

# Set bar positions
x = np.arange(len(file_sizes))
width = 0.25  # Width of each bar

# Colors: snapfs (90bff8), btrfs (ffd0a0), lvm+ext4 (dfdfdf)
# 太浅
# colors = ['#DAE8FC', '#F8CECC', '#FFE6CC']
# 太深
# colors = ['#9FC5F8', '#F4A6A6', '#F6B26B']
colors = ['#B7D3FA', '#F6BABA', '#F8C999']


# Upper subplot: show values from 14.5 to 16 (range of 1.5)
bars1_upper = ax1.bar(x - width, snapfs, width, color=colors[0], alpha=0.9, hatch='//', edgecolor='black')
bars2_upper = ax1.bar(x, btrfs, width, color=colors[1], alpha=0.9, hatch='\\', edgecolor='black')
bars3_upper = ax1.bar(x + width, lvm, width, color=colors[2], alpha=0.9, hatch='xx', edgecolor='black')
ax1.set_ylim(14.5, 16)
ax1.set_yticks([15, 16])  # Interval of 1

# Lower subplot: show values from 0 to 4.5 (all normal values)
bars1_lower = ax2.bar(x - width, snapfs, width, color=colors[0], alpha=0.9, hatch='//', edgecolor='black')
bars2_lower = ax2.bar(x, btrfs, width, color=colors[1], alpha=0.9, hatch='\\', edgecolor='black')
bars3_lower = ax2.bar(x + width, lvm, width, color=colors[2], alpha=0.9, hatch='xx', edgecolor='black')
ax2.set_ylim(0, 4.5)
ax2.set_yticks([0, 1, 2, 3, 4])  # Interval of 1

# Add value labels only where bars are visible - REMOVED as requested
# No value labels on bars

# Set labels (no title)
ax2.set_xlabel('Block Size')
# Remove individual ylabels and add centered one on left
ax2.set_ylabel('')
ax1.set_ylabel('')
fig.text(0.005, 0.5, 'WA', ha='center', va='center', rotation='vertical', fontsize=18)

ax1.set_xticks(x)
ax1.set_xticklabels([])
ax2.set_xticks(x)
ax2.set_xticklabels(file_sizes)

# handles = [plt.Rectangle((0,0),1,1, facecolor=colors['f2fs'],  hatch=hatches['f2fs'], edgecolor='black', linewidth=1),
#            plt.Rectangle((0,0),1,1, facecolor=colors['snapfs'], alpha=0.85, hatch=hatches['snapfs'], edgecolor='black', linewidth=1),
#            plt.Rectangle((0,0),1,1, facecolor=colors['snapfs-snap'], alpha=0.85, hatch=hatches['snapfs-snap'], edgecolor='black', linewidth=1)]
# fig.legend(handles, legend_labels, loc='upper center', bbox_to_anchor=(0.5, 1.05), ncol=3, prop={'family': 'Times New Roman'})

hatches = ['/', '\\', 'x']
# Combine legends
handles = [plt.Rectangle((0,0),1,1, facecolor=colors[i],  hatch=hatches[i], edgecolor='black', linewidth=1) for i in range(3)]
labels = ['SnapFS', 'Btrfs', 'LVM+Ext4']
ax1.legend(handles, labels, loc='upper right')

# Add grid
ax1.grid(axis='y', alpha=0.3, linestyle='--')
ax2.grid(axis='y', alpha=0.3, linestyle='--')
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

# Add parallel diagonal lines (true diagonal) with deeper color to break the btrfs 4K bar
# Position for btrfs 4K bar (x[0])
bar_x = x[0]
bar_half_width = width/2
btrfs_dark_color = '#cc8000'  # Deeper orange

# Create true diagonal lines at the break points
# Diagonal lines at bottom of upper plot (14.5)
line_length = bar_half_width * 0.8
ax1.plot([bar_x - line_length, bar_x], [14.5, 14.3],
         color=btrfs_dark_color, linewidth=2, linestyle='-')
ax1.plot([bar_x, bar_x + line_length], [14.3, 14.5],
         color=btrfs_dark_color, linewidth=2, linestyle='-')

# Diagonal lines at top of lower plot (4.5)
ax2.plot([bar_x - line_length, bar_x], [4.5, 4.7],
         color=btrfs_dark_color, linewidth=2, linestyle='-')
ax2.plot([bar_x, bar_x + line_length], [4.7, 4.5],
         color=btrfs_dark_color, linewidth=2, linestyle='-')

# Adjust layout
plt.tight_layout()
plt.savefig('motivation_performance.pdf', bbox_inches='tight')
plt.savefig('motivation_performance.png', bbox_inches='tight')
print('Motivation chart saved as motivation_performance.pdf and motivation_performance.png')
plt.show()