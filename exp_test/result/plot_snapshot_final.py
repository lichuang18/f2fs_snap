# -*- coding: utf-8 -*-
import matplotlib.pyplot as plt
import numpy as np

# Set font to Times New Roman
plt.rcParams['font.family'] = 'Times New Roman'
plt.rcParams['font.size'] = 12

# Read data file
data = np.loadtxt('mk_snap.txt', skiprows=1)

# Extract data
x = data[:, 0]  # File count
f2fs = data[:, 1]  # f2fs_snap
btrfs = data[:, 2]  # btrfs_snap
lvm = data[:, 3]    # lvm_snap

# Create figure with two subplots that look like one broken axis
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 6),
                               sharex=True,
                               gridspec_kw={'height_ratios': [1, 1]})

# Set x-axis ticks with custom positions for equal spacing
xtick_labels = [10, 50, 100, 500, 1000, 5000, 10000, 30000, 50000]
xtick_positions = range(len(xtick_labels))  # Equal spacing positions
ax2.set_xticks(xtick_positions)
ax2.set_xticklabels(xtick_labels)

# Plot data with equal spacing x positions
x_positions = range(len(x))
ax1.plot(x_positions, f2fs, marker='o', linewidth=2, label='f2fs_snap', color='#2E86AB', markersize=6)
ax1.plot(x_positions, btrfs, marker='s', linewidth=2, label='btrfs_snap', color='#A23B72', markersize=6)
ax1.plot(x_positions, lvm, marker='^', linewidth=2, label='lvm_snap', color='#F18F01', markersize=6)

ax2.plot(x_positions, f2fs, marker='o', linewidth=2, label='f2fs_snap', color='#2E86AB', markersize=6)
ax2.plot(x_positions, btrfs, marker='s', linewidth=2, label='btrfs_snap', color='#A23B72', markersize=6)
ax2.plot(x_positions, lvm, marker='^', linewidth=2, label='lvm_snap', color='#F18F01', markersize=6)

# Set y-axis limits
ax1.set_ylim(230, 270)   # Upper part for LVM
ax2.set_ylim(0, 40)      # Lower part for f2fs and btrfs

# Remove x-axis labels from upper plot
ax1.set_xticklabels([])

# Set x-axis ticks with custom positions for equal spacing
xtick_labels = [10, 50, 100, 500, 1000, 5000, 10000, 30000, 50000]
xtick_positions = range(len(xtick_labels))  # Equal spacing positions
ax2.set_xticks(xtick_positions)
ax2.set_xticklabels(xtick_labels)

# Add labels - remove individual ylabels and add centered one with proper positioning
ax2.set_xlabel('File Count')
ax2.set_ylabel('')
ax1.set_ylabel('')
fig.text(-0.005, 0.5, 'Time (ms)', ha='center', va='center', rotation='vertical', fontsize=12)
# Remove title and move legend outside top
ax1.legend(loc='upper center', bbox_to_anchor=(0.5, 1.15), ncol=3)

# Add legend - removed old legend call

# Add grids
ax1.grid(True, alpha=0.3)
ax2.grid(True, alpha=0.3)

# Hide the spines between ax1 and ax2
ax1.spines['bottom'].set_visible(False)
ax2.spines['top'].set_visible(False)
ax1.xaxis.tick_top()
ax1.tick_params(labeltop=False)  # don't put tick labels at the top
ax2.xaxis.tick_bottom()

# Add diagonal lines to indicate break
d = .015
kwargs = dict(transform=ax1.transAxes, color='k', clip_on=False)
ax1.plot((-d, +d), (-d, +d), **kwargs)
ax1.plot((1 - d, 1 + d), (-d, +d), **kwargs)

kwargs = dict(transform=ax2.transAxes, color='k', clip_on=False)
ax2.plot((-d, +d), (1 - d, 1 + d), **kwargs)
ax2.plot((1 - d, 1 + d), (1 - d, 1 + d), **kwargs)

# Adjust layout
plt.tight_layout()
plt.savefig('snapshot_performance_final.pdf', dpi=600, bbox_inches='tight')
plt.savefig('snapshot_performance_final.png', dpi=600, bbox_inches='tight')
print('Final broken axis chart saved as snapshot_performance_final.pdf')
plt.show()