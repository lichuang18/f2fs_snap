# -*- coding: utf-8 -*-
import matplotlib.pyplot as plt
import numpy as np

# Set font to Times New Roman
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.serif'] = ['Times New Roman']
plt.rcParams['font.size'] = 14
plt.rcParams['axes.labelsize'] = 14
plt.rcParams['xtick.labelsize'] = 14
plt.rcParams['ytick.labelsize'] = 14
plt.rcParams['legend.fontsize'] = 12

# Read data file
with open('motivation_new2.txt', 'r') as f:
    lines = f.readlines()

# Parse data
block_sizes = ['4K', '16K', '64K', '256K']

# Store data for each block size
data_by_block = {}

for line in lines[1:]:  # Skip header
    line = line.strip()
    if not line:
        continue

    # Check if it's a block size line
    if any(line.startswith(bs + '-') for bs in block_sizes):
        parts = line.split()
        label = parts[0]  # e.g., "4K-d1"
        bs_label = label.split('-')[0]
        depth_label = label.split('-')[1]
        # Extract numeric value from depth label (d1 -> 1, d2 -> 2, etc.)
        depth_num = int(depth_label[1:]) if depth_label.startswith('d') else depth_label
        btrfs_val = float(parts[1])
        btrfs_wo_val = float(parts[2])
        lvm_val = float(parts[3])
        lvm_wo_val = float(parts[4])

        if bs_label not in data_by_block:
            data_by_block[bs_label] = {
                'depths': [],
                'depth_nums': [],
                'btrfs': [],
                'btrfs_wo': [],
                'lvm': [],
                'lvm_wo': []
            }
        data_by_block[bs_label]['depths'].append(depth_label)
        data_by_block[bs_label]['depth_nums'].append(depth_num)
        data_by_block[bs_label]['btrfs'].append(btrfs_val)
        data_by_block[bs_label]['btrfs_wo'].append(btrfs_wo_val)
        data_by_block[bs_label]['lvm'].append(lvm_val)
        data_by_block[bs_label]['lvm_wo'].append(lvm_wo_val)

# Create figure with 4 subplots (2x2)
fig, axes = plt.subplots(2, 2, figsize=(11, 8.5))

# Colors and markers
colors = ['#E77C8E', '#D9534F', '#7FB3D5', '#2E86C1']
markers = ['o', 's', '^', 'D']
series = [
    ('btrfs', 'Btrfs', colors[0], markers[0]),
    ('btrfs_wo', 'Btrfs w/o snapshot', colors[1], markers[1]),
    ('lvm', 'LVM+Ext4', colors[2], markers[2]),
    ('lvm_wo', 'LVM+Ext4 w/o snapshot', colors[3], markers[3]),
]

# Plot each block size in a subplot
for idx, block_size in enumerate(block_sizes):
    ax = axes[idx // 2, idx % 2]
    data = data_by_block[block_size]

    x = np.arange(len(data['depths']))

    for key, label, color, marker in series:
        ax.plot(
            x,
            data[key],
            color=color,
            marker=marker,
            linewidth=2,
            markersize=6,
            markerfacecolor='white',
            markeredgewidth=1.5,
            label=label,
        )

    # Set labels
    ax.set_ylabel('Write Amplification')
    ax.set_xlabel('Directory Depth')
    ax.set_xticks(x)
    ax.set_xticklabels(data['depth_nums'])
    ax.set_title(f'Block Size: {block_size}')

    # Add grid
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)

# Add legend at the top
handles, labels = axes[0, 0].get_legend_handles_labels()
fig.legend(handles, labels, loc='upper center', ncol=2, bbox_to_anchor=(0.5, 0.98), frameon=False)

# Adjust layout
plt.tight_layout(rect=[0, 0, 1, 0.90])
plt.savefig('motivation_new2.pdf', bbox_inches='tight')
plt.savefig('motivation_new2.png', bbox_inches='tight', dpi=300)
print('Motivation chart saved as motivation_new2.pdf and motivation_new2.png')
plt.show()