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
plt.rcParams['legend.fontsize'] = 16

# Read data file
with open('motivation4.txt', 'r') as f:
    lines = f.readlines()

# Clean and filter lines
clean_lines = []
for line in lines:
    stripped = line.strip()
    if stripped:  # Skip empty lines
        clean_lines.append(stripped)

# Parse Btrfs data (first 3 non-empty lines)
btrfs_header = clean_lines[0].split('\t')
btrfs_block_sizes = [x for x in btrfs_header if x]  # Remove empty strings
btrfs_normal = [float(x) for x in clean_lines[1].split('\t')[1:] if x]
btrfs_snap = [float(x) for x in clean_lines[2].split('\t')[1:] if x]

# Parse LVM data (next 3 non-empty lines)
lvm_header = clean_lines[3].split('\t')
lvm_block_sizes = [x for x in lvm_header if x]
lvm_normal = [float(x) for x in clean_lines[4].split('\t')[1:] if x]
lvm_snap = [float(x) for x in clean_lines[5].split('\t')[1:] if x]

# Create figure with 2 subplots - width=10, height=5
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5))

# Colors and hatches
colors = ['#F2BA02', '#71BFB2']
hatches = ['\\', '/']
# colors = ['#AD0B08', '#71BFB2', '#EC817E', '#F2BA02', '#2ca02c'] 
# X-axis positions
x = np.arange(len(btrfs_block_sizes))
width = 0.35

# First subplot - Btrfs
bars1_btrfs = ax1.bar(x - width/2, btrfs_normal, width,
                      label='Normal',
                      color=colors[0], alpha=0.9, hatch=hatches[0], edgecolor='black')
bars2_btrfs = ax1.bar(x + width/2, btrfs_snap, width,
                      label='Snapshot',
                      color=colors[1], alpha=0.9, hatch=hatches[1], edgecolor='black')

ax1.set_ylabel('Normalized Throughput')
ax1.set_xticks(x)
ax1.set_xticklabels(btrfs_block_sizes)
ax1.grid(axis='y', alpha=0.3, linestyle='--')
ax1.set_axisbelow(True)
ax1.set_ylim(0, 1.2)
# Adjust x-axis limits for equal spacing
ax1.set_xlim(-0.5, len(btrfs_block_sizes) - 0.5)
# Add title with (a) below the subplot
ax1.set_xlabel('(a) Btrfs')

# Second subplot - LVM
bars1_lvm = ax2.bar(x - width/2, lvm_normal, width,
                    label='Normal',
                    color=colors[0], alpha=0.9, hatch=hatches[0], edgecolor='black')
bars2_lvm = ax2.bar(x + width/2, lvm_snap, width,
                    label='Snapshot',
                    color=colors[1], alpha=0.9, hatch=hatches[1], edgecolor='black')

ax2.set_ylabel('Normalized Throughput')
ax2.set_xticks(x)
ax2.set_xticklabels(lvm_block_sizes)
ax2.grid(axis='y', alpha=0.3, linestyle='--')
ax2.set_axisbelow(True)
ax2.set_ylim(0, 1.2)
# Adjust x-axis limits for equal spacing
ax2.set_xlim(-0.5, len(lvm_block_sizes) - 0.5)
# Add title with (b) below the subplot
ax2.set_xlabel('(b) LVM+ext4')

# Create a single legend at the top
handles, labels = ax1.get_legend_handles_labels()
fig.legend(handles, labels, loc='upper center', bbox_to_anchor=(0.5, 0.96), ncol=2)

# Adjust layout to make room for the top legend
plt.tight_layout(rect=[0, 0, 1, 0.88])
plt.savefig('motivation4_fio.pdf', bbox_inches='tight')
plt.savefig('motivation4_fio.png', bbox_inches='tight', dpi=300)
print('FIO motivation charts saved as motivation4_fio.pdf and motivation4_fio.png')
plt.show()