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

# Read data file
data = np.loadtxt('motivation_new.txt', skiprows=1, usecols=(1, 2))

# Extract data
file_sizes = ['4K', '16K', '64K', '256K']
btrfs = data[:, 0]   # btrfs-snapshot
lvm = data[:, 1]     # lvm+ext4-snapshot

# Create figure
fig, ax = plt.subplots(figsize=(10, 6))

# Set bar positions
x = np.arange(len(file_sizes))
width = 0.35  # Width of each bar (only 2 bars now)

# Colors (original colors for btrfs and lvm)
colors = ['#F6BABA', '#F8C999']
hatches = ['\\', 'x']

# Plot bars
bars1 = ax.bar(x - width/2, btrfs, width, color=colors[0], alpha=0.9, hatch=hatches[0], edgecolor='black', label='Btrfs')
bars2 = ax.bar(x + width/2, lvm, width, color=colors[1], alpha=0.9, hatch=hatches[1], edgecolor='black', label='LVM+Ext4')

# Set labels
ax.set_xlabel('Block Size')
ax.set_ylabel('Write Amplification')
ax.set_xticks(x)
ax.set_xticklabels(file_sizes)

# Legend
handles = [plt.Rectangle((0,0),1,1, facecolor=colors[i], hatch=hatches[i], edgecolor='black', linewidth=1) for i in range(2)]
labels = ['Btrfs', 'LVM+Ext4']
ax.legend(handles, labels, loc='upper right')

# Add grid
ax.grid(axis='y', alpha=0.3, linestyle='--')
ax.set_axisbelow(True)

# Adjust layout
plt.tight_layout()
plt.savefig('motivation_new.pdf', bbox_inches='tight')
plt.savefig('motivation_new.png', bbox_inches='tight')
print('Motivation chart saved as motivation_new.pdf and motivation_new.png')
plt.show()
