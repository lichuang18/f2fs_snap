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
with open('motivation3.txt', 'r') as f:
    lines = f.readlines()

# Parse data: each line has format: benchmark_name, btrfs_cow, lvm_cow
benchmarks = []
btrfs_cow_values = []
lvm_cow_values = []

for line in lines[1:]:  # Skip header
    parts = line.strip().split('\t')
    if len(parts) >= 3:
        benchmarks.append(parts[0])
        btrfs_cow_values.append(float(parts[1]))
        lvm_cow_values.append(float(parts[2]))

# Create figure
fig, ax = plt.subplots(figsize=(10, 6))

# Set bar positions
x = np.arange(len(benchmarks))
width = 0.35

# Colors and hatches
colors = ['#BAC8D3', '#D5E8D4']
hatches = ['\\', '/']
# 'f2fs': '#BAC8D3',      # 淡天蓝
#     'snapfs': '#D5E8D4',    # 淡薄荷绿

# Plot grouped bars
bars1 = ax.bar(x - width/2, btrfs_cow_values, width, label='Btrfs-CoW',
               color=colors[0], alpha=0.9, hatch=hatches[0], edgecolor='black')
bars2 = ax.bar(x + width/2, lvm_cow_values, width, label='LVM-CoW',
               color=colors[1], alpha=0.9, hatch=hatches[1], edgecolor='black')

# Set labels
ax.set_ylabel('Write Amplification')
ax.set_xticks(x)
ax.set_xticklabels(benchmarks)
ax.legend()

# Add grid
ax.grid(axis='y', alpha=0.3, linestyle='--')
ax.set_axisbelow(True)

# Adjust layout
plt.tight_layout()
plt.savefig('motivation3.pdf', bbox_inches='tight')
plt.savefig('motivation3.png', bbox_inches='tight', dpi=300)
print('Motivation chart saved as motivation3.pdf and motivation3.png')
plt.show()