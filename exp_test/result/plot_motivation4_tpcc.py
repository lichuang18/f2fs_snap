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
with open('motivation4_2.txt', 'r') as f:
    lines = f.readlines()

# Parse data: each line has format: filesystem, normal, snapshot
filesystems = []
normal_values = []
snapshot_values = []

for line in lines[1:]:  # Skip header
    parts = line.strip().split('\t')
    if len(parts) >= 3:
        filesystems.append(parts[0])
        normal_values.append(float(parts[1]))
        snapshot_values.append(float(parts[2]))

# Create figure with height=5, width=8
fig, ax = plt.subplots(figsize=(8, 5))

# Set bar positions
x = np.arange(len(filesystems))
width = 0.15

# Colors and hatches
colors = ['#F9F7ED', '#E1D5E7']
hatches = ['\\', '/']
# colors = ['#FFCCCC', '#F9F7ED', '#E1D5E7']


# Plot grouped bars
bars1 = ax.bar(x - width/2, normal_values, width, label='Normal',
               color=colors[0], alpha=0.9, hatch=hatches[0], edgecolor='black')
bars2 = ax.bar(x + width/2, snapshot_values, width, label='Snapshot',
               color=colors[1], alpha=0.9, hatch=hatches[1], edgecolor='black')

# Set labels
ax.set_ylabel('Normalized Throughput')
ax.set_xticks(x)
ax.set_xticklabels(filesystems)
# Adjust x-axis limits for equal spacing
ax.set_xlim(-0.5, len(filesystems) - 0.5)

# Create legend at the top center
handles, labels = ax.get_legend_handles_labels()
fig.legend(handles, labels, loc='upper center', bbox_to_anchor=(0.5, 0.96), ncol=2)

# Add grid
ax.grid(axis='y', alpha=0.3, linestyle='--')
ax.set_axisbelow(True)

# Adjust layout to make room for the top legend
plt.tight_layout(rect=[0, 0, 1, 0.88])
plt.savefig('motivation4_tpcc.pdf', bbox_inches='tight')
plt.savefig('motivation4_tpcc.png', bbox_inches='tight', dpi=300)
print('TPCC motivation chart saved as motivation4_tpcc.pdf and motivation4_tpcc.png')
plt.show()