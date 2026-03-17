import matplotlib.pyplot as plt
import numpy as np

# Data from space2.txt (skip 0% row)
percentages = [10, 20, 50, 100]
btrfs = [1200236, 2369384, 5890452, 11698620]
snapfs = [1010320, 2010320, 5010320, 10010320]
base = [1000000, 2000000, 5000000, 10000000]

# Normalize by snapfs
btrfs_norm = [btrfs[i]/snapfs[i] for i in range(len(snapfs))]
snapfs_norm = [1.0] * len(snapfs)
base_norm = [base[i]/snapfs[i] for i in range(len(snapfs))]

# Create bar plot
x = np.arange(len(percentages))
width = 0.25

fig, ax = plt.subplots(figsize=(8, 5))
ax.bar(x - width, btrfs_norm, width, label='Btrfs', color='#FFB6C1', edgecolor='black', hatch='///')
ax.bar(x, snapfs_norm, width, label='SnapFS', color='#B0E0E6', edgecolor='black', hatch='\\\\\\')
ax.bar(x + width, base_norm, width, label='Base', color='#D8BFD8', edgecolor='black', hatch='xxx')

ax.set_xlabel('Modified Ratio (%)', fontsize=14)
ax.set_ylabel('Normalized Space Overhead', fontsize=14)
ax.set_xticks(x)
ax.set_xticklabels(percentages)
ax.legend(fontsize=12, frameon=True, loc='upper center', bbox_to_anchor=(0.5, 1.15), ncol=3)
ax.grid(True, alpha=0.3, linestyle='--', axis='y')
plt.tight_layout()

plt.savefig('space_overhead2_normalized.pdf', dpi=300, bbox_inches='tight')
plt.savefig('space_overhead2_normalized.png', dpi=300, bbox_inches='tight')
print("Plots saved: space_overhead2_normalized.pdf/png")
