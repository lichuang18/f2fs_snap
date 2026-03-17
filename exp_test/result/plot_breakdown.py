import matplotlib.pyplot as plt
import matplotlib as mpl
mpl.rcParams['font.family'] = 'Times New Roman'
mpl.rcParams['font.size'] = 18

import numpy as np

# Data from break_down.txt
snapfs_data = {
    'Node Block': 0.100387597,
    'Dentry': 0.018217054,
    'Other': 0.88120155
}

btrfs_data = {
    'File Tree': 0.14125,
    'Extent Tree': 0.28375,
    'Checksum Tree': 0.0067,
    'Other': 0.5683
}

snapfs_total = 10320  # bytes
btrfs_total = 200236  # bytes

# Create figure with two subplots
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

# Colors for academic style
colors_snapfs = ['#2E86AB', '#A23B72', '#F18F01']
colors_btrfs = ['#2E86AB', '#A23B72', '#F18F01', '#C73E1D']

# SnapFS pie chart
wedges1, texts1, autotexts1 = ax1.pie(snapfs_data.values(), labels=snapfs_data.keys(),
                                       autopct='%1.1f%%', colors=colors_snapfs,
                                       startangle=90, textprops={'fontsize': 10})
ax1.set_title(f'SnapFS Storage Breakdown\n(Total: {snapfs_total:,} bytes)',
              fontsize=12, fontweight='bold', pad=20)

# Btrfs pie chart
wedges2, texts2, autotexts2 = ax2.pie(btrfs_data.values(), labels=btrfs_data.keys(),
                                       autopct='%1.1f%%', colors=colors_btrfs,
                                       startangle=90, textprops={'fontsize': 10})
ax2.set_title(f'Btrfs Storage Breakdown\n(Total: {btrfs_total:,} bytes)',
              fontsize=12, fontweight='bold', pad=20)

# Adjust layout
plt.tight_layout()
plt.savefig('storage_breakdown.pdf', dpi=300, bbox_inches='tight')
plt.savefig('storage_breakdown.png', dpi=300, bbox_inches='tight')
plt.show()