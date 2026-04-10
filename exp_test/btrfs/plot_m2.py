#!/usr/bin/env python3
import sys
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else "./results_btrfs_gran")

def load_csv(name: str) -> pd.DataFrame:
    path = ROOT / f"{name}.csv"
    if not path.exists():
        raise FileNotFoundError(f"missing file: {path}")

    df = pd.read_csv(path)

    required = {"round", "cumulative_hot_overwrite_bytes", "used_bytes"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"{path} missing columns: {sorted(missing)}")

    df = df.sort_values("round").copy()
    df["layout"] = name

    # 单位换算
    df["cumulative_gib"] = df["cumulative_hot_overwrite_bytes"] / (1024**3)
    df["used_gib"] = df["used_bytes"] / (1024**3)

    # 相对增量：相对于 round 0 的 used_bytes
    base_used = df["used_bytes"].iloc[0]
    df["used_delta_bytes"] = df["used_bytes"] - base_used
    df["used_delta_gib"] = df["used_delta_bytes"] / (1024**3)

    return df

def nice_label(layout: str) -> str:
    mapping = {
        "single_subvol": "single-subvolume layout",
        "split_subvol": "split-subvolume layout",
    }
    return mapping.get(layout, layout)

def main():
    dfs = []
    for name in ["single_subvol", "split_subvol"]:
        dfs.append(load_csv(name))

    df = pd.concat(dfs, ignore_index=True)
    df = df.sort_values(["layout", "round"])

    out_csv = ROOT / "summary_with_delta.csv"
    df.to_csv(out_csv, index=False)

    # 图1：最推荐，画相对增量
    plt.figure(figsize=(8, 5))
    for layout, sub in df.groupby("layout"):
        plt.plot(
            sub["cumulative_gib"],
            sub["used_delta_gib"],
            marker="o",
            label=nice_label(layout),
        )
    plt.xlabel("Cumulative overwrites to unrelated hot data (GiB)")
    plt.ylabel("Used-space increase since round 0 (GiB)")
    plt.title("Snapshot granularity affects space growth of unrelated hot updates")
    plt.legend()
    plt.tight_layout()
    plt.savefig(ROOT / "snapshot_granularity_used_delta.png", dpi=200)

    # 图2：保留原始 used space，方便你自己对照
    plt.figure(figsize=(8, 5))
    for layout, sub in df.groupby("layout"):
        plt.plot(
            sub["cumulative_gib"],
            sub["used_gib"],
            marker="o",
            label=nice_label(layout),
        )
    plt.xlabel("Cumulative overwrites to unrelated hot data (GiB)")
    plt.ylabel("Filesystem used space (GiB)")
    plt.title("Absolute filesystem used space")
    plt.legend()
    plt.tight_layout()
    plt.savefig(ROOT / "snapshot_granularity_used_abs.png", dpi=200)

    # 图3：每轮新增空间，观察哪几轮增长最明显
    df["per_round_delta_gib"] = df.groupby("layout")["used_delta_gib"].diff().fillna(0.0)

    plt.figure(figsize=(8, 5))
    for layout, sub in df.groupby("layout"):
        plt.plot(
            sub["round"],
            sub["per_round_delta_gib"],
            marker="o",
            label=nice_label(layout),
        )
    plt.xlabel("Round")
    plt.ylabel("Per-round used-space increase (GiB)")
    plt.title("Per-round space growth")
    plt.legend()
    plt.tight_layout()
    plt.savefig(ROOT / "snapshot_granularity_per_round_delta.png", dpi=200)

    print("saved:", out_csv)
    print("saved:", ROOT / "snapshot_granularity_used_delta.png")
    print("saved:", ROOT / "snapshot_granularity_used_abs.png")
    print("saved:", ROOT / "snapshot_granularity_per_round_delta.png")

if __name__ == "__main__":
    main()