#!/usr/bin/env python3
import argparse
import json
import os
import random
import time


def parse_size(size_str: str) -> int:
    size_str = size_str.strip().lower()
    units = {
        "k": 1024,
        "kb": 1024,
        "m": 1024 ** 2,
        "mb": 1024 ** 2,
        "g": 1024 ** 3,
        "gb": 1024 ** 3,
    }

    for suffix, multiplier in units.items():
        if size_str.endswith(suffix):
            number = float(size_str[:-len(suffix)])
            return int(number * multiplier)

    return int(size_str)


def main():
    parser = argparse.ArgumentParser(
        description="Modify a fixed percentage of unique blocks in an existing file."
    )

    parser.add_argument("--file", required=True, help="Target file path")
    parser.add_argument("--ratio", required=True, type=float, help="Modify ratio in percent, e.g. 10 for 10%")
    parser.add_argument("--block-size", default="4K", help="Write block size, default 4K")
    parser.add_argument("--seed", default=1, type=int, help="Random seed")
    parser.add_argument("--fsync", action="store_true", help="Call fsync on the file before exit")
    parser.add_argument("--sync", action="store_true", help="Call global sync before exit")
    parser.add_argument("--log", default="modify.log", help="Output log file")

    args = parser.parse_args()

    path = args.file
    ratio = args.ratio
    block_size = parse_size(args.block_size)

    file_size = os.path.getsize(path)
    total_blocks = file_size // block_size

    if total_blocks <= 0:
        raise RuntimeError("File is smaller than one block")

    blocks_to_modify = int(total_blocks * ratio / 100.0)

    if ratio > 0 and blocks_to_modify == 0:
        blocks_to_modify = 1

    if blocks_to_modify > total_blocks:
        raise RuntimeError("Requested ratio is larger than file size")

    random.seed(args.seed)

    start_time = time.time()

    # 随机选择不重复的 block index
    selected_blocks = random.sample(range(total_blocks), blocks_to_modify)

    # 固定写入内容。这里不需要随机内容，因为我们关心的是覆盖写行为。
    write_buf = b"\x5a" * block_size

    bytes_modified = 0

    with open(path, "r+b", buffering=0) as f:
        for block_idx in selected_blocks:
            offset = block_idx * block_size
            f.seek(offset)
            f.write(write_buf)
            bytes_modified += block_size

        if args.fsync:
            f.flush()
            os.fsync(f.fileno())

    if args.sync:
        os.sync()

    end_time = time.time()

    log = {
        "file": path,
        "file_size_bytes": file_size,
        "ratio_percent": ratio,
        "block_size_bytes": block_size,
        "total_blocks": total_blocks,
        "unique_blocks_modified": blocks_to_modify,
        "actual_bytes_modified": bytes_modified,
        "seed": args.seed,
        "fsync": args.fsync,
        "sync": args.sync,
        "duration_seconds": end_time - start_time,
    }

    with open(args.log, "w") as out:
        json.dump(log, out, indent=2)

    print(json.dumps(log, indent=2))


if __name__ == "__main__":
    main()