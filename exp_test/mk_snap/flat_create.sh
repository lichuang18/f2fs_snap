#!/bin/bash
set -e

############################################
# 可调参数

# 默认 50000
# ././create_file.sh

# 生成 20000 个
# ././create_file.sh 20000

############################################


FILE_COUNT=${1:-10000}                 # 文件数量（可传参）
MAX_TOTAL_GB=20                       # 最大总容量
MIN_SIZE_BYTES=4                       # 单文件最小 4B
MAX_SIZE_BYTES=$((3 * 1024 * 1024 * 1024))  # 单文件最大 3GB
# TARGET_DIR="./testvol"                 # 生成目录
TARGET_DIR="/mnt/test_random"


mkdir -p "$TARGET_DIR"
# sudo btrfs subvolume create $TARGET_DIR


############################################
# 计算
############################################
MAX_TOTAL_BYTES=$((MAX_TOTAL_GB * 1024 * 1024 * 1024))

echo "===== 参数 ====="
echo "文件数量: $FILE_COUNT"
echo "总容量上限: ${MAX_TOTAL_GB} GB"
echo "单文件范围: 4B ~ 3GB"
echo "================="

mkdir -p "$TARGET_DIR"

echo "Step 1: 生成随机权重..."
weights=()
total_weight=0

for ((i=0;i<FILE_COUNT;i++)); do
    # 生成 1~10000 随机权重
    w=$((RANDOM + 1))
    weights+=($w)
    total_weight=$((total_weight + w))
done

echo "权重总和: $total_weight"

echo "Step 2: 计算每个文件大小（缩放保证不超 480GB）..."

total_alloc=0

for ((i=0;i<FILE_COUNT;i++)); do

    # 按比例分配
    size=$(( weights[i] * MAX_TOTAL_BYTES / total_weight ))

    # 保证范围限制
    if [ "$size" -lt "$MIN_SIZE_BYTES" ]; then
        size=$MIN_SIZE_BYTES
    fi
    if [ "$size" -gt "$MAX_SIZE_BYTES" ]; then
        size=$MAX_SIZE_BYTES
    fi

    total_alloc=$((total_alloc + size))
    sizes[$i]=$size
done

echo "预计总分配: $((total_alloc / 1024 / 1024 / 1024)) GB"

if [ "$total_alloc" -gt "$MAX_TOTAL_BYTES" ]; then
    echo "⚠ 超过容量上限，自动缩减比例"
    scale=$(( total_alloc / MAX_TOTAL_BYTES + 1 ))
    for ((i=0;i<FILE_COUNT;i++)); do
        sizes[$i]=$(( sizes[$i] / scale ))
    done
fi

echo "Step 3: 开始写入文件..."

for ((i=0;i<FILE_COUNT;i++)); do
    size=${sizes[$i]}
    file="$TARGET_DIR/file_$i"

    # 小文件直接一次写
    if [ "$size" -le 1048576 ]; then
        dd if=/dev/urandom of="$file" bs=$size count=1 status=none
    else
        # 大文件分块写，避免一次性 bs 太大
        bs=1M
        count=$(( size / 1048576 ))
        remain=$(( size % 1048576 ))

        dd if=/dev/urandom of="$file" bs=$bs count=$count status=none

        if [ "$remain" -gt 0 ]; then
            dd if=/dev/urandom of="$file" bs=$remain count=1 \
               oflag=append conv=notrunc status=none
        fi
    fi

    # 每 1000 个文件打印一次进度
    if (( i % 1000 == 0 )); then
        echo "已生成 $i / $FILE_COUNT"
    fi
done

echo "===== 完成 ====="
du -sh "$TARGET_DIR"