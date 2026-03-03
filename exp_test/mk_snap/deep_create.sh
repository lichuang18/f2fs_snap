#!/bin/bash
set -e

############################################
# 可调参数

# 默认 50000
# ./create_file.sh

# 生成 20000 个
# ./create_file.sh 20000

############################################


FILE_COUNT=${1:-10000}                 # 文件数量（可传参）
MAX_TOTAL_GB=20                       # 最大总容量
MIN_SIZE_BYTES=4                       # 单文件最小 4B
MAX_SIZE_BYTES=$((3 * 1024 * 1024 * 1024))  # 单文件最大 3GB
TARGET_DIR="/mnt/test_random"

# 新增：目录层级配置
SUB_DIR_COUNT=10                        # 10层子目录
FILES_PER_DIR=$((FILE_COUNT / SUB_DIR_COUNT))  # 每层5000个文件

mkdir -p "$TARGET_DIR"
# sudo btrfs subvolume create $TARGET_DIR

# 创建子目录
echo "Step 0: 创建 $SUB_DIR_COUNT 个子目录..."
for ((d=0; d<SUB_DIR_COUNT; d++)); do
    SUB_DIR="$TARGET_DIR/dir_$d"
    mkdir -p "$SUB_DIR"
done

############################################
# 计算
############################################
MAX_TOTAL_BYTES=$((MAX_TOTAL_GB * 1024 * 1024 * 1024))

echo "===== 参数 ====="
echo "文件总数: $FILE_COUNT"
echo "子目录数: $SUB_DIR_COUNT"
echo "每目录文件: $FILES_PER_DIR"
echo "总容量上限: ${MAX_TOTAL_GB} GB"
echo "单文件范围: 4B ~ 3GB"
echo "================="

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

echo "Step 2: 计算每个文件大小（缩放保证不超 $MAX_TOTAL_GB GB）..."

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

# 如果超出容量上限，按比例缩减
if [ "$total_alloc" -gt "$MAX_TOTAL_BYTES" ]; then
    echo "⚠ 超过容量上限，自动缩减比例"
    scale=$(( total_alloc / MAX_TOTAL_BYTES + 1 ))
    total_alloc=0
    for ((i=0;i<FILE_COUNT;i++)); do
        sizes[$i]=$(( sizes[$i] / scale ))
        total_alloc=$((total_alloc + sizes[$i]))
    done
    echo "调整后总分配: $((total_alloc / 1024 / 1024 / 1024)) GB"
fi

echo "Step 3: 开始写入文件到各层子目录..."

file_index=0
for ((d=0; d<SUB_DIR_COUNT; d++)); do
    SUB_DIR="$TARGET_DIR/dir_$d"
    
    # 计算当前目录的文件范围
    dir_start=$((d * FILES_PER_DIR))
    dir_end=$((dir_start + FILES_PER_DIR))
    
    # 处理最后一个目录可能多出来的文件（如果不能整除）
    if [ $d -eq $((SUB_DIR_COUNT - 1)) ]; then
        dir_end=$FILE_COUNT
    fi
    
    echo "  目录 dir_$d: 文件 $dir_start ~ $((dir_end - 1))"
    
    for ((i=dir_start; i<dir_end; i++)); do
        size=${sizes[$i]}
        file="$SUB_DIR/file_$i"

        # 小文件直接一次写
        if [ "$size" -le 1048576 ]; then
            dd if=/dev/urandom of="$file" bs=$size count=1 status=none 2>/dev/null
        else
            # 大文件分块写，避免一次性 bs 太大
            bs=1M
            count=$(( size / 1048576 ))
            remain=$(( size % 1048576 ))

            dd if=/dev/urandom of="$file" bs=$bs count=$count status=none 2>/dev/null

            if [ "$remain" -gt 0 ]; then
                dd if=/dev/urandom of="$file" bs=$remain count=1 \
                   oflag=append conv=notrunc status=none 2>/dev/null
            fi
        fi

        file_index=$((file_index + 1))
        
        # 每生成1000个文件打印一次进度（基于全局计数）
        if (( file_index % 1000 == 0 )); then
            echo "已生成 $file_index / $FILE_COUNT 个文件"
        fi
    done
done

echo ""
echo "===== 完成 ====="
echo "文件分布: $SUB_DIR_COUNT 个子目录，每目录约 $FILES_PER_DIR 个文件"
du -sh "$TARGET_DIR"
tree -L 2 "$TARGET_DIR" | head -20