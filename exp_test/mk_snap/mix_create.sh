#!/bin/bash
set -e

############################################
# 可调参数

FILE_COUNT=${1:-10000}                 # 文件数量（可传参）
MAX_TOTAL_GB=20                       # 最大总容量
MIN_SIZE_BYTES=4                       # 单文件最小 4B
MAX_SIZE_BYTES=$((3 * 1024 * 1024 * 1024))  # 单文件最大 3GB
TARGET_DIR="/mnt/test_random"

# 随机层数范围
MIN_DEPTH=3
MAX_DEPTH=5


mkdir -p "$TARGET_DIR"
# btrfs subvolume create "$TARGET_DIR"

############################################
# 生成随机目录结构
############################################
echo "===== 生成随机目录结构 ====="

# 随机决定层数（3-5层）
DEPTH=$((RANDOM % (MAX_DEPTH - MIN_DEPTH + 1) + MIN_DEPTH))
echo "目录深度: $DEPTH 层"

# 递归生成目录树函数
generate_dir_tree() {
    local current_path=$1
    local current_depth=$2
    local max_depth=$3
    
    mkdir -p "$current_path"
    
    # 如果达到最大深度，返回
    if [ $current_depth -ge $max_depth ]; then
        return
    fi
    
    # 随机决定当前目录下创建多少个子目录（2-5个）
    local subdir_count=$((RANDOM % 4 + 2))
    
    for ((s=0; s<subdir_count; s++)); do
        local subdir_name=$(printf "d%02x" $((RANDOM % 256)))
        generate_dir_tree "$current_path/$subdir_name" $((current_depth + 1)) $max_depth
    done
}

# 生成随机目录树
generate_dir_tree "$TARGET_DIR" 1 $DEPTH

# 修复：正确识别叶子目录（没有子目录的目录）
echo "收集所有叶子目录..."
LEAF_DIRS=()
while IFS= read -r dir; do
    # 检查这个目录下是否有子目录
    if [ -z "$(find "$dir" -mindepth 1 -maxdepth 1 -type d)" ]; then
        LEAF_DIRS+=("$dir")
    fi
done < <(find "$TARGET_DIR" -type d)

LEAF_COUNT=${#LEAF_DIRS[@]}
echo "叶子目录数量: $LEAF_COUNT"

# 显示前10个叶子目录
echo "前10个叶子目录:"
for ((d=0; d<10 && d<LEAF_COUNT; d++)); do
    echo "  ${LEAF_DIRS[$d]}"
done

# 如果叶子目录太少，补充一些
if [ $LEAF_COUNT -lt 10 ]; then
    echo "叶子目录太少，补充生成..."
    for ((i=0; i<30; i++)); do
        # 随机找一个现有目录，在下面新建子目录
        RANDOM_DIR=$(find "$TARGET_DIR" -type d | shuf -n 1)
        NEW_DIR="$RANDOM_DIR/extra_$i"
        mkdir -p "$NEW_DIR"
    done
    
    # 重新收集叶子目录
    LEAF_DIRS=()
    while IFS= read -r dir; do
        if [ -z "$(find "$dir" -mindepth 1 -maxdepth 1 -type d)" ]; then
            LEAF_DIRS+=("$dir")
        fi
    done < <(find "$TARGET_DIR" -type d)
    
    LEAF_COUNT=${#LEAF_DIRS[@]}
    echo "补充后叶子目录数量: $LEAF_COUNT"
fi

############################################
# 随机分配文件到各叶子目录
############################################
echo ""
echo "===== 随机分配 $FILE_COUNT 个文件到 $LEAF_COUNT 个目录 ====="

# 生成随机权重分配文件数
declare -a DIR_WEIGHTS
TOTAL_WEIGHT=0

for ((d=0; d<LEAF_COUNT; d++)); do
    w=$((RANDOM % 100 + 1))
    DIR_WEIGHTS[$d]=$w
    TOTAL_WEIGHT=$((TOTAL_WEIGHT + w))
done

# 按权重分配文件数
declare -a DIR_FILES
TOTAL_ALLOC=0
REMAINING=$FILE_COUNT

for ((d=0; d<LEAF_COUNT; d++)); do
    if [ $d -eq $((LEAF_COUNT - 1)) ]; then
        files=$REMAINING
    else
        files=$((DIR_WEIGHTS[$d] * FILE_COUNT / TOTAL_WEIGHT))
        if [ $files -lt 1 ]; then
            files=1
        fi
    fi
    
    DIR_FILES[$d]=$files
    TOTAL_ALLOC=$((TOTAL_ALLOC + files))
    REMAINING=$((FILE_COUNT - TOTAL_ALLOC))
done

# 验证总文件数
echo "文件分配预览（前10个目录）:"
for ((d=0; d<10 && d<LEAF_COUNT; d++)); do
    echo "  ${LEAF_DIRS[$d]}: ${DIR_FILES[$d]} 个文件"
done
[ $LEAF_COUNT -gt 10 ] && echo "  ... 还有 $((LEAF_COUNT - 10)) 个目录"
echo "总分配文件数: $TOTAL_ALLOC / $FILE_COUNT"

############################################
# 计算文件大小
############################################
MAX_TOTAL_BYTES=$((MAX_TOTAL_GB * 1024 * 1024 * 1024))

echo ""
echo "===== 参数 ====="
echo "文件总数: $FILE_COUNT"
echo "目录深度: $DEPTH (随机)"
echo "叶子目录数: $LEAF_COUNT"
echo "总容量上限: ${MAX_TOTAL_GB} GB"
echo "单文件范围: 4B ~ 3GB"
echo "================="

echo "Step 1: 生成文件随机权重..."
weights=()
total_weight=0

for ((i=0;i<FILE_COUNT;i++)); do
    w=$((RANDOM + 1))
    weights+=($w)
    total_weight=$((total_weight + w))
    
    if (( i % 10000 == 0 && i > 0 )); then
        echo "  已生成 $i / $FILE_COUNT 个权重"
    fi
done

echo "权重总和: $total_weight"

echo "Step 2: 计算每个文件大小..."
total_alloc=0

for ((i=0;i<FILE_COUNT;i++)); do
    size=$(( weights[i] * MAX_TOTAL_BYTES / total_weight ))

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
    total_alloc=0
    for ((i=0;i<FILE_COUNT;i++)); do
        sizes[$i]=$(( sizes[$i] / scale ))
        total_alloc=$((total_alloc + sizes[$i]))
    done
    echo "调整后总分配: $((total_alloc / 1024 / 1024 / 1024)) GB"
fi

echo "Step 3: 开始写入文件到随机目录..."

file_index=0
total_files=$FILE_COUNT
start_time=$(date +%s)

for ((d=0; d<LEAF_COUNT; d++)); do
    current_dir="${LEAF_DIRS[$d]}"
    files_in_this_dir=${DIR_FILES[$d]}
    
    echo "  目录 $((d+1))/$LEAF_COUNT: ${current_dir##*/} ($files_in_this_dir 个文件)"
    
    for ((f=0; f<files_in_this_dir; f++)); do
        size=${sizes[$file_index]}
        file="$current_dir/file_${file_index}.dat"
        
        # 修复：确保文件非空
        if [ "$size" -le 1048576 ]; then
            dd if=/dev/urandom of="$file" bs=$size count=1 status=none
        else
            # 大文件分块写
            bs=1M
            count=$(( size / 1048576 ))
            remain=$(( size % 1048576 ))

            dd if=/dev/urandom of="$file" bs=$bs count=$count status=none
            
            if [ "$remain" -gt 0 ]; then
                dd if=/dev/urandom of="$file" bs=$remain count=1 \
                   oflag=append conv=notrunc status=none
            fi
        fi
        
        # 验证文件大小
        actual_size=$(stat -c %s "$file" 2>/dev/null || echo "0")
        if [ "$actual_size" -eq 0 ]; then
            echo "警告: 文件 $file 大小为0，重新写入..."
            echo "test data" > "$file"
        fi
        
        file_index=$((file_index + 1))
        
        # 每100个文件显示一次进度
        if (( file_index % 100 == 0 )); then
            current_time=$(date +%s)
            elapsed=$((current_time - start_time))
            if [ $elapsed -gt 0 ]; then
                speed=$((file_index / elapsed))
                echo "  已生成 $file_index / $total_files 个文件 (约 $speed 文件/秒)"
            else
                echo "  已生成 $file_index / $total_files 个文件"
            fi
        fi
    done
done

end_time=$(date +%s)
total_time=$((end_time - start_time))

# 验证最终文件数量
actual_files=$(find "$TARGET_DIR" -type f | wc -l)

echo ""
echo "===== 完成 ====="
echo "目录深度: $DEPTH (随机)"
echo "叶子目录数: $LEAF_COUNT"
echo "预期文件总数: $FILE_COUNT"
echo "实际文件总数: $actual_files"
echo "总耗时: $total_time 秒"
if [ $total_time -gt 0 ]; then
    echo "平均速度: $((actual_files / total_time)) 文件/秒"
fi

echo ""
echo "磁盘使用情况:"
du -sh "$TARGET_DIR"
echo ""
echo "文件大小分布:"
find "$TARGET_DIR" -type f -exec ls -lh {} \; | awk '{print $5}' | sort | uniq -c | head -10

echo ""
echo "目录结构预览 (前30行):"
tree -L $DEPTH "$TARGET_DIR" 2>/dev/null | head -30 || echo "  请安装 tree 命令以查看目录结构"