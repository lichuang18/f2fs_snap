#!/bin/bash
# 实验2：数据修改比例控制脚本（块级别）
# 只需要目标文件夹参数，遍历所有文件按指定比例修改

set -e

# 检查参数
if [ $# -ne 2 ]; then
    echo "用法: $0 <目标文件夹> <修改比例>"
    echo "示例: $0 /mnt/test_data 10"
    echo "修改比例: 0-100 的整数，表示要修改的数据块百分比"
    exit 1
fi

TARGET_DIR="$1"
MODIFY_PCT="$2"

# 验证参数
if [ ! -d "$TARGET_DIR" ]; then
    echo "错误: 目标文件夹 $TARGET_DIR 不存在"
    exit 1
fi

if ! [[ "$MODIFY_PCT" =~ ^[0-9]+$ ]] || [ "$MODIFY_PCT" -gt 100 ]; then
    echo "错误: 修改比例必须是 0-100 的整数"
    exit 1
fi

echo "=== 块级别数据修改 ==="
echo "目标文件夹: $TARGET_DIR"
echo "修改比例: ${MODIFY_PCT}%"

# 统计目标文件夹信息
file_count=$(find "$TARGET_DIR" -type f | wc -l)

# 这个获取的是所有文件的总大小
total_size_kb=$(du -sk "$TARGET_DIR" | awk '{print $1}')
total_size_mb=$((total_size_kb / 1024))

echo "文件数量: $file_count"
echo "总数据量: ${total_size_mb} MB (${total_size_kb} KB)"

if [ $file_count -eq 0 ]; then
    echo "错误: 目标文件夹中没有文件"
    exit 1
fi

# 按块修改比例修改文件
if [ $MODIFY_PCT -gt 0 ]; then
    echo "开始按 ${MODIFY_PCT}% 块比例修改文件..."

    python3 << PYEOF
import os
import random
import subprocess
import sys

modify_pct = ${MODIFY_PCT}
target_dir = "${TARGET_DIR}"

# 获取所有文件列表
files = []
for root, dirs, filenames in os.walk(target_dir):
    for filename in filenames:
        filepath = os.path.join(root, filename)
        if os.path.isfile(filepath):
            files.append(filepath)

file_count = len(files)
print(f"找到 {file_count} 个文件")

if file_count == 0:
    print("警告: 没有找到任何文件")
    sys.exit(0)

# 遍历所有文件进行块级别修改
modified_files = 0
total_blocks_modified = 0
total_blocks_total = 0

for filepath in files:
    subprocess.run(['echo', filepath], check=True)
    try:
        # 获取文件大小
        file_size_bytes = os.path.getsize(filepath)
        if file_size_bytes == 0:
            continue

        block_count = (file_size_bytes + 4095) // 4096  # 4KB 块数量
        total_blocks_total += block_count

        if block_count == 0:
            continue

        # 计算要修改的块数（至少修改1个块）
        blocks_to_modify = max(1, int(block_count * modify_pct / 100))

        # 确保不超过总块数
        blocks_to_modify = min(blocks_to_modify, block_count)

        # 随机选择要修改的块位置
        if block_count <= blocks_to_modify:
            # 如果要修改的块数 >= 总块数，修改所有块
            block_offsets = list(range(block_count))
        else:
            # 随机选择 blocks_to_modify 个块
            block_offsets = random.sample(range(block_count), blocks_to_modify)

        # 修改选中的块
        for block_idx in block_offsets:
            offset_bytes = block_idx * 4096
            offset_kb = offset_bytes // 1024
            subprocess.run(['echo', str(block_idx)], check=True)
            try:
                subprocess.run([
                    'dd', 'if=/dev/urandom', f'of={filepath}',
                    'bs=4K', 'count=1', f'seek={offset_kb}',
                    'oflag=direct', 'conv=notrunc', 'status=none'
                ], check=True, capture_output=True, text=True)
                
                subprocess.run(['sync'], check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error modifying block {block_idx} in {filepath}: {e}", file=sys.stderr)
                continue

        modified_files += 1
        total_blocks_modified += len(block_offsets)

    except (OSError, IOError) as e:
        print(f"Error processing file {filepath}: {e}", file=sys.stderr)
        continue

actual_modify_pct = (total_blocks_modified / total_blocks_total) * 100 if total_blocks_total > 0 else 0

print(f"处理了 {file_count} 个文件，修改了 {modified_files} 个文件")
print(f"总共 {total_blocks_total} 个数据块，修改了 {total_blocks_modified} 个数据块")
print(f"实际修改比例: {actual_modify_pct:.2f}% (目标: {modify_pct}%)")
print(f"块级别修改完成!")
PYEOF

    echo "修改完成！"
else
    echo "修改比例为 0%，无需修改文件"
fi
