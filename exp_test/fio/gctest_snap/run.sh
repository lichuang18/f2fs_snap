#!/bin/bash

# 创建测试目录
mkdir -p /mnt/f2fs/gc_test

echo "=== 运行第 fill 测试 ==="
# 循环1000次，使用数字后缀
for i in {1..20000}; do
    
    # 构建文件名
    filename="/mnt/f2fs/gc_test/gc_test_file_${i}"
    # 运行fio测试
    fio \
    --ioengine=libaio \
    --direct=1 \
    --bs=128k \
    --iodepth=32 \
    --filename="${filename}" \
    --group_reporting=1 \
    --randrepeat=0 \
    --name="fill_${i}" \
    --rw=write \
    --size=3M
done
echo "------------------------"



echo "=== 运行第 gc 测试 ==="

for i in {1..20000}; do
    
    # 构建文件名
    filename="/mnt/f2fs/gc_test/gc_test_file_${i}"
    # 运行fio测试
    fio \
    --ioengine=libaio \
    --direct=1 \
    --bs=128k \
    --iodepth=32 \
    --filename="${filename}" \
    --group_reporting=1 \
    --randrepeat=0 \
    --name="fill_${i}" \
    --rw=randwrite \
    --size=3M
done


echo "------------------------"




echo "所有测试完成！"
