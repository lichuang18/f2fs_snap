# SnapFS 对比实验测试方案

> 完整可行的测试方案，突出 SnapFS 优势

## 一、测试环境

```bash
# 硬件配置
CPU: 8+ cores
内存: 32GB+
存储: NVMe SSD (1TB+) - 避免机械硬盘成为瓶颈

# 软件配置
OS: Linux 5.15+
内核: 加载 snapfs.ko
工具: fio 3.x+, filebench, mdtest, dbench
```

---

## 二、核心测试目标

| 维度 | 测试重点 | SnapFS 优势 |
|------|----------|-------------|
| **空间效率** | 快照后额外空间占用 | 只复制 node 元数据，数据块共享 |
| **快照创建速度** | 不同规模下的创建时间 | 元数据复制轻量，无需数据复制 |
| **I/O 性能开销** | 有/无快照下的读写性能 | mulref 查询开销极小 |
| **多快照扩展性** | 快照数量增长时的性能 | hopscotch hashing O(1) 查找 |
| **闪存友好性** | 写放大对比 | 基于 f2fs 日志结构 |

---

## 三、FIO 测试详解

### 3.1 快照创建时间测试

```bash
# 测试目的：验证元数据复制的轻量性
# 测试维度：文件数量 × 文件大小

#!/bin/bash

MOUNT="/mnt/f2fs"
SNAP_DIR="/mnt/snap"
RESULT="./results/snap_create"

mkdir -p $RESULT

# 文件数量：100, 1K, 10K, 100K
# 文件大小：4KB (小文件), 1MB (中等文件), 100MB (大文件)

for size in 4K 1M 100M; do
    for count in 100 1000 10000; do
        echo "Testing: $size × $count files"

        # 准备测试数据
        rm -rf $MOUNT/test/*
        mkdir -p $MOUNT/test
        sync
        drop_caches

        # 使用 fio 生成测试文件
        fio --name=prep --filename=$MOUNT/test/file --rw=write \
            --bs=$size --numjobs=$count --size=$size --group_reporting \
            --direct=0 --fsync=1 --fallocate=none > /dev/null

        # 记录快照前空间
        space_before=$(df -B1 $MOUNT | awk 'NR==2 {print $3}')

        # 测量快照创建时间
        START=$(date +%s.%N)
        ./test_ioctl/test $MOUNT/test /mnt/snap snap_${size}_${count}
        END=$(date +%s.%N)
        ELAPSED=$(echo "$END - $START" | bc)

        # 记录快照后空间
        sync
        drop_caches
        space_after=$(df -B1 $MOUNT | awk 'NR==2 {print $3}')
        space_used=$((space_after - space_before))

        echo "$size,$count,$ELAPSED,$space_used" >> $RESULT/create_time.csv
    done
done

# 输出格式
# file_size,file_count,create_time_sec,space_used_bytes
```

### 3.2 空间效率测试

```bash
#!/bin/bash

# 测试目的：验证 CoW 空间节省效果
# 对比：SnapFS vs Btrfs vs ZFS vs LVM snapshot vs rsync

MOUNT="/mnt/f2fs"
SNAP_DIR="/mnt/snap"
RESULT="./results/space_efficiency"

mkdir -p $RESULT

# 基础数据：10000 个 1MB 文件
TOTAL_SIZE=$((10000 * 1024 * 1024))  # 约 10GB

echo "Creating 10GB baseline data..."
rm -rf $MOUNT/test/*
mkdir -p $MOUNT/test

fio --name=baseline --filename=$MOUNT/test/file --rw=write \
    --bs=1M --size=1M --numjobs=10000 --group_reporting \
    --direct=0 --fsync=1 --fallocate=none > /dev/null

sync
drop_caches
baseline_space=$(df -B1 $MOUNT | awk 'NR==2 {print $3}')
echo "Baseline space: $baseline_space bytes"

# 测试不同修改比例下的空间变化
for modify_pct in 0 5 10 20 30 50 100; do
    echo "Testing with $modify_pct% modification..."

    # 创建快照
    ./test_ioctl/test $MOUNT/test /mnt/snap snap_${modify_pct}
    sync
    drop_caches

    # 快照后空间
    snap_space=$(df -B1 $MOUNT | awk 'NR==2 {print $3}')

    # 修改文件
    if [ $modify_pct -gt 0 ]; then
        modify_count=$((10000 * modify_pct / 100))
        for i in $(seq 1 $modify_count); do
            echo "modified content for file $i" > $MOUNT/test/file.$i
        done
    fi
    sync
    drop_caches

    # 修改后空间
    modified_space=$(df -B1 $MOUNT | awk 'NR==2 {print $3}')

    # 计算空间放大因子
    # Amplification = (Total Space / Original Data)
    amplification=$(echo "scale=2; $modified_space / $TOTAL_SIZE" | bc)

    echo "$modify_pct,$baseline_space,$snap_space,$modified_space,$amplification" \
        >> $RESULT/space_efficiency.csv

    # 清理快照
    rm -rf $SNAP_DIR/snap_${modify_pct}
    # 恢复原文件（简化处理，实际可能需要重新准备）
done

# 输出格式
# modify_pct,baseline_space,snap_space,modified_space,space_amplification
```

### 3.3 I/O 性能影响测试

```bash
#!/bin/bash

# 测试目的：量化有/无快照时的 I/O 性能差异
# 使用 fio 多种模式测试

MOUNT="/mnt/f2fs"
SNAP_DIR="/mnt/snap"
RESULT="./results/io_performance"

mkdir -p $RESULT

# 准备测试数据
echo "Preparing test data..."
fio --name=prep --filename=$MOUNT/testfile --rw=write \
    --bs=1M --size=2G --numjobs=1 --group_reporting > /dev/null
sync
drop_caches

# 测试场景：无快照、1个快照、10个快照、50个快照
for snap_count in 0 1 10 50; do
    echo "Testing with $snap_count snapshots..."

    # 创建快照
    for i in $(seq 1 $snap_count); do
        ./test_ioctl/test $MOUNT/test /mnt/snap snap_$i
    done
    sync
    drop_caches

    # ===== 顺序读测试 =====
    fio --name=seqread --filename=$MOUNT/testfile --rw=read \
        --bs=4K --size=2G --iodepth=32 --numjobs=4 \
        --group_reporting --time_based --runtime=60 \
        --output=$RESULT/seqread_snap${snap_count}.json --output-format=json \
        --direct=1 --ioengine=libaio

    # ===== 顺序写测试（无 CoW，新文件）=====
    fio --name=seqwrite_new --filename=$MOUNT/testfile_new --rw=write \
        --bs=4K --size=2G --iodepth=32 --numjobs=4 \
        --group_reporting --time_based --runtime=60 \
        --output=$RESULT/seqwrite_new_snap${snap_count}.json --output-format=json \
        --direct=1 --ioengine=libaio --fallocate=none

    # ===== 随机读测试 =====
    fio --name=randread --filename=$MOUNT/testfile --rw=randread \
        --bs=4K --size=2G --iodepth=32 --numjobs=4 \
        --group_reporting --time_based --runtime=60 \
        --output=$RESULT/randread_snap${snap_count}.json --output-format=json \
        --direct=1 --ioengine=libaio

    # ===== 随机写测试（有 CoW，修改现有文件）=====
    fio --name=randwrite_cow --filename=$MOUNT/testfile --rw=randwrite \
        --bs=4K --size=2G --iodepth=32 --numjobs=4 \
        --group_reporting --time_based --runtime=60 \
        --output=$RESULT/randwrite_cow_snap${snap_count}.json --output-format=json \
        --direct=1 --ioengine=libaio --overwrite=1

    # ===== 混合读写测试 =====
    fio --name=mixedrw --filename=$MOUNT/testfile --rw=rw \
        --rwmixread=70 --bs=4K --size=2G --iodepth=32 --numjobs=4 \
        --group_reporting --time_based --runtime=60 \
        --output=$RESULT/mixedrw_snap${snap_count}.json --output-format=json \
        --direct=1 --ioengine=libaio

    # 清理
    for i in $(seq 1 $snap_count); do
        rm -rf $SNAP_DIR/snap_$i
    done
    rm -f $MOUNT/testfile_new
    sync
    drop_caches
done

# 解析结果
echo "snap_count,operation,iops,bandwidth_mb,lat_us" > $RESULT/io_summary.csv

for snap_count in 0 1 10 50; do
    for op in seqread seqwrite_new randread randwrite_cow mixedrw; do
        file=$RESULT/${op}_snap${snap_count}.json
        if [ -f $file ]; then
            iops=$(jq -r '.jobs[0].read.iops + .jobs[0].write.iops' $file 2>/dev/null)
            bw=$(jq -r '.jobs[0].read.bw + .jobs[0].write.bw' $file 2>/dev/null)
            lat=$(jq -r '.jobs[0].read.lat_ns.mean + .jobs[0].write.lat_ns.mean' $file 2>/dev/null)
            lat_us=$(echo "scale=2; $lat / 1000" | bc 2>/dev/null || echo "0")

            # 转换为 MB/s
            bw_mb=$(echo "scale=2; $bw / 1024" | bc 2>/dev/null || echo "0")

            echo "$snap_count,$op,$iops,$bw_mb,$lat_us" >> $RESULT/io_summary.csv
        fi
    done
done
```

### 3.4 FIO 关键参数说明

```bash
# 参数选择理由

# --bs=4K: 标准 4KB 页大小，闪存最小写入单位
# --bs=1M: 大块顺序 I/O，测试带宽
# --iodepth=32: 队列深度，模拟高并发
# --numjobs=4: 多线程，利用多核
# --direct=1: 绕过 page cache，测试真实设备性能
# --ioengine=libaio: Linux 标准 async I/O
# --time_based --runtime=60: 运行固定时间，测稳定性能
# --rwmixread=70: 混合读写，70% 读 30% 写，模拟真实负载
# --overwrite=1: 覆盖现有文件，触发 CoW

# 避免的参数
# --refill_buffers: 可能影响 CoW 触发
# --zero_buffers: 可能影响数据内容，不利于测试 CoW
```

---

## 四、Filebench 测试

### 4.1 Filebench 配置文件

```bash
# varmail.f - 邮件服务器负载
# 模拟大量小文件读写，适合测试 CoW 开销

# 创建配置文件
cat > /tmp/varmail.f << 'EOF'
# varmail configuration for SnapFS testing

set $dir=/mnt/f2fs/test
set $nfiles=10000
set $meanfilesize=128k
set $meandirwidth=20

define fileset name=bigfileset,path=$dir,size=$meanfilesize,entries=$nfiles,dirwidth=$meandirwidth

define process name=mailreader,instances=2
{
  thread name=mailreader-thread,memsize=4k
  {
    flowop openfile name=openfile1,filesetname=bigfileset,fd=1
    flowop readwholefile name=readfile1,fd=1,iosize=1M
    flowop closefile name=closefile1,fd=1
    flowop deletefile name=deletefile1,filesetname=bigfileset
    flowop createfile name=createfile1,filesetname=bigfilefileset,fd=1
    flowop writewholefile name=writefile1,fd=1,iosize=1M
    flowop closefile name=closefile2,fd=1
  }
}

run 60
EOF

# fileserver.f - 文件服务器负载
cat > /tmp/fileserver.f << 'EOF'
set $dir=/mnt/f2fs/test
set $nfiles=5000
set $meanfilesize=1M

define fileset name=largefileset,path=$dir,size=$meanfilesize,entries=$nfiles,dirwidth=20,prealloc=80

define process name=filewriter,instances=1
{
  thread name=filewriter-thread,memsize=4k
  {
    flowop createfile name=createfile1,filesetname=largefileset,fd=1
    flowop writewholefile name=writefile1,fd=1,iosize=$meanfilesize
    flowop closefile name=closefile1,fd=1
    flowop deletefile name=deletefile1,filesetname=largefileset
  }
}

define process name=filereader,instances=4
{
  thread name=filereader-thread,memsize=4k
  {
    flowop openfile name=openfile1,filesetname=largefileset,fd=1
    flowop readwholefile name=readfile1,fd=1,iosize=$meanfilesize
    flowop closefile name=closefile1,fd=1
  }
}

run 60
EOF
```

### 4.2 Filebench 测试脚本

```bash
#!/bin/bash

MOUNT="/mnt/f2fs"
SNAP_DIR="/mnt/snap"
RESULT="./results/filebench"

mkdir -p $RESULT

# 测试场景：无快照、1个快照、5个快照
for snap_count in 0 1 5; do
    echo "Filebench with $snap_count snapshots..."

    # 准备测试目录
    rm -rf $MOUNT/test/*
    mkdir -p $MOUNT/test

    # 运行 varmail 测试（无快照基线）
    filebench -f /tmp/varmail.f > $RESULT/varmail_snap${snap_count}.txt 2>&1

    # 提取关键指标
    ops=$(grep "IO summary" $RESULT/varmail_snap${snap_count}.txt | awk '{print $4}')
    mb_per_sec=$(grep "IO summary" $RESULT/varmail_snap${snap_count}.txt | awk '{print $6}')
    lat_ms=$(grep "IO summary" $RESULT/varmail_snap${snap_count}.txt | awk '{print $8}')

    echo "$snap_count,varmail,$ops,$mb_per_sec,$lat_ms" >> $RESULT/filebench_summary.csv

    # 清理
    rm -rf $MOUNT/test/*
done
```

---

## 五、元数据性能测试

### 5.1 mdtest 测试

```bash
#!/bin/bash

# 测试目的：验证 CoW 对元数据操作的影响
# 元数据操作（创建/删除文件）在快照场景下需要触发 CoW

MOUNT="/mnt/f2fs"
SNAP_DIR="/mnt/snap"
RESULT="./results/metadata"

mkdir -p $RESULT

# 测试规模
for count in 1000 10000 50000; do
    for snap_count in 0 1 5; do
        echo "mdtest: $count files, $snap_count snapshots..."

        rm -rf $MOUNT/test/*
        mkdir -p $MOUNT/test

        # 创建快照
        for i in $(seq 1 $snap_count); do
            ./test_ioctl/test $MOUNT/test /mnt/snap snap_$i
        done

        # mdtest 测试
        mdtest -T -d $MOUNT/test -n $count -i 4 > $RESULT/mdtest_${count}_snap${snap_count}.txt

        # 提取创建速率
        create_rate=$(grep "created" $RESULT/mdtest_${count}_snap${snap_count}.txt | tail -1 | awk '{print $2}')
        stat_rate=$(grep "stat" $RESULT/mdtest_${count}_snap${snap_count}.txt | tail -1 | awk '{print $2}')
        read_rate=$(grep "read" $RESULT/mdtest_${count}_snap${snap_count}.txt | tail -1 | awk '{print $2}')
        delete_rate=$(grep "removed" $RESULT/mdtest_${count}_snap${snap_count}.txt | tail -1 | awk '{print $2}')

        echo "$count,$snap_count,$create_rate,$stat_rate,$read_rate,$delete_rate" \
            >> $RESULT/metadata_summary.csv

        # 清理
        for i in $(seq 1 $snap_count); do
            rm -rf $SNAP_DIR/snap_$i
        done
    done
done
```

---

## 六、对比测试脚本

### 6.1 SnapFS vs Btrfs 对比

```bash
#!/bin/bash

# 测试目的：与主流 CoW 文件系统对比

RESULT="./results/comparison"
mkdir -p $RESULT

# 测试数据
DATA_SIZE="10G"
FILE_COUNT=10000
FILE_SIZE="1M"

# 测试函数
test_filesystem() {
    local fs=$1
    local mount=$2
    local snap_cmd=$3

    echo "=== Testing $fs ==="

    # 准备数据
    rm -rf $mount/*
    mkdir -p $mount/test

    echo "Creating $FILE_COUNT files of $FILE_SIZE each..."
    fio --name=prep --filename=$mount/test/file --rw=write \
        --bs=$FILE_SIZE --size=$FILE_SIZE --numjobs=$FILE_COUNT \
        --group_reporting > /dev/null
    sync
    drop_caches

    # 记录基线空间
    baseline_space=$(df -B1 $mount | awk 'NR==2 {print $3}')

    # 测试快照创建时间
    START=$(date +%s.%N)
    $snap_cmd create $mount/test $mount/snap_test
    END=$(date +%s.%N)
    create_time=$(echo "$END - $START" | bc)

    sync
    drop_caches

    # 记录快照后空间
    snap_space=$(df -B1 $mount | awk 'NR==2 {print $3}')
    snap_overhead=$((snap_space - baseline_space))

    # 测试 I/O 性能（随机读写）
    fio --name=randread --filename=$mount/test/file.1 --rw=randread \
        --bs=4K --size=1M --iodepth=16 --time_based --runtime=30 \
        --output=$RESULT/${fs}_read.json --output-format=json \
        --direct=1 --ioengine=libaio

    fio --name=randwrite --filename=$mount/test/file.1 --rw=randwrite \
        --bs=4K --size=1M --iodepth=16 --time_based --runtime=30 \
        --output=$RESULT/${fs}_write.json --output-format=json \
        --direct=1 --ioengine=libaio --overwrite=1

    # 提取 I/O 指标
    read_iops=$(jq -r '.jobs[0].read.iops' $RESULT/${fs}_read.json)
    write_iops=$(jq -r '.jobs[0].write.iops' $RESULT/${fs}_write.json)

    echo "$fs,$create_time,$snap_overhead,$read_iops,$write_iops" >> $RESULT/comparison.csv

    # 清理快照
    $snap_cmd delete $mount/snap_test
}

# SnapFS 测试
mount -t f2fs /dev/sdX1 /mnt/f2fs_snap
test_filesystem "SnapFS" "/mnt/f2fs_snap" "./snapfs_snapshot.sh"
umount /mnt/f2fs_snap

# Btrfs 测试
mount -t btrfs /dev/sdX2 /mnt/btrfs
test_filesystem "Btrfs" "/mnt/btrfs" "./btrfs_snapshot.sh"
umount /mnt/btrfs
```

---

## 七、测试数据收集与分析

### 7.1 数据收集脚本

```bash
#!/bin/bash

# 统一收集所有测试数据并生成报告

RESULT="./results"
REPORT="./results/report.txt"

echo "=== SnapFS Performance Test Report ===" > $REPORT
echo "Generated: $(date)" >> $REPORT
echo "" >> $REPORT

# 1. 快照创建时间分析
echo "## 1. Snapshot Creation Time" >> $REPORT
echo "" >> $REPORT
if [ -f $RESULT/create_time.csv ]; then
    echo "File Size,File Count,Time (sec),Space Used (bytes)" >> $REPORT
    cat $RESULT/create_time.csv >> $REPORT
    echo "" >> $REPORT
fi

# 2. 空间效率分析
echo "## 2. Space Efficiency" >> $REPORT
echo "" >> $REPORT
if [ -f $RESULT/space_efficiency.csv ]; then
    echo "Modify %,Baseline,After Snap,After Modify,Amplification" >> $REPORT
    cat $RESULT/space_efficiency.csv >> $REPORT
    echo "" >> $REPORT

    # 计算平均空间放大
    avg_amp=$(awk -F, 'NR>1 {sum+=$5; count++} END {print sum/count}' $RESULT/space_efficiency.csv)
    echo "Average Space Amplification: $avg_amp" >> $REPORT
    echo "" >> $REPORT
fi

# 3. I/O 性能对比
echo "## 3. I/O Performance Impact" >> $REPORT
echo "" >> $REPORT
if [ -f $RESULT/io_summary.csv ]; then
    echo "Snap Count,Operation,IOPS,BW (MB/s),Lat (us)" >> $REPORT
    cat $RESULT/io_summary.csv >> $REPORT
    echo "" >> $REPORT

    # 计算性能下降百分比
    echo "Performance Impact (vs 0 snapshots):" >> $REPORT
    for snap_count in 1 10 50; do
        for op in seqread randread seqwrite_new randwrite_cow; do
            base=$(awk -F, "\$1==0 && \$2==\"$op\" {print \$3}" $RESULT/io_summary.csv)
            curr=$(awk -F, "\$1==$snap_count && \$2==\"$op\" {print \$3}" $RESULT/io_summary.csv)
            if [ -n "$base" ] && [ -n "$curr" ] && [ "$base" != "0" ]; then
                impact=$(echo "scale=2; ($curr - $base) / $base * 100" | bc)
                echo "  $snap_count snaps, $op: $impact%" >> $REPORT
            fi
        done
    done
    echo "" >> $REPORT
fi

# 4. 文件系统对比
echo "## 4. Filesystem Comparison" >> $REPORT
echo "" >> $REPORT
if [ -f $RESULT/comparison.csv ]; then
    echo "FS,Create Time,Overhead,Read IOPS,Write IOPS" >> $REPORT
    cat $RESULT/comparison.csv >> $REPORT
    echo "" >> $REPORT
fi

cat $REPORT
```

---

## 八、论文图表生成

### 8.1 使用 Python 生成图表

```python
#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# 设置中文支持
plt.rcParams['font.sans-serif'] = ['SimHei', 'DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

# 图1: 快照创建时间 vs 文件数量
def plot_creation_time():
    df = pd.read_csv('results/create_time.csv')
    df['file_count'] = df['file_count'].astype(int)

    fig, ax = plt.subplots(figsize=(10, 6))
    sizes = df['file_size'].unique()
    for size in sizes:
        data = df[df['file_size'] == size]
        ax.plot(data['file_count'], data['create_time_sec'],
                marker='o', label=f'File Size: {size}')

    ax.set_xlabel('Number of Files')
    ax.set_ylabel('Snapshot Creation Time (s)')
    ax.set_title('Snapshot Creation Time vs File Count')
    ax.set_xscale('log')
    ax.legend()
    ax.grid(True, alpha=0.3)
    plt.savefig('results/fig1_creation_time.png', dpi=300)
    plt.close()

# 图2: 空间放大因子
def plot_space_amplification():
    df = pd.read_csv('results/space_efficiency.csv')

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(df['modify_pct'], df['space_amplification'],
            marker='s', linewidth=2, markersize=8)

    ax.axhline(y=1.0, color='r', linestyle='--', label='No Overhead')
    ax.set_xlabel('Modification Percentage (%)')
    ax.set_ylabel('Space Amplification Factor')
    ax.set_title('Space Efficiency: Amplification vs Modification')
    ax.set_ylim(0.8, 2.0)
    ax.legend()
    ax.grid(True, alpha=0.3)
    plt.savefig('results/fig2_space_efficiency.png', dpi=300)
    plt.close()

# 图3: I/O 性能开销
def plot_io_overhead():
    df = pd.read_csv('results/io_summary.csv')

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    # IOPS
    for op in ['seqread', 'randread', 'seqwrite_new', 'randwrite_cow']:
        data = df[df['operation'] == op]
        ax1.plot(data['snap_count'], data['iops'],
                marker='o', label=op)

    ax1.set_xlabel('Number of Snapshots')
    ax1.set_ylabel('IOPS')
    ax1.set_title('IOPS vs Snapshot Count')
    ax1.legend()
    ax1.grid(True, alpha=0.3)

    # Latency
    for op in ['seqread', 'randread', 'seqwrite_new', 'randwrite_cow']:
        data = df[df['operation'] == op]
        ax2.plot(data['snap_count'], data['lat_us'],
                marker='s', label=op)

    ax2.set_xlabel('Number of Snapshots')
    ax2.set_ylabel('Latency (µs)')
    ax2.set_title('Latency vs Snapshot Count')
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig('results/fig3_io_overhead.png', dpi=300)
    plt.close()

# 图4: 与其他文件系统对比
def plot_fs_comparison():
    df = pd.read_csv('results/comparison.csv')

    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(15, 5))

    # 创建时间
    ax1.bar(df['fs'], df['create_time'], color='steelblue')
    ax1.set_ylabel('Time (s)')
    ax1.set_title('Snapshot Creation Time')

    # 空间开销
    overhead_mb = df['snap_overhead'] / (1024 * 1024)
    ax2.bar(df['fs'], overhead_mb, color='lightcoral')
    ax2.set_ylabel('Overhead (MB)')
    ax2.set_title('Space Overhead')

    # IOPS
    x = np.arange(len(df))
    width = 0.35
    ax3.bar(x - width/2, df['read_iops'], width, label='Read', color='green')
    ax3.bar(x + width/2, df['write_iops'], width, label='Write', color='orange')
    ax3.set_ylabel('IOPS')
    ax3.set_title('I/O Performance')
    ax3.set_xticks(x)
    ax3.set_xticklabels(df['fs'])
    ax3.legend()

    plt.tight_layout()
    plt.savefig('results/fig4_fs_comparison.png', dpi=300)
    plt.close()

if __name__ == '__main__':
    plot_creation_time()
    plot_space_amplification()
    plot_io_overhead()
    plot_fs_comparison()
    print("All plots generated successfully!")
```

---

## 九、测试执行流程

```bash
#!/bin/bash

# 完整测试流程

echo "=== SnapFS Comprehensive Test Suite ==="
echo "Start time: $(date)"

# 1. 环境检查
echo "[1/7] Checking environment..."
./scripts/check_env.sh

# 2. 清理并准备
echo "[2/7] Cleaning and preparing..."
./scripts/prepare_test.sh

# 3. 快照创建时间测试
echo "[3/7] Testing snapshot creation time..."
./scripts/test_snap_create.sh

# 4. 空间效率测试
echo "[4/7] Testing space efficiency..."
./scripts/test_space.sh

# 5. I/O 性能测试
echo "[5/7] Testing I/O performance..."
./scripts/test_io.sh

# 6. Filebench 测试
echo "[6/7] Running filebench workloads..."
./scripts/test_filebench.sh

# 7. 生成报告
echo "[7/7] Generating report..."
./scripts/collect_results.sh
python3 scripts/generate_plots.py

echo "=== Test Complete ==="
echo "End time: $(date)"
echo "Results saved to ./results/"
```

---

## 十、测试结果分析要点

### 10.1 SnapFS 预期优势

| 指标 | 预期结果 | 论文论点 |
|------|----------|----------|
| **快照创建时间** | < 0.1s (1000文件) | 只复制元数据，不复制数据 |
| **空间开销** | < 5% (100%修改前) | 数据块共享，node 复制轻量 |
| **读性能损失** | < 3% | mulref 查询开销极小 |
| **写性能损失（新文件）** | < 5% | 不触发 CoW |
| **写性能损失（修改）** | 10-20% | CoW 开销，但仅在首次写 |
| **多快照扩展性** | 线性增长 | O(1) 哈希查找 |

### 10.2 与 Btrfs 对比预期

| 指标 | SnapFS vs Btrfs | 原因 |
|------|-----------------|------|
| 快照创建时间 | 更快 | f2fs 元数据结构更简单 |
| 空间效率 | 相当 | 都是 CoW |
| 闪存友好性 | 更好 | 基于 f2fs 日志结构 |
| 写放大 | 更低 | f2fs 优化了写操作 |

---

## 十一、故障排查

```bash
# 常见问题

# 1. fio 无法运行
# 确保直接 I/O 权限
sudo chmod 666 /dev/sdX1

# 2. 快照创建失败
# 检查模块加载
lsmod | grep snapfs
dmesg | grep snapfs

# 3. 空间不足
# 清理测试数据
rm -rf /mnt/f2fs/test/*

# 4. 性能数据异常
# 确保没有其他进程干扰
htop  # 检查 CPU/IO 使用
sync && echo 3 > /proc/sys/vm/drop_caches  # 清理缓存
```