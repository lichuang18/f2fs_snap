# F2FS 快照文件系统 - 论文实验设计

> 本文档记录论文发表所需的实验指标和测试方案

## 一、核心性能指标

### 1.1 快照操作性能

| 指标 | 测试方法 | 意义 |
|------|----------|------|
| **快照创建时间** | 不同文件数量/大小下创建快照耗时 | 体现元数据复制效率 |
| **快照删除时间** | 删除快照耗时（含引用计数更新） | 体现 mulref 清理效率 |
| **快照恢复时间** | 从快照恢复数据耗时 | 实用性指标 |

### 1.2 空间效率

| 指标 | 测试方法 | 意义 |
|------|----------|------|
| **快照空间开销** | 创建快照后额外占用空间 | CoW 的核心优势 |
| **空间放大因子** | (快照后总空间 / 原始数据) | 与全量复制对比 |
| **修改后空间增长** | 快照后修改文件的空间变化 | 体现 CoW 效果 |

### 1.3 I/O 性能影响

| 指标 | 测试方法 | 意义 |
|------|----------|------|
| **读性能开销** | 有/无快照时的读吞吐量对比 | mulref 查询开销 |
| **写性能开销** | 有/无快照时的写吞吐量对比 | CoW 触发开销 |
| **首次写延迟** | 快照后首次修改文件的延迟 | CoW 路径开销 |

## 二、可扩展性指标

### 2.1 多快照场景

```
测试维度：
- 快照数量: 1, 10, 50, 100, 200 个快照
- 测量: 创建时间、删除时间、读写性能
```

| 指标 | 意义 |
|------|------|
| **第N个快照创建时间** | mulref 链表遍历开销 |
| **多快照下读性能** | 引用计数查询开销 |
| **多快照下写性能** | CoW 复杂度增长 |

### 2.2 数据规模

```
测试维度：
- 文件数量: 1K, 10K, 100K, 1M 个文件
- 文件大小: 4KB, 64KB, 1MB, 100MB
- 目录深度: 1, 5, 10, 20 层
```

## 三、对比基准

### 3.1 对比对象

| 系统 | 类型 | 对比意义 |
|------|------|----------|
| **Btrfs** | CoW 文件系统 | 同类方案对比 |
| **ZFS** | CoW + 快照 | 成熟方案对比 |
| **LVM snapshot** | 块级快照 | 不同层次对比 |
| **原生 f2fs** | 无快照 | 基线性能 |
| **rsync/cp** | 全量复制 | 空间效率对比 |

### 3.2 关键对比指标

```
1. 快照创建时间 vs Btrfs/ZFS
2. 空间效率 vs 全量复制
3. 正常 I/O 性能损失 vs 原生 f2fs
4. 多快照扩展性 vs Btrfs
```

## 四、特色指标（突出设计优势）

### 4.1 Magic Table 效率

| 指标 | 意义 |
|------|------|
| **哈希查找命中率** | hopscotch hashing 效果 |
| **冲突链平均长度** | 哈希表设计质量 |
| **查找延迟分布** | P50/P99 延迟 |

### 4.2 Mulref 机制效率

| 指标 | 意义 |
|------|------|
| **引用计数更新开销** | mulref entry 操作效率 |
| **共享块比例** | 空间节省效果 |
| **GC 对 mulref 块的处理时间** | GC 集成效果 |

### 4.3 三阶段锁效果

| 指标 | 意义 |
|------|------|
| **并发快照创建性能** | 多线程同时创建快照 |
| **锁竞争统计** | 死锁避免效果 |

## 五、Workload 设计

### 5.1 微基准测试 (Microbenchmark)

```bash
# 快照创建
time create_snapshot /mnt/test /mnt/snap

# 顺序写 + CoW
fio --name=seqwrite --rw=write --bs=4k --size=1G

# 随机写 + CoW
fio --name=randwrite --rw=randwrite --bs=4k --size=1G

# 元数据操作
mdtest -C -T -r -F -d /mnt/test -n 10000
```

### 5.2 宏基准测试 (Macrobenchmark)

| Workload | 工具 | 场景 |
|----------|------|------|
| **Filebench** | varmail, fileserver | 真实负载模拟 |
| **YCSB** | 数据库负载 | 数据库场景 |
| **Kernel compile** | make -j | 开发场景 |
| **Git operations** | clone, checkout | 版本控制场景 |

### 5.3 真实应用场景

```
- 虚拟机快照: 创建 VM 磁盘快照
- 数据库备份: MySQL/PostgreSQL 热备份
- 容器镜像: Docker layer 场景
```

## 六、论文图表建议

### 6.1 必备图表

```
Figure 1: 快照创建时间 vs 文件数量
Figure 2: 空间效率对比 (SnapFS vs rsync vs Btrfs)
Figure 3: 多快照下的性能变化曲线
Figure 4: 读写性能开销 (有/无快照对比)
Figure 5: 与 Btrfs/ZFS 的性能对比
```

### 6.2 可选图表

```
- Magic table 查找延迟分布 (CDF)
- Mulref 链表长度分布
- 并发性能扩展性
- 不同文件大小下的 CoW 开销
```

## 七、测试脚本框架

### 7.1 基础性能测试

```bash
#!/bin/bash
# 基础性能测试框架

MOUNT_POINT="/mnt/f2fs"
SNAP_POINT="/mnt/snap"
RESULT_DIR="./results"

mkdir -p $RESULT_DIR

# 1. 快照创建时间 vs 文件数量
echo "=== Test 1: Snapshot Creation Time ==="
for files in 1000 10000 100000; do
    echo "Testing with $files files..."
    prepare_files $MOUNT_POINT $files

    start=$(date +%s.%N)
    # 调用快照创建 ioctl
    create_snapshot $MOUNT_POINT $SNAP_POINT
    end=$(date +%s.%N)

    echo "$files, $(echo "$end - $start" | bc)" >> $RESULT_DIR/creation_time.csv
    cleanup
done

# 2. 空间效率测试
echo "=== Test 2: Space Efficiency ==="
for modify_ratio in 0 10 30 50 100; do
    prepare_files $MOUNT_POINT 10000
    space_before=$(df $MOUNT_POINT | awk 'NR==2 {print $3}')

    create_snapshot $MOUNT_POINT $SNAP_POINT
    space_after_snap=$(df $MOUNT_POINT | awk 'NR==2 {print $3}')

    modify_files $MOUNT_POINT $modify_ratio
    space_after_modify=$(df $MOUNT_POINT | awk 'NR==2 {print $3}')

    echo "$modify_ratio, $space_before, $space_after_snap, $space_after_modify" >> $RESULT_DIR/space.csv
    cleanup
done

# 3. I/O 性能测试
echo "=== Test 3: I/O Performance ==="
for snap_count in 0 1 10 50 100; do
    prepare_files $MOUNT_POINT 10000

    for i in $(seq 1 $snap_count); do
        create_snapshot $MOUNT_POINT "${SNAP_POINT}_$i"
    done

    # FIO 测试
    fio --name=seqread --rw=read --bs=4k --size=1G --directory=$MOUNT_POINT \
        --output=$RESULT_DIR/fio_snap${snap_count}_read.json --output-format=json

    fio --name=seqwrite --rw=write --bs=4k --size=1G --directory=$MOUNT_POINT \
        --output=$RESULT_DIR/fio_snap${snap_count}_write.json --output-format=json

    cleanup
done
```

### 7.2 对比测试脚本

```bash
#!/bin/bash
# 与其他文件系统对比测试

FILESYSTEMS=("f2fs_snap" "btrfs" "zfs" "ext4_lvm")
TEST_SIZE="10G"
FILE_COUNT=10000

for fs in "${FILESYSTEMS[@]}"; do
    echo "=== Testing $fs ==="

    # 挂载对应文件系统
    mount_filesystem $fs

    # 准备测试数据
    prepare_test_data $FILE_COUNT

    # 测试快照创建时间
    time_snapshot_create $fs

    # 测试空间开销
    measure_space_overhead $fs

    # 测试 I/O 性能
    run_fio_benchmark $fs

    # 清理
    cleanup_filesystem $fs
done
```

### 7.3 Filebench 测试

```bash
#!/bin/bash
# Filebench workload 测试

WORKLOADS=("varmail" "fileserver" "webserver")

for workload in "${WORKLOADS[@]}"; do
    echo "=== Running $workload ==="

    # 无快照基线
    filebench -f workloads/${workload}.f > results/${workload}_baseline.txt

    # 创建快照后
    create_snapshot
    filebench -f workloads/${workload}.f > results/${workload}_with_snap.txt

    # 多快照场景
    for i in {1..10}; do
        create_snapshot
    done
    filebench -f workloads/${workload}.f > results/${workload}_multi_snap.txt
done
```

## 八、论文亮点总结

基于本设计，论文可重点强调以下优势：

### 8.1 技术创新点

1. **空间效率**: CoW 只复制 node 元数据，数据块通过 mulref 共享
2. **闪存友好**: 基于 f2fs 的日志结构，减少写放大
3. **细粒度快照**: 文件级别而非块级别，更灵活
4. **低开销**: 三阶段锁避免死锁，减少锁竞争
5. **高效查找**: hopscotch hashing 实现 O(1) 快照映射查找

### 8.2 预期实验结论

| 对比维度 | 预期结果 |
|----------|----------|
| 快照创建时间 | 优于 Btrfs（只复制元数据） |
| 空间效率 | 远优于全量复制，接近 Btrfs/ZFS |
| 读性能开销 | < 5%（mulref 查询开销小） |
| 写性能开销 | 首次写有 CoW 开销，后续正常 |
| 多快照扩展性 | 线性增长，优于链表遍历方案 |

### 8.3 适用场景

- 移动设备数据保护
- 嵌入式系统快照备份
- SSD/闪存存储优化
- 容器镜像分层存储
