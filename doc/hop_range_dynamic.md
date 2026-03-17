# 动态 Hop Range 实现说明

## 概述

实现了一个简单的后台线程，根据 magic entry 的使用率动态调整 hopscotch 哈希的 hop_range 参数。

## 设计原则

- **简单**: 不需要复杂的负载因子计算和频繁调整
- **自适应**: 根据实际使用情况自动调整
- **低开销**: 线程大部分时间处于睡眠状态

## 配置参数

```c
#define HOP_RANGE_INIT      4    // 初始 hop_range (低负载)
#define HOP_RANGE_MED       16   // 中等负载 (50%+)
#define HOP_RANGE_HIGH      32   // 高负载 (80%+)
#define HOP_RANGE_ADJUST_INTERVAL  5000  // 检查间隔 5 秒
```

## 调整策略

| 负载率 | hop_range | 说明 |
|--------|-----------|------|
| < 50%  | 4         | 低负载，减少查询开销 |
| 50-79% | 16        | 中等负载，平衡性能 |
| ≥ 80%  | 32        | 高负载，减少冲突 |

## 核心数据结构

### f2fs_magic_info 新增字段

```c
struct f2fs_magic_info {
    // ... 原有字段 ...
    u32 hop_range;              // 当前 hop_range 值
    atomic_t used_entries;      // 已使用的 entry 数量
};
```

### 线程结构

```c
struct f2fs_hop_range_kthread {
    struct task_struct *f2fs_hop_task;
    wait_queue_head_t hop_wait_queue;
    unsigned int sleep_time;    // 检查间隔 (ms)
};
```

## 工作流程

### 1. 挂载时初始化

```
f2fs_build_segment_manager()
  ├─ 分配 magic_info
  ├─ 初始化 hop_range = HOP_RANGE_INIT (4)
  ├─ 初始化 used_entries = 0
  ├─ rebuild_snap_index()  // 统计已有 entry
  └─ f2fs_start_hop_range_thread()  // 启动调整线程
```

### 2. 运行时更新

**插入 entry 时**:
```c
f2fs_magic_lookup_or_alloc_hopscotch()
  └─ atomic_inc(&mi->used_entries)  // 成功插入后计数+1
```

**删除 entry 时**:
```c
f2fs_magic_delete_entry()
  └─ atomic_dec(&mi->used_entries)  // 删除后计数-1
```

### 3. 后台线程逻辑

```c
hop_range_adjust_thread() {
    while (!kthread_should_stop()) {
        sleep(5000ms);

        // 计算负载率
        used = atomic_read(&mi->used_entries);
        load_percent = (used * 100) / MAGIC_ENTRY_NR;

        // 调整 hop_range
        if (load_percent >= 80)
            mi->hop_range = 32;
        else if (load_percent >= 50)
            mi->hop_range = 16;
        else
            mi->hop_range = 4;
    }
}
```

### 4. 卸载时清理

```
f2fs_put_super()
  └─ f2fs_stop_hop_range_thread()  // 停止线程并释放资源
```

## 性能影响

### 优势

1. **低负载优化**: 初始 hop_range=4，减少不必要的查询开销
2. **高负载适应**: 自动增大到 32，减少冲突和 displacement 失败
3. **双向调整**: 负载降低时自动减小 hop_range
4. **低开销**: 5 秒检查一次，几乎无性能影响

### 查询性能对比

| 场景 | 固定 hop_range=32 | 动态调整 |
|------|-------------------|----------|
| 空表 (0% 负载) | 扫描 32 个位置 | 扫描 4 个位置 (8x 提升) |
| 半满 (50% 负载) | 扫描 32 个位置 | 扫描 16 个位置 (2x 提升) |
| 接近满 (80%+) | 扫描 32 个位置 | 扫描 32 个位置 (相同) |

## 日志输出

### 挂载时

```
[snapfs hop_range]: thread started, check interval=5000ms
[rebuild snap index]: found 1234 existing magic entries
```

### 运行时调整

```
[snapfs hop_range]: adjusted 4 -> 16 (load=52%, used=162048/311296)
[snapfs hop_range]: adjusted 16 -> 32 (load=81%, used=252249/311296)
[snapfs hop_range]: adjusted 32 -> 16 (load=45%, used=140083/311296)
```

### 卸载时

```
[snapfs hop_range]: thread stopped
```

## 测试建议

### 1. 基本功能测试

```bash
# 挂载文件系统
mount -t f2fs /dev/sda /mnt

# 查看初始 hop_range (应该是 4)
dmesg | grep hop_range

# 创建快照直到负载超过 50%
for i in {1..1000}; do
    ./test_ioctl/test /mnt/data /mnt snap_$i
done

# 观察 hop_range 是否调整到 16
dmesg | grep "adjusted.*16"

# 继续创建快照直到负载超过 80%
# 观察 hop_range 是否调整到 32
```

### 2. 删除测试

```bash
# 删除大量快照
for i in {1..500}; do
    ./test_ioctl/test_delete /mnt/snap_$i
done

# 观察 hop_range 是否降低
dmesg | grep "adjusted.*4\|adjusted.*16"
```

### 3. 性能测试

```bash
# 测试低负载查询性能
time for i in {1..1000}; do
    ./test_ioctl/test /mnt/data /mnt snap_$i
done

# 测试高负载查询性能
# (在负载 > 80% 时重复上述测试)
```

## 未来优化方向

1. **可调参数**: 通过 sysfs 暴露阈值和间隔参数
2. **更细粒度**: 支持更多档位 (如 8, 24, 48, 64)
3. **自适应间隔**: 根据负载变化速度调整检查频率
4. **统计信息**: 记录调整历史和性能指标

## 代码位置

- **数据结构**: `f2fs.h:1062-1073, 1113-1117`
- **线程实现**: `snapshot.c:5395-5498`
- **函数声明**: `snapshot.h:73-74`
- **初始化**: `segment.c:5716-5728, 5689-5693`
- **启动/停止**: `super.c:4410-4423, 1585-1593`
- **计数更新**: `snapshot.c:2363`, `file.c:3653`
