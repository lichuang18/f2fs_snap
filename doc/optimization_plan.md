# f2fs_set_mulref_blocks 性能优化方案 v2

## 问题分析

当前实现虽然改为 node-by-node 遍历，但对 20GB 文件（约 524 万个块）仍然耗时 1.9s，仅优化了 20ms。

### 根本瓶颈

**锁和 I/O 开销过高**：

```
对于 524 万个块：
- 锁操作：524万 × 3 = 1570万次（curmulref_lock + curmulref_mutex + smentry_lock）
- Meta page 访问：524万 × 2 = 1048万次
- SIT 更新：524万次
```

### 热点路径分析

```c
f2fs_set_mulref_blocks()
  └─ for each block (524万次):
       └─ set_mulref_entry()
            ├─ f2fs_alloc_mulref_entry()
            │    ├─ curmulref_alloc_entry()  // 锁1+2，meta page读1
            │    │    ├─ down_write(&curmulref_lock)
            │    │    ├─ mutex_lock(&curmulref_mutex)
            │    │    ├─ f2fs_get_meta_page()
            │    │    └─ f2fs_put_page()
            │    ├─ down_write(&curmulref_lock)  // 重复获取
            │    ├─ mutex_lock(&curmulref_mutex)
            │    ├─ f2fs_get_meta_page()  // 重复读取
            │    └─ f2fs_put_page()
            └─ update_sit_mulref_entry()  // 锁3
                 ├─ down_write(&smentry_lock)
                 └─ 位图操作
```

## 优化策略

### 核心思想：批量处理 + 锁粗化

将 524 万次细粒度操作合并为少量批次，每批次：
1. **一次获取所有锁**
2. **缓存 meta page**
3. **批量分配 entry**
4. **批量更新 SIT**
5. **一次释放所有锁**

### 批次大小选择

- **太小**：锁开销仍然高
- **太大**：持锁时间长，影响并发
- **推荐**：1024 个块/批次（约 4MB 数据）

对于 20GB 文件：524万 / 1024 ≈ 5117 批次
- 锁操作：5117 × 3 = 15,351 次（减少 99.9%）
- Meta page 访问：显著减少（缓存命中率高）

## 实现方案

### 1. 新增批量接口

```c
// snapshot.c 新增函数
int set_mulref_entry_batch(struct f2fs_sb_info *sbi,
                           block_t *blkaddrs,
                           nid_t *owners,
                           unsigned int count)
{
    struct f2fs_sm_info *sm = SM_I(sbi);
    struct curmulref_info *cmr = &sm->curmulref_blk;
    struct sit_mulref_info *smi = SIT_MR_I(sbi);
    struct page *cached_mulref_page = NULL;
    block_t cached_blkaddr = NULL_ADDR;
    unsigned int i;
    int ret = 0;

    // 一次性获取所有锁
    down_write(&sm->curmulref_lock);
    mutex_lock(&cmr->curmulref_mutex);
    down_write(&smi->smentry_lock);

    for (i = 0; i < count; i++) {
        block_t blkaddr = blkaddrs[i];
        nid_t owner = owners[i];

        // 检查是否已经是 mulref
        bool is_mulref = check_sit_mulref_entry_nolock(sbi, blkaddr);

        // 分配 entry（复用缓存的 page）
        ret = alloc_mulref_entry_nolock(sbi, cmr, blkaddr, owner,
                                        is_mulref, &cached_mulref_page,
                                        &cached_blkaddr);
        if (ret)
            goto out;

        // 批量更新 SIT（无锁版本）
        update_sit_mulref_entry_nolock(sbi, smi, blkaddr);
    }

out:
    // 写回缓存的 page
    if (cached_mulref_page) {
        set_page_dirty(cached_mulref_page);
        f2fs_put_page(cached_mulref_page, 1);
    }

    // 一次性释放所有锁
    up_write(&smi->smentry_lock);
    mutex_unlock(&cmr->curmulref_mutex);
    up_write(&sm->curmulref_lock);

    return ret;
}
```

### 2. 修改 f2fs_set_mulref_blocks()

将原来的：
```c
for (i = 0; i < nr; i++) {
    ret = set_mulref_entry(sbi, blk_buf[i], owner_buf[i]);
    if (ret) goto out;
}
```

改为：
```c
// 分批处理，每批 1024 个
#define BATCH_SIZE 1024
for (i = 0; i < nr; i += BATCH_SIZE) {
    unsigned int batch_cnt = min(nr - i, BATCH_SIZE);
    ret = set_mulref_entry_batch(sbi, &blk_buf[i], &owner_buf[i], batch_cnt);
    if (ret) goto out;
}
```

### 3. 新增无锁辅助函数

```c
// 无锁版本的 SIT 检查（调用者已持锁）
static bool check_sit_mulref_entry_nolock(struct f2fs_sb_info *sbi,
                                          block_t blkaddr);

// 无锁版本的 SIT 更新（调用者已持锁）
static void update_sit_mulref_entry_nolock(struct f2fs_sb_info *sbi,
                                           struct sit_mulref_info *smi,
                                           block_t blkaddr);

// 无锁版本的 entry 分配（调用者已持锁，复用缓存 page）
static int alloc_mulref_entry_nolock(struct f2fs_sb_info *sbi,
                                     struct curmulref_info *cmr,
                                     block_t blkaddr,
                                     nid_t owner,
                                     bool is_mulref,
                                     struct page **cached_page,
                                     block_t *cached_blkaddr);
```

## 预期效果

### 性能提升

- **锁操作**：1570万 → 1.5万（减少 99.9%）
- **Meta page 访问**：大幅减少（缓存命中）
- **预计耗时**：1.9s → 50-100ms（提升 20-40 倍）

### 风险控制

1. **持锁时间**：每批 1024 个块，约 1-2ms，不会阻塞其他操作
2. **内存占用**：无额外内存（复用现有 blk_buf/owner_buf）
3. **正确性**：保持原有语义，仅改变执行顺序

## 实现步骤

1. 实现无锁辅助函数（snapshot.c）
2. 实现 `set_mulref_entry_batch()`
3. 修改 `f2fs_set_mulref_blocks()` 的 5 个调用点
4. 编译测试
5. 性能对比

## 注意事项

- 保持 `set_mulref_entry()` 原函数不变（其他地方可能调用）
- 批量函数仅在 `f2fs_set_mulref_blocks()` 内使用
- 错误处理：任何失败立即释放锁并返回
