# 性能瓶颈深度分析

## 用户关键提醒

**Mulref entry 分配是随机的**：
- 初期可能顺序分配
- 随着分配/删除，bitmap 出现空洞
- 后续分配可能跨越多个 mulref 块
- **一个 batch 内的 1024 个数据块，其 entry 可能分散在不同的 mulref 块中**

## 重新审视代码逻辑

### 1. Entry 分配流程

```c
set_mulref_entry(sbi, blkaddr, owner) {
    // 每个数据块需要分配 1-2 个 entry
    if (!is_mulref) {
        // 首次标记为 mulref：需要 2 个 entry
        curmulref_alloc_entry(sbi, &eidx1);  // entry1: 原始 owner
        blkaddr1 = cmr->blkaddr;

        curmulref_alloc_entry(sbi, &eidx2);  // entry2: 新 owner
        blkaddr2 = cmr->blkaddr;  // 可能 != blkaddr1

        // 处理同块或跨块
        if (blkaddr1 == blkaddr2) {
            // 一次 get_meta_page
        } else {
            // 两次 get_meta_page
        }
    } else {
        // 已经是 mulref：只需 1 个 entry
        curmulref_alloc_entry(sbi, &eidx1);
        blkaddr1 = cmr->blkaddr;
        // 一次 get_meta_page
    }
}
```

### 2. curmulref_alloc_entry 的行为

```c
int curmulref_alloc_entry(sbi, eidx) {
    down_write(&curmulref_lock);      // 锁1
    mutex_lock(&curmulref_mutex);     // 锁2

    page = f2fs_get_meta_page(sbi, cmr->blkaddr);  // 读当前块

retry_find:
    // 在当前块的 bitmap 中找空闲位
    for (idx = cmr->next_free_entry; idx < 336; idx++) {
        if (!f2fs_test_bit(idx, bitmap)) break;
    }

    if (idx >= 336) {  // 当前块满了
        set_page_dirty(page);
        f2fs_put_page(page, 1);

        cmr->blkaddr += 1;  // 切换到下一个块
        page = f2fs_get_meta_page(sbi, cmr->blkaddr);
        goto retry_find;
    }

    // 分配成功
    f2fs_set_bit(idx, bitmap);
    *eidx = idx;

    set_page_dirty(page);
    f2fs_put_page(page, 1);

    mutex_unlock(&curmulref_mutex);
    up_write(&curmulref_lock);
}
```

### 3. 关键观察

**每次 `curmulref_alloc_entry()` 都是独立的事务**：
- 获取锁
- 读 meta page
- 分配 entry（可能触发块切换）
- 写回 page
- 释放锁

**无法预测下一次分配在哪个块**：
- 取决于当前块的 bitmap 状态
- 取决于 `cmr->next_free_entry` 的位置
- 随着系统运行，碎片化严重

## 真正的瓶颈

### 对于 524 万个数据块

假设：
- 80% 是首次 mulref（需要 2 个 entry）
- 20% 已经是 mulref（需要 1 个 entry）

总 entry 分配次数：524万 × (0.8×2 + 0.2×1) = **943 万次**

每次 `curmulref_alloc_entry()` 的开销：
1. **锁操作**：`down_write` + `mutex_lock` + 释放
2. **Meta page I/O**：`f2fs_get_meta_page` + `f2fs_put_page`
3. **Bitmap 扫描**：最坏 O(336)

### 锁竞争分析

```
curmulref_alloc_entry() 内部：
  down_write(&curmulref_lock)
  mutex_lock(&curmulref_mutex)
  ...
  up_write(&curmulref_lock)
  mutex_unlock(&curmulref_mutex)

f2fs_alloc_mulref_entry() 外层：
  // 调用 curmulref_alloc_entry() 1-2 次
  down_write(&curmulref_lock)    // 重复获取！
  mutex_lock(&curmulref_mutex)   // 重复获取！
  ...
  up_write(&curmulref_lock)
  mutex_unlock(&curmulref_mutex)
```

**发现重复锁问题**：
- `curmulref_alloc_entry()` 内部已经加锁
- `f2fs_alloc_mulref_entry()` 在 1307 行又加了一次锁
- **这是死锁风险！** 或者说明我理解有误？

让我检查 1307 行的上下文：

```c
1271: ret = curmulref_alloc_entry(sbi, &eidx_tmp);  // 已释放锁
1280: ret = curmulref_alloc_entry(sbi, &eidx_tmp);  // 已释放锁

1307: down_write(&sm->curmulref_lock);  // 重新获取锁
1308: mutex_lock(&cmr->curmulref_mutex);
```

**原来如此**：
- `curmulref_alloc_entry()` 执行完后释放锁
- 然后 `f2fs_alloc_mulref_entry()` 重新获取锁来填充 entry 内容
- **这意味着在两次加锁之间，cmr->blkaddr 可能被其他线程修改！**

## 为什么我的 Batch 方案有问题

### 问题 1：无法预测 entry 位置

```c
// 我的方案假设
for (i = 0; i < 1024; i++) {
    alloc_entry_nolock(..., &cached_page, &cached_blkaddr);
    // 假设可以缓存 page
}
```

**现实**：
- 第 1 个块分配 entry 在 mulref_blk=100, idx=50
- 第 2 个块分配 entry 在 mulref_blk=100, idx=51
- ...
- 第 287 个块分配 entry 在 mulref_blk=100, idx=336（满了）
- 第 288 个块分配 entry 在 mulref_blk=101, idx=0（切换块）
- ...

**缓存失效频繁**，无法有效复用。

### 问题 2：锁的语义复杂

当前实现的锁模型：
```
Phase 1: 分配 entry（短暂持锁）
  curmulref_alloc_entry() {
    lock();
    分配 idx，更新 bitmap;
    unlock();
  }

Phase 2: 填充 entry 内容（短暂持锁）
  f2fs_alloc_mulref_entry() {
    lock();
    读 page，填充 mgentry;
    unlock();
  }
```

**两阶段之间释放锁的原因**：
- 避免长时间持锁
- 允许其他线程插入分配

**如果改为批量持锁**：
- 持锁时间过长（1024 个块）
- 阻塞其他线程
- 可能导致系统卡顿

## 真正的优化方向

### 方向 1：减少锁粒度（当前已经很细）

当前锁粒度已经很细了，难以进一步优化。

### 方向 2：优化 Meta Page 访问

**观察**：
- `curmulref_alloc_entry()` 每次都读写同一个 page（cmr->blkaddr）
- 只有在块满时才切换
- **大部分时间访问的是同一个 page**

**优化思路**：
- 在 `curmulref_info` 中缓存当前 page
- 避免每次 `f2fs_get_meta_page()`

### 方向 3：优化 Bitmap 扫描

当前每次从 `cmr->next_free_entry` 开始线性扫描，最坏 O(336)。

**优化思路**：
- 使用 `find_next_zero_bit()` 内核函数
- 或者维护空闲链表

### 方向 4：批量更新 SIT

`update_sit_mulref_entry()` 每次都要：
```c
down_write(&smi->smentry_lock);
f2fs_set_bit(...);
up_write(&smi->smentry_lock);
```

**优化思路**：
- SIT 更新可以延迟批量处理
- 先收集所有需要更新的 blkaddr
- 一次性持锁更新

## 可行的优化方案

### 方案 A：缓存 curmulref page（最有效）

```c
struct curmulref_info {
    ...
    struct page *cached_page;  // 新增：缓存当前块的 page
    block_t cached_blkaddr;    // 新增：缓存的块地址
};

int curmulref_alloc_entry_cached(sbi, eidx) {
    down_write(&curmulref_lock);
    mutex_lock(&curmulref_mutex);

    // 检查缓存
    if (!cmr->cached_page || cmr->cached_blkaddr != cmr->blkaddr) {
        // 写回旧 page
        if (cmr->cached_page) {
            set_page_dirty(cmr->cached_page);
            f2fs_put_page(cmr->cached_page, 1);
        }
        // 读取新 page
        cmr->cached_page = f2fs_get_meta_page(sbi, cmr->blkaddr);
        cmr->cached_blkaddr = cmr->blkaddr;
    }

    // 使用缓存的 page
    blk = page_address(cmr->cached_page);

    // ... 分配逻辑 ...

    // 不释放 page，保持缓存

    mutex_unlock(&curmulref_mutex);
    up_write(&curmulref_lock);
}
```

**效果**：
- 只有在块切换时才读取新 page
- 大部分时间复用缓存
- **预计减少 90% 的 meta page I/O**

### 方案 B：批量更新 SIT

```c
// 在 f2fs_set_mulref_blocks() 中
block_t sit_update_buf[1024];
unsigned int sit_count = 0;

// 收集阶段
for (i = 0; i < nr; i++) {
    ret = set_mulref_entry_no_sit(sbi, blk_buf[i], owner_buf[i]);
    sit_update_buf[sit_count++] = blk_buf[i];
}

// 批量更新 SIT
batch_update_sit_mulref(sbi, sit_update_buf, sit_count);
```

**效果**：
- 锁操作：524万 → 5117 次（减少 99.9%）

## 推荐实施方案

**优先级 1**：缓存 curmulref page（方案 A）
- 改动小，风险低
- 效果显著（减少 90% meta page I/O）

**优先级 2**：批量更新 SIT（方案 B）
- 改动中等
- 效果显著（减少 99.9% SIT 锁操作）

**不推荐**：批量处理 entry 分配
- 无法预测 entry 位置
- 持锁时间过长
- 破坏现有锁模型

## 预期效果

实施方案 A + B：
- Meta page I/O：减少 90%
- SIT 锁操作：减少 99.9%
- **预计总耗时**：1.9s → 200-300ms（提升 6-9 倍）
