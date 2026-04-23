# Snapfs 调试记录

本文档记录 snapfs 开发过程中遇到的问题、根因分析及解决方案。

---

## 2026/04/22 - MySQL TPCC 测试期间 NULL Pointer Dereference 崩溃

### 问题描述

运行 MySQL TPCC 测试时，dmesg 输出内核 oops：

```
BUG: kernel NULL pointer dereference, address: 0000000000000028
#PF: supervisor read access in kernel mode
#PF: error_code(0x0000) - not-present page

RIP: 0010:__dquot_initialize+0x16/0x4d0
```

崩溃发生在线程 `ib_pg_flush_co`（PID 88567）上。

### 调用链

```
f2fs_file_write_iter          ← MySQL 写操作
  → f2fs_snapshot_cow         ← 触发写时复制
    → __f2fs_snapshot_cow_from_path
      → snapfs_replay_one_snapshot
        → f2fs_cow
          → f2fs_dquot_initialize(snap_inode)
            → dquot_initialize (内核 quota 子系统)
              → __dquot_initialize
                → f2fs_get_projid()  ← 崩溃点
                  → 访问 F2FS_I(inode)->i_projid
```

### 根因分析

`f2fs_cow_update_inode()` 函数在复制 inode 元数据时，**遗漏了 `i_projid` 字段**。

当内核 quota 子系统 (`__dquot_initialize`) 处理 `PRJQUOTA`（项目配额）类型时，会调用 `sb->dq_op->get_projid()` 来获取 inode 的项目 ID：

```c
case PRJQUOTA:
    rc = inode->i_sb->dq_op->get_projid(inode, &projid);
    if (rc)
        continue;
    qid = make_kqid_projid(projid);
    break;
```

`f2fs_get_projid()` 的实现：
```c
static int f2fs_get_projid(struct inode *inode, kprojid_t *projid)
{
    *projid = F2FS_I(inode)->i_projid;
    return 0;
}
```

如果 `F2FS_I(snap_inode)->i_projid` 没有被正确初始化（或保留垃圾值），可能导致后续 quota 操作异常。

### 相关代码

**问题位置**: `snapshot.c:3550-3571` - `f2fs_cow_update_inode()`

```c
void f2fs_cow_update_inode(struct inode *src_inode, struct inode *snap_inode){
    snap_inode->i_mode = src_inode->i_mode;
    snap_inode->i_opflags = src_inode->i_opflags;
    snap_inode->i_uid = src_inode->i_uid;
    snap_inode->i_gid = src_inode->i_gid;
    snap_inode->i_flags = src_inode->i_flags;
    if (S_ISCHR(src_inode->i_mode) || S_ISBLK(src_inode->i_mode)) {
        snap_inode->i_rdev = src_inode->i_rdev;
    }
    snap_inode->i_atime = src_inode->i_atime;
    snap_inode->i_mtime = src_inode->i_mtime;
    snap_inode->i_ctime = src_inode->i_ctime;
    snap_inode->i_blkbits = src_inode->i_blkbits;
    snap_inode->i_write_hint = src_inode->i_write_hint;
    snap_inode->i_bytes = src_inode->i_bytes;
    snap_inode->i_version = src_inode->i_version;
    snap_inode->i_sequence = src_inode->i_sequence;
    snap_inode->i_generation = src_inode->i_generation;
    snap_inode->dirtied_when = src_inode->dirtied_when;
    snap_inode->dirtied_time_when = src_inode->dirtied_time_when;
    snap_inode->i_count = src_inode->i_count;
    // ❌ 缺少: F2FS_I(snap_inode)->i_projid = F2FS_I(src_inode)->i_projid;
}
```

### 修复方案

在 `f2fs_cow_update_inode()` 中添加 `i_projid` 的复制：

```c
void f2fs_cow_update_inode(struct inode *src_inode, struct inode *snap_inode){
    // ... 现有代码保持不变 ...

    snap_inode->i_count = src_inode->i_count;

    // 添加: 复制 i_projid (项目配额需要)
    F2FS_I(snap_inode)->i_projid = F2FS_I(src_inode)->i_projid;
}
```

### 后续排查 - inode 字段残缺清单

经全面核查，发现 COW 过程中以下 inode 字段可能未正确复制/初始化：

#### 1. f2fs_cow_update_inode() 遗漏的字段

| 字段 | 结构体 | 影响 | 状态 |
|------|--------|------|------|
| `i_projid` | f2fs_inode_info | PRJQUOTA 崩溃 | ⚠️ **待修复** |
| `i_pino` | f2fs_inode_info | 父子目录关系 | 暂未发现问题 |
| `i_advise` | f2fs_inode_info | 文件提示属性 | 暂未发现问题 |
| `i_dir_level` | f2fs_inode_info | 大目录优化 | 暂未发现问题 |

#### 2. update_f2fs_inode() 遗漏的字段

`update_f2fs_inode()` 负责复制磁盘格式的 f2fs_inode 结构体字段：

| 字段 | 影响 | 状态 |
|------|------|------|
| `i_pino` | 父子目录关系，rename/link 需要 | ⚠️ 待观察 |
| `i_projid` | PRJQUOTA | ⚠️ 待观察 |
| `i_extra_isize` | 扩展属性大小 | 暂未发现问题 |
| `i_inline_xattr_size` | 内联 xattr 大小 | 暂未发现问题 |
| `i_crtime` | inode 创建时间 | 暂未发现问题 |
| `i_inode_checksum` | inode 校验和 | 暂未发现问题 |
| `i_compr_blocks` | 压缩块数 | 暂未发现问题 |
| `i_compress_algorithm` | 压缩算法 | 暂未发现问题 |
| `i_log_cluster_size` | 簇大小对数 | 暂未发现问题 |
| `i_compress_flag` | 压缩标志 | 暂未发现问题 |

### 后续计划

1. **优先级高**: 修复 `i_projid` 复制问题（解决当前崩溃）
2. **优先级中**: 补充 `i_pino` 复制（确保 rename/link 正确性）
3. **优先级低**: 根据实际使用情况，补充其他遗漏字段

## 2026/04/22 - 第二次分析：i_projid 修复后崩溃仍然存在

### 问题描述

上次修复 `i_projid` 后（snapshot.c:3573），崩溃仍然发生。

### 调用链分析

```
f2fs_cow+0xa0 (调用 f2fs_dquot_initialize)
  → f2fs_dquot_initialize(snap_inode)
    → dquot_initialize(inode)
      → f2fs_setup_filename (通过内核 quota 子系统间接调用)
        → f2fs_find_entry
          → __dquot_initialize+0x16 (crash: RDI=0x0, 访问 inode+0x28)
```

### 崩溃分析

- **RIP**: `__dquot_initialize+0x16`
- **CR2**: `0x28` (访问 `inode->i_sb`)
- **RDI**: `0x0` (NULL inode)

崩溃发生在 `__dquot_initialize` 内部，尝试访问 `inode->i_sb` 时，`inode` 参数为 NULL。

### 根因分析

根据代码分析，`f2fs_cow` 中通过 `snapfs_new_inode` 创建新 inode 时：

1. `snapfs_new_inode` 使用默认值 `F2FS_DEF_PROJID` (通常是 0) 初始化 `i_projid`
2. 但 **COW 的 inode 应该继承源文件的 `i_projid`**，而不是使用默认值
3. 虽然 `f2fs_cow_update_inode` 已经添加了 `i_projid` 复制，但在创建新 inode 时还没有调用它

### 修复方案

在 `f2fs_cow` 中，创建新 inode 后立即从 `son_inode` 复制 `i_projid`：

```c
tmp_inode = snapfs_new_inode(snap_inode, mode);
if (IS_ERR(tmp_inode)) {
    ret = PTR_ERR(tmp_inode);
    goto next_free;
}

// 修复: 从 son_inode 复制 i_projid（项目配额）
F2FS_I(tmp_inode)->i_projid = F2FS_I(son_inode)->i_projid;
```

### 代码位置

**修复位置**: `snapshot.c:8234-8238`

### 调试措施

已在 snapshot.c:8141-8166 添加调试日志：
- 在 `f2fs_dquot_initialize` 调用前后打印 snap_inode 的 i_ino 和 i_projid
- 检查 snap_inode 和 F2FS_I(snap_inode) 是否为 NULL

### 待确认

1. 调试日志是否能帮助定位问题
2. snap_inode 在传入时是否为 NULL 或无效
3. 是否存在寄存器损坏的情况

---

## 2026/04/22 - i_projid 修复方案（已实施）

### 问题描述

运行 MySQL TPCC 测试时，dmesg 输出内核 oops：

```
BUG: kernel NULL pointer dereference, address: 0000000000000028
RIP: 0010:__dquot_initialize+0x16/0x4d0
```

### 根因分析

`f2fs_cow_update_inode()` 函数在复制 inode 元数据时，**遗漏了 `i_projid` 字段**。

### 修复方案

在 `f2fs_cow_update_inode()` 中添加 `i_projid` 的复制：

```c
void f2fs_cow_update_inode(struct inode *src_inode, struct inode *snap_inode){
    // ... 现有代码保持不变 ...
    snap_inode->i_count = src_inode->i_count;

    // 添加: 复制 i_projid (项目配额需要)
    F2FS_I(snap_inode)->i_projid = F2FS_I(src_inode)->i_projid;
}
```

### 后续排查 - inode 字段残缺清单

经全面核查，发现 COW 过程中以下 inode 字段可能未正确复制/初始化：

#### 1. f2fs_cow_update_inode() 遗漏的字段

| 字段 | 结构体 | 影响 | 状态 |
|------|--------|------|------|
| `i_projid` | f2fs_inode_info | PRJQUOTA 崩溃 | ✅ **已修复** |
| `i_pino` | f2fs_inode_info | 父子目录关系 | 暂未发现问题 |
| `i_advise` | f2fs_inode_info | 文件提示属性 | 暂未发现问题 |
| `i_dir_level` | f2fs_inode_info | 大目录优化 | 暂未发现问题 |

#### 2. update_f2fs_inode() 遗漏的字段

`update_f2fs_inode()` 负责复制磁盘格式的 f2fs_inode 结构体字段：

| 字段 | 影响 | 状态 |
|------|------|------|
| `i_pino` | 父子目录关系，rename/link 需要 | ⚠️ 待观察 |
| `i_projid` | PRJQUOTA | ✅ **已修复** |
| `i_extra_isize` | 扩展属性大小 | 暂未发现问题 |
| `i_inline_xattr_size` | 内联 xattr 大小 | 暂未发现问题 |
| `i_crtime` | inode 创建时间 | 暂未发现问题 |
| `i_inode_checksum` | inode 校验和 | 暂未发现问题 |
| `i_compr_blocks` | 压缩块数 | 暂未发现问题 |
| `i_compress_algorithm` | 压缩算法 | 暂未发现问题 |
| `i_log_cluster_size` | 簇大小对数 | 暂未发现问题 |
| `i_compress_flag` | 压缩标志 | 暂未发现问题 |

### 后续计划

1. **优先级高**: 确认 `i_projid` 修复是否完全解决问题
2. **优先级中**: 补充 `i_pino` 复制（确保 rename/link 正确性）
3. **优先级低**: 根据实际使用情况，补充其他遗漏字段

---

## 2026/04/23 - MySQL TPCC 测试期间 NULL Pointer Dereference（续）

### 问题描述

在 MySQL TPCC 测试期间，f2fs_cow 函数崩溃，崩溃地址为 `f2fs_cow+0x98`：
```
BUG: kernel NULL pointer dereference, address: 000000000000040c
RIP: 0010:f2fs_cow+0x98/0x1170 [snapfs]
```

调用链：
```
f2fs_file_write_iter → f2fs_snapshot_cow → f2fs_cow → 崩溃
```

### 调用时序分析

从 dmesg 日志观察到的时序：
1. `f2fs_cow(snap_inode=789)` → inline dir → 返回成功
2. `f2fs_cow(snap_inode=790)` → 成功 (31855ns)
3. `f2fs_cow(snap_inode=789)` → 成功 (6667ns)
4. `f2fs_cow(snap_inode=789)` → **崩溃**

**关键发现**：snap_inode=789 在被使用两次后崩溃。第一次成功，第三次也成功，但第四次崩溃。这说明在第二次和第三次调用之间，snap_inode=789 的状态发生了变化。

### 崩溃现场分析

- **RIP**: `f2fs_cow+0x98`
- **CR2**: `0x40c`（inode 结构偏移）
- **RBX = 0x0**（NULL，表示 snap_inode 参数为 NULL）

崩溃时的调试日志显示 snap_inode=789 是有效的：
```
[snapfs cow] snap_inode[789] i_projid=0, i_sb=00000000c994cf25
```

但崩溃时 snap_inode 变成 NULL，说明在函数执行过程中指针被破坏。

### 根因分析 - Inline Dentry 分支错误使用 snap_inode

在 `f2fs_cow` 函数中，处理 inline dentry 子目录的代码存在 bug：

**错误代码**（修复前）：
```c
// snapshot.c:8319-8334
if (f2fs_has_inline_dentry(son_inode)){
    set_inode_flag(tmp_inode, FI_INLINE_DENTRY);
    son_ipage = f2fs_get_node_page(sbi, son_inode->i_ino);  // ✓ 源 inode
    new_ipage = f2fs_get_node_page(sbi, snap_inode->i_ino); // ✗ 错误：应用 tmp_inode
    inline_dentry = inline_data_addr(son_inode, son_ipage);
    inline_dentry2 = inline_data_addr(tmp_inode, new_ipage);  // 使用 tmp_inode 计算偏移
    memcpy(inline_dentry2, inline_dentry, MAX_INLINE_DATA(son_inode));
    make_dentry_ptr_inline(snap_inode, &d, inline_dentry2);  // ✗ 错误：应用 tmp_inode
    f2fs_update_dentry(snap_inode->i_ino, snap_inode->i_mode, &d, &dot, 0, 0);  // ✗ 错误
    f2fs_update_dentry(snap_inode->i_ino, snap_inode->i_mode, &d, &dotdot, 0, 1);  // ✗ 错误
}
```

**对比非 inline 分支**（snapshot.c:8347-8388，正确的代码）：
```c
new_ipage = f2fs_get_node_page(sbi, tmp_inode->i_ino);  // ✓ 正确
// ...
f2fs_update_dentry(tmp_inode->i_ino, tmp_inode->i_mode, &d, &dot, 0, 0);  // ✓ 正确
f2fs_update_dentry(tmp_inode->i_ino, tmp_inode->i_mode, &d, &dotdot, 0, 1);  // ✓ 正确
```

### Bug 影响机制

1. **错误的 page 访问**：`f2fs_get_node_page(sbi, snap_inode->i_ino)` 获取的是 snap_inode 的 inode page，但这个 page 是用于 snap_inode 的，不是用于 tmp_inode 的

2. **错误的 dentry 操作**：在 inline dentry 数据上执行 `f2fs_update_dentry` 时使用 snap_inode 而非 tmp_inode，可能导致 dentry 结构被错误地修改

3. **内存污染**：当 inline dentry 分支执行时，会错误地操作 snap_inode 的 inode page 和 dentry 结构，这可能导致 snap_inode 的内存被污染

4. **间接导致崩溃**：内存污染可能导致 snap_inode 结构中的某个字段（在偏移 0x40c 处）被破坏，当后续调用 f2fs_cow 时访问该字段就会触发 NULL pointer dereference

### 修复方案

将 inline dentry 分支中错误使用 `snap_inode` 的地方改为 `tmp_inode`：

```c
// 修复后的代码
if (f2fs_has_inline_dentry(son_inode)){
    set_inode_flag(tmp_inode, FI_INLINE_DENTRY);
    son_ipage = f2fs_get_node_page(sbi, son_inode->i_ino);  // ✓ 保持不变
    new_ipage = f2fs_get_node_page(sbi, tmp_inode->i_ino); // ✓ 修复：使用 tmp_inode
    inline_dentry = inline_data_addr(son_inode, son_ipage);
    inline_dentry2 = inline_data_addr(tmp_inode, new_ipage);
    memcpy(inline_dentry2, inline_dentry, MAX_INLINE_DATA(son_inode));
    make_dentry_ptr_inline(tmp_inode, &d, inline_dentry2);  // ✓ 修复：使用 tmp_inode
    f2fs_update_dentry(tmp_inode->i_ino, tmp_inode->i_mode, &d, &dot, 0, 0);  // ✓ 修复
    f2fs_update_dentry(tmp_inode->i_ino, tmp_inode->i_mode, &d, &dotdot, 0, 1);  // ✓ 修复
}
```

### 修改位置

1. **snapshot.c:8319**：`snap_inode->i_ino` → `tmp_inode->i_ino`
2. **snapshot.c:8330**：`snap_inode` → `tmp_inode`
3. **snapshot.c:8332-8334**：使用 `tmp_inode->i_ino` 和 `tmp_inode->i_mode`

### 附加修复

错误处理中也添加了资源释放：
```c
new_ipage = f2fs_get_node_page(sbi, tmp_inode->i_ino);
if (IS_ERR(new_ipage)) {
    pr_err("[snapfs cow2]: get new page[%lu] failed\n", tmp_inode->i_ino);
    f2fs_put_page(son_ipage, 1);  // ✓ 修复：释放已获取的 son_ipage
    goto next_free;
}
```

### 待验证

1. 重新编译模块后运行 MySQL TPCC 测试
2. 观察是否仍有 NULL pointer dereference 崩溃
3. 如仍崩溃，需要添加更多调试日志来追踪 snap_inode 何时变成 NULL

---

## 2026/04/23 - page_mkclean BUG 分析（第二轮）

### 问题描述

在 MySQL TPCC 测试期间，触发 kernel BUG：

```
kernel BUG at mm/rmap.c:997!
invalid opcode: 0000 [#1] SMP NOPTI
RIP: 0010:page_mkclean+0xae/0xc0
```

崩溃位置：`page_mkclean` 函数中的 `BUG_ON(!PageLocked(page))`。

调用链：
```
f2fs_file_write_iter → f2fs_snapshot_cow → f2fs_cow
  → __f2fs_set_mulref_blocks
    → __f2fs_cow_direct_node_batch
      → f2fs_cow_node_block_batch
        → snapfs_batch_apply_one (多次调用)
        → snapfs_batch_flush_all
          → snapfs_flush_locked_meta_page
            → f2fs_sync_meta_page
              → clear_page_dirty_for_io
                → page_mkclean (BUG!)
```

### 根因分析

**问题代码**（snapshot.c:2056-2070，原 `out:` 标签处）：

```c
out:
    /* 释放 pages 的 lock */
    if (ctx->dirty_mr_page && PageLocked(ctx->dirty_mr_page))
        unlock_page(ctx->dirty_mr_page);
    for (i = 0; i < ctx->dirty_sum_count; i++) {
        if (ctx->dirty_sum_pages[i] && PageLocked(ctx->dirty_sum_pages[i]))
            unlock_page(ctx->dirty_sum_pages[i]);
    }
    for (i = 0; i < ctx->dirty_sit_count; i++) {
        if (ctx->dirty_sit_pages[i] && PageLocked(ctx->dirty_sit_pages[i]))
            unlock_page(ctx->dirty_sit_pages[i]);
    }

    if (ret)
        return ret;

    /* 3. 执行 summary 和 SIT 的修改（对 unlocked pages） */
    ...
```

**问题链路**：

1. `snapfs_batch_apply_one` 在 `out:` 标签处**提前解锁**了所有收集的 dirty pages
2. 之后仍继续修改这些 pages（section 3），此时 pages 处于 unlocked 状态
3. `snapfs_batch_flush_all` 尝试 flush 这些 unlocked pages
4. `f2fs_sync_meta_page` → `clear_page_dirty_for_io` → `page_mkclean`
5. `page_mkclean` 函数检查 `BUG_ON(!PageLocked(page))` → **触发 BUG**

**内层函数调用链**：

```
snapfs_batch_flush_all
  → snapfs_flush_locked_meta_page
    → f2fs_sync_meta_page
      → f2fs_wait_on_page_writeback
      → clear_page_dirty_for_io   // 内核函数
        → page_mkclean            // 要求 page 必须 locked！
          → BUG_ON(!PageLocked(page))  // 触发点
```

### 修复方案

**设计原则**：保持 pages 锁定状态，不在 `snapfs_batch_apply_one` 中提前解锁。统一 flush 由 `snapfs_batch_flush_all` 处理。

**修改内容**：

1. **删除 `out:` 标签处的 unlock 代码**

2. **修改错误路径**：避免 `goto out` 导致 pages 泄漏，改为直接返回并 put pages

```c
// 修复后的错误路径示例
if (IS_ERR(sum_page)) {
    ret = PTR_ERR(sum_page);
    /* 错误路径：直接 put mr_page，避免泄漏 */
    if (ctx->dirty_mr_page) {
        f2fs_put_page(ctx->dirty_mr_page, 1);
        ctx->dirty_mr_page = NULL;
    }
    return ret;  // 不再 goto out
}
```

3. **添加注释说明设计意图**：

```c
/*
 * 保持 pages 锁定状态，不在此处解锁
 * 理由：
 * 1. pages 被保存到 ctx 中，期望后续由 snapfs_batch_flush_all flush
 * 2. page_mkclean 要求 page 必须处于 locked 状态
 * 3. 如果在 apply_one 中提前解锁，flush_all 需要重新锁定，效率略低但正确
 *
 * 统一 flush 在 snapfs_batch_flush_all() 中进行
 */
```

### 修改位置

| 文件 | 行号 | 修改内容 |
|------|------|----------|
| snapshot.c | 2019-2034 | sum_page 获取错误路径：直接 return，不 goto out |
| snapshot.c | 2036-2054 | sit_page 获取错误路径：直接 return，不 goto out |
| snapshot.c | 2056-2070 | 删除 `out:` 标签及 unlock 代码 |
| snapshot.c | 2072 | 添加注释说明 |

### 与之前"死锁"问题的区分

文档 redo_batch_design.md C.2.3 节描述的"死锁"问题是指：
- `f2fs_get_sum_page` 内部触发同步 I/O 等待导致系统 hang
- **解决方案**：改用 `f2fs_get_meta_page`

本次问题（page_mkclean BUG）是**不同的问题**：
- Page 未锁定导致 kernel panic
- **解决方案**：不在 `out:` 提前解锁 pages

两者都与 page 锁定机制无关，而是与 page 获取函数的选择有关。

### 待验证

1. 重新编译模块
2. 运行 MySQL TPCC 测试
3. 观察是否仍有 page_mkclean BUG

---

## 2026/04/23 - Batch Flush 死锁分析（第三轮）

### 问题描述

MySQL TPCC 测试期间，系统出现假死状态：
- `ib_log_writer` 线程阻塞超过 122 秒
- `f2fs_get_meta_page` 调用处被阻塞
- 磁盘 IO 始终为 0
- GC 线程反复启动但无进展

### dmesg 关键信息

```
ib_log_writer:3202 blocked for more than 122 seconds.
  Call Trace:
  <TASK>
  __schedule+0x356/0x17b0
  ...
  __get_meta_page+0x90/0x1a0 [snapfs]
  f2fs_get_meta_page+0x13/0x20 [snapfs]
  snapfs_batch_apply_one+0x6d9/0xa30 [snapfs]
  f2fs_cow_node_block_batch+0x625/0xc40 [snapfs]
  __f2fs_set_mulref_blocks+0x1e0c/0x20e0 [snapfs]
  f2fs_cow+0x67f/0x11b0 [snapfs]
  f2fs_file_write_iter+0x225/0x430 [snapfs]
  ...
```

### 根因分析

**调用链**：
```
ib_log_writer write()
  → f2fs_file_write_iter
    → f2fs_snapshot_cow
      → f2fs_cow
        → __f2fs_set_mulref_blocks
          → f2fs_cow_node_block_batch (batch mode)
            → snapfs_batch_apply_one
              → f2fs_get_meta_page   ← 阻塞点
                → __get_meta_page
                  → wait_on_page_bit_common
```

**死锁根因**：

上次修复 `page_mkclean BUG` 时，采用了以下策略：
1. 删除 `out:` 标签处的 unlock 代码
2. 让 dirty pages 在 `snapfs_batch_apply_one` 中保持 locked 状态
3. 在 `snapfs_batch_flush_all` 中统一 flush

这个修复解决了 `page_mkclean BUG`，但引入了新的问题：

**`f2fs_sync_meta_page` 函数的等待链**：
```c
f2fs_wait_on_page_writeback(page, META, true, true);  // 第一次等待
// ... 提交 writeback ...
f2fs_do_write_meta_page(sbi, page, io_type);
unlock_page(page);
f2fs_submit_merged_write(sbi, META);
f2fs_wait_on_page_writeback(page, META, true, true);  // 第二次等待 ← 阻塞点
```

**问题**：
1. `snapfs_batch_flush_all` 调用 `f2fs_sync_meta_page` 等待 page writeback 完成
2. 如果 I/O 队列被大量请求积压（MySQL redo log + snapfs batch），writeback 无法及时完成
3. `f2fs_wait_on_page_writeback` 无限期等待，导致线程阻塞 122 秒
4. 与其他线程形成资源竞争，表现为类似死锁的假死状态

**等待环**：
```
线程 A (snapfs_batch)
  → f2fs_sync_meta_page
    → f2fs_wait_on_page_writeback 等待 I/O
      → I/O 队列积压，无法完成

线程 B (MySQL ib_log_writer)
  → 也在提交 I/O，加剧积压
  → 如果等待 snapfs 释放的资源，形成等待环
```

### 解决方案

**核心思路**：不等待 I/O 完成，只提交 writeback 后立即返回

**修改内容**：重写 `snapfs_flush_locked_meta_page` 函数

```c
/*
 * snapfs_flush_locked_meta_page - 提交 meta page 的 writeback（不等待 I/O 完成）
 *
 * 与 f2fs_sync_meta_page 的区别：
 * - 不调用 f2fs_wait_on_page_writeback 等待 I/O 完成
 * - 只提交 writeback I/O，然后立即 unlock page
 * - 调用者需要在适当时机释放 page 引用
 *
 * 设计理由：
 * 在 batch redo 流程中，batch slot 的 APPLIED 标记会在所有 dirty pages
 * 被提交后写入。由于 checkpoint 会定期刷写所有 dirty meta pages，
 * 即使 snapfs 不等待 I/O 完成，内核也会 eventually 将这些 pages 刷写到磁盘。
 *
 * 这种方式避免了 f2fs_sync_meta_page 中的长时间阻塞（可能超过 120 秒），
 * 从而避免了类似死锁的假死状态。
 */
static int snapfs_flush_locked_meta_page(struct f2fs_sb_info *sbi,
					 struct page *page)
{
	// ... 构建 fio 结构 ...
	if (!page)
		return 0;
	if (!PageLocked(page))
		return -EINVAL;
	if (PageWriteback(page)) {
		unlock_page(page);
		return 0;
	}
	if (!PageDirty(page)) {
		unlock_page(page);
		return 0;
	}
	clear_page_dirty_for_io(page);
	set_page_writeback(page);
	f2fs_submit_page_write(&fio);
	unlock_page(page);
	return 0;
}
```

### 修改位置

| 文件 | 行号 | 修改内容 |
|------|------|----------|
| snapshot.c | 397-472 | 重写 `snapfs_flush_locked_meta_page` 函数，移除 I/O 等待 |
| snapshot.c | 1217-1220 | 更新注释说明 |
| snapshot.c | 1264-1273 | 更新注释说明 |
| snapshot.c | 1438-1448 | 更新注释说明 |
| snapshot.c | 1705-1707 | 更新注释说明 |
| snapshot.c | 2222-2225 | 更新注释说明 |
| snapshot.c | 2253-2256 | 更新注释说明 |
| snapshot.c | 2288-2291 | 更新注释说明 |

### 设计考量

1. **Durability 保证**：
   - batch slot 的 APPLIED 标记会在 dirty pages 提交后写入
   - checkpoint 会定期刷写所有 dirty meta pages
   - 即使 snapfs 不等待 I/O，kernel eventual 会刷写到磁盘

2. **Page 生命周期**：
   - `snapfs_flush_locked_meta_page` 只 unlock，不释放引用
   - 调用者负责调用 `f2fs_put_page` 释放引用

3. **与其他代码路径的兼容性**：
   - 非 batch 模式的代码路径（如 `f2fs_alloc_mulref_entry`）也使用此函数
   - 这些路径可能需要同步等待 I/O，但那是后续优化点

### 待验证

1. 重新编译模块
2. 运行 MySQL TPCC 测试
3. 观察：
   - 是否仍有长时间阻塞（>120 秒）
   - 数据一致性是否保持
   - checkpoint 是否正常刷写 dirty pages

---

## 2026/04/23 - Batch Flush 死锁问题（第四轮）

### 问题描述

MySQL TPCC 测试期间，系统出现死锁：
- `ib_log_writer` 线程阻塞超过 245 秒
- `f2fs_mulref-259` 线程（compact thread）也阻塞超过 245 秒
- 磁盘 IO 为 0，GC 线程反复启动但无进展
- `snapfs_batch_apply_one` 调用 `f2fs_get_meta_page` 处被阻塞

### dmesg 关键信息

```
INFO: task ib_log_writer:3157 blocked for more than 245 seconds.
  Call Trace:
  __get_meta_page+0x90/0x1a0 [snapfs]
  f2fs_get_meta_page+0x13/0x20 [snapfs]
  snapfs_batch_apply_one+0x6d9/0xa30 [snapfs]
  f2fs_cow_node_block_batch+0x625/0xc40 [snapfs]
  __f2fs_set_mulref_blocks+0x1e0c/0x20e0 [snapfs]
  f2fs_cow+0x67f/0x11b0 [snapfs]
  snapfs_replay_one_snapshot+0x117/0x1e0 [snapfs]

INFO: task f2fs_mulref-259:3094 blocked for more than 245 seconds.
  Call Trace:
  __get_meta_page+0x90/0x1a0 [snapfs]
  f2fs_get_meta_page+0x13/0x20 [snapfs]
  mulref_collect_stats+0x5f/0x130 [snapfs]
  mulref_compact_thread_func+0x10c/0x2b0 [snapfs]
```

### 根因分析

**问题起源**：第三轮修改（2026/04/23 Batch Flush 死锁分析）中，为了解决 `page_mkclean BUG`，修改了 `snapfs_flush_locked_meta_page` 函数，移除了 I/O 等待：

```c
// 第三轮修改后的代码（snapshot.c:462-469）
set_page_writeback(page);
ClearPageError(page);
f2fs_submit_page_write(&fio);    // 提交 I/O
stat_inc_meta_count(sbi, page->index);
f2fs_update_iostat(sbi, FS_META_IO, F2FS_BLKSIZE);

/* 解锁 page（I/O 在后台进行，不等待完成） */
unlock_page(page);               // ← 问题：未等待 I/O 完成就 unlock

return 0;
```

**死锁机制**：

```
Thread A (batch flush):                          Thread B (后续读操作):
─────────────────────────────────────────────    ───────────────────────────────────
1. f2fs_submit_page_write(&fio)                  1. f2fs_grab_cache_page()
   → 提交 I/O，page 进入 writeback                   → 获得 page
2. unlock_page(page)                               
   → page 仍处于 Writeback 状态                  2. PageUptodate(page) == false
3. f2fs_put_page(page, 0)                       3. f2fs_submit_page_bio() 读取同一 page
                                                  → 可能与 Thread A 的 writeback 冲突
                                                  → 等待 I/O 完成（无限期阻塞）
```

**核心问题**：
1. batch flush 提交 writeback 后立即 unlock，未等待 I/O 完成
2. 后续线程尝试读取同一 page，此时 page 仍处于 Writeback 状态
3. `__get_meta_page` 调用 `lock_page(page)` 时被阻塞（page 已被另一个 writeback 操作锁定）
4. 形成循环等待：batch flush 的 page 等待 I/O，后续操作的 page 等待 flush 完成

### 修复方案

恢复 `f2fs_wait_on_page_writeback()` 等待 I/O 完成后再 unlock page：

**修改位置**：`snapshot.c:491-493`

```c
set_page_writeback(page);
ClearPageError(page);
f2fs_submit_page_write(&fio);
stat_inc_meta_count(sbi, page->index);
f2fs_update_iostat(sbi, FS_META_IO, F2FS_BLKSIZE);

/* 等待 I/O 完成后再 unlock（避免死锁） */
f2fs_wait_on_page_writeback(page, META, true, true);
unlock_page(page);
return 0;
```

### 设计决策权衡

| 方案 | 优点 | 缺点 |
|------|------|------|
| **等待 I/O 完成** | 避免死锁，保证数据一致性 | 可能长时间阻塞（>120秒） |
| **不等待 I/O** | 响应快，避免长时间阻塞 | 引入死锁风险 |

**选择等待 I/O 完成**，理由：
1. meta pages 的持久化对 snapfs 正确性至关重要
2. 长时间阻塞的根本原因是 I/O 队列积压（MySQL redo log + snapfs batch 并发）
3. 应优化 I/O 调度而非跳过等待

### 后续优化建议

1. **I/O 调度优化**：评估是否需要限制 snapfs batch 的 I/O 优先级，避免与 MySQL redo log 竞争
2. **batch 大小限制**：当前 batch 可覆盖 1018 个数据块，考虑分批处理减少单次 I/O 量
3. **监控与告警**：添加 I/O 超时监控，及时发现 I/O 系统问题

---

## 2026/04/23 - Batch Flush 死锁问题（第五轮）- 两阶段 Flush 优化

### 问题描述

第四轮修复后（恢复 `f2fs_wait_on_page_writeback`），系统仍然出现长时间阻塞：
- `ib_log_writer` 线程阻塞超过 122 秒
- `f2fs_mulref-259` 线程阻塞超过 122 秒
- `f2fs_ckpt-259` 线程阻塞在 `f2fs_flush_inline_data`
- `kworker/u40:5` 和 `kworker/u40:13` 也被阻塞

### 根因分析

问题在于 `snapfs_batch_flush_all` 对每个 dirty page **逐个提交 writeback 并等待 I/O 完成**：

```c
// 原有实现（伪代码）
for each dirty_page in ctx:
    snapfs_flush_locked_meta_page(sbi, page)  // 提交 writeback + 等待 I/O
    f2fs_put_page(page, 0)
```

这种方式的问题是：
1. 每个 page 的 writeback 提交后立即等待 I/O 完成
2. I/O 调度器无法合并相邻的写请求
3. 磁盘需要反复寻道，效率低下
4. 大量 meta pages 分布在不同磁盘位置时，阻塞时间显著增加

### 解决方案

实现**两阶段 flush** 优化：

1. **第一阶段**：批量提交所有 writeback
   - 先对所有 dirty pages 调用 `snapfs_submit_meta_page_write`
   - 让 I/O 调度器收集所有写请求，合并相邻的请求
   - 减少磁盘寻道次数

2. **第二阶段**：统一等待所有 I/O 完成
   - 对所有 dirty pages 调用 `snapfs_wait_meta_page_writeback`
   - 此时所有 I/O 已提交，调度器可以最优地安排执行顺序

### 新增函数

| 函数名 | 功能 |
|--------|------|
| `snapfs_submit_meta_page_write` | 提交 writeback，不等待 I/O 完成 |
| `snapfs_wait_meta_page_writeback` | 等待 writeback I/O 完成 |

### 修改位置

| 文件 | 行号 | 修改内容 |
|------|------|----------|
| snapshot.c | 391-479 | 添加 `snapfs_submit_meta_page_write` 和 `snapfs_wait_meta_page_writeback` |
| snapshot.c | 465-480 | 简化 `snapfs_flush_locked_meta_page`，调用上述两个函数 |
| snapshot.c | 2286-2448 | 重写 `snapfs_batch_flush_all`，实现两阶段 flush |

### 设计优势

1. **I/O 合并**：I/O 调度器可以合并相邻的写请求，减少磁盘寻道
2. **并行执行**：所有 writeback 同时提交，硬件可以并行处理
3. **向后兼容**：`snapfs_flush_locked_meta_page` 保持单阶段 flush 功能

### 待验证

1. 重新编译模块后运行 MySQL TPCC 测试
2. 观察是否仍有长时间阻塞（>120 秒）
3. 评估 I/O 吞吐量和延迟是否有改善

---

## 2026/04/23 - MySQL TPCC 测试 meta page 阻塞分析

### 问题描述

MySQL TPCC 测试期间，系统出现长时间阻塞：
- `ib_log_writer` 线程阻塞超过 122 秒
- `f2fs_mulref-259` 线程（compact thread）阻塞超过 122 秒
- `f2fs_ckpt-259` 线程阻塞在 `f2fs_flush_inline_data`
- `kworker/u40:*` 线程阻塞在 `__get_node_page`
- **监控观察：看不到有磁盘 IO 下发**

### dmesg 关键信息

```
[  369.899014] INFO: task kworker/u40:3:231 blocked for more than 122 seconds.
  Call Trace:
  f2fs_issue_checkpoint+0xf2/0x1d0 [snapfs]
  f2fs_sync_fs+0x47/0xb0 [snapfs]

[  369.899503] INFO: task kworker/u40:11:733 blocked for more than 122 seconds.
  Call Trace:
  __get_node_page.part.0+0x3e/0x1e0 [snapfs]
  f2fs_update_inode_page+0x2c/0x80 [snapfs]
  f2fs_write_inode+0x65/0x290 [snapfs]

[  369.899963] INFO: task f2fs_ckpt-259:0:3128 blocked for more than 122 seconds.
  Call Trace:
  __lock_page+0x4c/0x60
  f2fs_flush_inline_data+0x1b7/0x2a0 [snapfs]
  f2fs_write_checkpoint+0x154/0x15d0 [snapfs]

[  369.900377] INFO: task ib_log_writer:3228 blocked for more than 122 seconds.
  Call Trace:
  __get_meta_page+0x90/0x1a0 [snapfs]
  f2fs_get_meta_page+0x13/0x20 [snapfs]
  snapfs_batch_apply_one+0x6d9/0xa30 [snapfs]
  f2fs_cow_node_block_batch+0x625/0xc40 [snapfs]
  __f2fs_set_mulref_blocks+0x1e0c/0x20e0 [snapfs]
  f2fs_cow+0x67f/0x11b0 [snapfs]

[  492.779856] INFO: task f2fs_mulref-259:3132 blocked for more than 122 seconds.
  Call Trace:
  __get_meta_page+0x90/0x1a0 [snapfs]
  f2fs_get_meta_page+0x13/0x20 [snapfs]
  mulref_collect_stats+0x5f/0x130 [snapfs]
  mulref_compact_thread_func+0x10c/0x2b0 [snapfs]
```

### 调用链分析

```
ib_log_writer write()
  → f2fs_file_write_iter
    → f2fs_snapshot_cow
      → f2fs_cow
        → __f2fs_set_mulref_blocks
          → f2fs_cow_node_block_batch (batch mode)
            → snapfs_batch_begin
            → snapfs_batch_commit
            → snapfs_batch_apply_one  ← 阻塞点
              → f2fs_get_meta_page (获取 sum/sit page)
                → __get_meta_page
                  → wait_on_page_bit_common  ← 等待 page 解锁
```

### 根因分析

**问题 1：Dirty Page 泄漏（方案 4 - 优先修复）**

`f2fs_cow_node_block_batch` 的 `out_free_slot` 标签（snapshot.c:4656-4658）存在 page 泄漏：

```c
out_free_slot:
    snapfs_batch_free_slot(sbi, batch_ctx->slot_id);  // 只释放了 slot
    return ret;  // ❌ 没有释放 dirty pages！
```

当以下步骤失败时，代码跳转到 `out_free_slot`，但没有释放 dirty pages：
- `snapfs_batch_begin`（步骤3）
- `snapfs_batch_commit`（步骤4）
- `snapfs_batch_apply_one`（步骤5）
- `snapfs_batch_flush_all`（步骤5b）
- `snapfs_batch_mark_applied`（步骤6）

泄漏的 pages 包括：
- `batch_ctx->dirty_mr_page`
- `batch_ctx->dirty_sum_pages[]`
- `batch_ctx->dirty_sit_pages[]`

这些 pages 被分配但从未释放，导致：
1. 占用 page cache 内存
2. 长期处于 locked 状态
3. 后续 `f2fs_get_meta_page` 调用被阻塞

**问题 2：Meta Page I/O 积压**

两阶段 flush 的设计导致大量 dirty meta pages 同时需要 writeback：
- 一次 batch 最多处理 1018 个数据块
- 每个数据块需要修改 mr/sum/sit pages
- 大量 dirty pages 的 writeback 请求积压，导致 I/O 队列饱和

### 修复方案

#### 方案 4：修复 Dirty Page 泄漏（优先实施）

**修改位置**：`snapshot.c:4656-4658`（`out_free_slot` 标签）

**修改内容**：在 `out_free_slot` 处添加 dirty pages 清理逻辑

```c
out_free_slot: {
    int j;
    /* 清理 dirty pages */
    if (batch_ctx->dirty_mr_page) {
        f2fs_put_page(batch_ctx->dirty_mr_page, 1);
        batch_ctx->dirty_mr_page = NULL;
    }
    for (j = 0; j < batch_ctx->dirty_sum_count; j++) {
        if (batch_ctx->dirty_sum_pages[j]) {
            f2fs_put_page(batch_ctx->dirty_sum_pages[j], 1);
            batch_ctx->dirty_sum_pages[j] = NULL;
        }
    }
    batch_ctx->dirty_sum_count = 0;
    for (j = 0; j < batch_ctx->dirty_sit_count; j++) {
        if (batch_ctx->dirty_sit_pages[j]) {
            f2fs_put_page(batch_ctx->dirty_sit_pages[j], 1);
            batch_ctx->dirty_sit_pages[j] = NULL;
        }
    }
    batch_ctx->dirty_sit_count = 0;

    snapfs_batch_free_slot(sbi, batch_ctx->slot_id);
    kfree(batch_ctx);
    return ret;
}
```

**预期效果**：
- 如果泄漏是问题根因，修复后应该立即改善
- Dirty pages 在错误路径中被正确释放
- 减少 meta page cache 的内存占用

---

### 方案 3：更激进的 Page 释放策略（后续改进）

如果方案 4 不能完全解决问题，可以考虑以下策略。

#### 策略 1：分批 Flush（推荐）

**思路**：不一次性 flush 所有 dirty pages，而是分批次处理。

**详细设计**：

```c
#define FLUSH_BATCH_SIZE 100  // 每批处理的 dirty pages 数量

int snapfs_batch_flush_with_throttle(struct f2fs_sb_info *sbi,
                                     struct snapfs_batch_context *ctx)
{
    struct page **all_pages;
    int total_pages = 0;
    int i, j;

    /* 1. 提取所有 dirty pages 到数组 */
    if (ctx->dirty_mr_page)
        all_pages[total_pages++] = ctx->dirty_mr_page;
    for (i = 0; i < ctx->dirty_sum_count; i++)
        if (ctx->dirty_sum_pages[i])
            all_pages[total_pages++] = ctx->dirty_sum_pages[i];
    for (i = 0; i < ctx->dirty_sit_count; i++)
        if (ctx->dirty_sit_pages[i])
            all_pages[total_pages++] = ctx->dirty_sit_pages[i];

    /* 2. 分批提交 writeback */
    for (i = 0; i < total_pages; i += FLUSH_BATCH_SIZE) {
        int batch_end = min(i + FLUSH_BATCH_SIZE, total_pages);

        /* 第一阶段：提交本批 writeback */
        for (j = i; j < batch_end; j++)
            snapfs_submit_meta_page_write(sbi, all_pages[j]);

        /* 第二阶段：等待本批 I/O 完成 */
        for (j = i; j < batch_end; j++) {
            snapfs_wait_meta_page_writeback(sbi, all_pages[j]);
            f2fs_put_page(all_pages[j], 0);
        }

        /* 每批完成后释放 CPU，避免长时间占用 */
        cond_resched();
    }

    return 0;
}
```

**优点**：
- 避免一次性提交过多 I/O 请求
- 每批 I/O 完成后再处理下一批，减少 I/O 队列积压
- 每批完成后释放 CPU，让其他操作有机会执行

**缺点**：
- 整体 I/O 次数可能增加
- 需要更多代码逻辑

---

#### 策略 2：超时机制

**思路**：在等待 I/O 完成时设置超时，避免无限期等待。

```c
static int snapfs_wait_meta_page_writeback_throttle(struct f2fs_sb_info *sbi,
                                                    struct page *page)
{
    /* 检查 page 是否已完成 writeback */
    if (!PageWriteback(page)) {
        if (PageLocked(page))
            unlock_page(page);
        return 0;
    }

    /* I/O 还在进行，设置超时等待（5秒） */
    unsigned long timeout = jiffies + 5 * HZ;
    int ret = wait_event_timeout(page->wait_queue,
        !PageWriteback(page), timeout);

    if (PageWriteback(page)) {
        /* 超时，强制 unlock */
        pr_warn("[snapfs flush] wait page writeback timeout\n");
        unlock_page(page);
        return -ETIMEDOUT;
    }

    if (PageLocked(page))
        unlock_page(page);
    return 0;
}
```

**注意**：此策略可能影响数据持久化保证，需谨慎使用。

---

#### 策略 3：MR Page 优先处理

**思路**：MR page 是最关键的元数据，优先处理。

```c
int snapfs_batch_flush_mr_first(struct f2fs_sb_info *sbi,
                                struct snapfs_batch_context *ctx)
{
    /* 1. 先处理 MR page */
    if (ctx->dirty_mr_page) {
        snapfs_submit_meta_page_write(sbi, ctx->dirty_mr_page);
        snapfs_wait_meta_page_writeback(sbi, ctx->dirty_mr_page);
        f2fs_put_page(ctx->dirty_mr_page, 0);
        ctx->dirty_mr_page = NULL;
    }

    /* 2. 然后处理 sum pages */
    /* ... */

    /* 3. 最后处理 sit pages */
    /* ... */

    return 0;
}
```

---

### 实施建议

1. **先修复方案 4**（page 泄漏问题）
   - 简单直接，效果可能最明显
   - 修复后重新运行测试，观察是否改善

2. **如果问题仍存在，实施策略 1**（分批 flush）
   - 效果较好，但需要较多代码改动
   - 需要重新设计 `snapfs_batch_flush_all` 函数

3. **如果需要微调，实施策略 2**（超时机制）
   - 作为策略 1 的补充
   - 需权衡数据持久化保证

4. **不建议实施的方案**：
   - **减少 batch 的块数**：管理复杂，开销加大，效果不一定好
   - **跳过 I/O 等待**：与"batch 持久化必须紧跟元数据持久化"的设计约束冲突

---

### 待验证

1. 重新编译模块后运行 MySQL TPCC 测试
2. 观察是否仍有 meta page 阻塞
3. 监控磁盘 I/O 是否正常下发
4. 如仍有问题，按方案 3 的策略进行后续改进

---

## 2026/04/23 - 分批 Flush 优化（第六轮）

### 问题描述

第五轮修改（两阶段 flush）虽然理论上能提高 I/O 效率，但在实际测试中仍然导致长时间阻塞：
- 多个线程阻塞超过 122 秒
- 看不到有磁盘 I/O 下发
- 线程阻塞在 `f2fs_get_meta_page` → `wait_on_page_bit_common`

### 根因分析

两阶段 flush 的问题是：
1. 第一阶段一次性提交所有 dirty pages 的 writeback
2. 第二阶段一次性等待所有 I/O 完成
3. 在高负载下，I/O 调度器积压大量请求，导致长时间阻塞

### 解决方案

实现**分批 flush**（策略1）：
1. 将 dirty pages 分成小批次处理（每批 32 个）
2. 每批次：提交 writeback → 等待 I/O 完成 → 释放 pages
3. 每批次之间调用 `cond_resched()`，让其他操作有机会执行

### 新增常量

| 常量 | 值 | 说明 |
|------|-----|------|
| `SNAPFS_FLUSH_BATCH_SIZE` | 32 | 每批处理的 dirty pages 数量 |
| `SNAPFS_MAX_DIRTY_PAGES` | 64 | dirty pages 数组的最大长度 |

### 修改位置

| 文件 | 行号 | 修改内容 |
|------|------|----------|
| snapshot.h | 14-17 | 添加常量定义 |
| snapshot.c | 2189-2340 | 重写 `snapfs_batch_flush_all`，实现分批 flush |

### 设计优势

1. **避免长时间阻塞**：每批 I/O 有机会及时完成，避免无限期等待
2. **CPU 释放**：每批完成后调用 `cond_resched()`，让其他操作（如 checkpoint）有机会执行
3. **内存占用降低**：不再需要 `dirty_sum_pages[]` 和 `dirty_sit_pages[]` 数组，直接收集到本地数组处理

### 待验证

1. 重新编译模块后运行 MySQL TPCC 测试
2. 观察是否仍有长时间阻塞（>120 秒）
3. 监控磁盘 I/O 是否正常下发

---

## 2026/04/23 - Meta Page 等待超时机制（第七轮）

### 问题描述

MySQL TPCC 测试期间，系统出现死锁：
- 多个线程阻塞超过 122 秒
- 阻塞在 `f2fs_get_meta_page` → `snapfs_batch_apply_one`
- `ib_log_writer`、`f2fs_mulref-259`、`f2fs_ckpt-259` 均被阻塞
- **监控观察：看不到有磁盘 IO 下发**

### 根因分析

`f2fs_wait_on_page_writeback` 会无限期等待 I/O 完成：
- 在 I/O 系统繁忙时，可能等待超过 120 秒
- 导致 meta page 被长期持有，系统级联阻塞
- 后续的 `f2fs_get_meta_page` 操作无法获取 meta pages

### 解决方案

实现**超时 + fsync 机制**：
1. 第一阶段：5 秒超时轮询等待，期间调用 `cond_resched()` 释放 CPU
2. 第二阶段：超时后调用 `f2fs_sync_meta_page` 强制等待 I/O 完成，确保 durability
3. 最终：unlock page，允许后续操作访问

### 新增常量

| 常量 | 值 | 说明 |
|------|-----|------|
| `SNAPFS_PAGE_WAIT_TIMEOUT` | 5 | meta page writeback 超时时间（秒） |

### 修改位置

| 文件 | 行号 | 修改内容 |
|------|------|----------|
| snapshot.h | 20 | 添加 `SNAPFS_PAGE_WAIT_TIMEOUT` 常量定义 |
| snapshot.c | 446-490 | 重写 `snapfs_wait_meta_page_writeback` 函数 |

### 修改后的函数逻辑

```c
static int snapfs_wait_meta_page_writeback(struct f2fs_sb_info *sbi, struct page *page)
{
    unsigned long timeout;
    int ret;

    if (!page)
        return 0;

    // 第一阶段：5 秒超时轮询等待
    timeout = jiffies + SNAPFS_PAGE_WAIT_TIMEOUT * HZ;
    while (time_before(jiffies, timeout)) {
        if (!PageWriteback(page))
            break;
        cond_resched();
    }

    // 第二阶段：超时后调用 f2fs_sync_meta_page 确保 durability
    if (PageWriteback(page)) {
        pr_warn("[snapfs flush] page writeback timeout, forcing sync\n");
        ret = f2fs_sync_meta_page(sbi, page, FS_META_IO);
        if (ret) {
            pr_err("[snapfs flush] sync_meta_page failed: %d\n", ret);
        }
    }

    if (PageLocked(page))
        unlock_page(page);

    return 0;
}
```

### 设计说明

| 阶段 | 行为 | 目的 |
|------|------|------|
| 第一阶段 | 5 秒超时轮询等待 | 避免长时间阻塞，给 I/O 系统恢复时间 |
| 第二阶段 | f2fs_sync_meta_page | 超时后强制等待 I/O 完成，确保 durability |
| 最终 | unlock page | 释放 page，允许后续操作访问 |

### Durability 保证

- `f2fs_sync_meta_page` 会等待该 page 的 writeback 完成
- 即使超时后仍会阻塞，但这确保了 meta page 被真正持久化
- 避免了 batch redo 数据丢失的风险

### 潜在问题

- 如果 I/O 系统持续繁忙，`f2fs_sync_meta_page` 仍可能长时间阻塞
- 但这是 durability 的必要代价

### 回滚方案

如需回滚本次修改：

1. **snapshot.h**：删除 `SNAPFS_PAGE_WAIT_TIMEOUT` 常量定义（第 20 行）

2. **snapshot.c**：将 `snapfs_wait_meta_page_writeback` 函数恢复为原版本：

```c
static int snapfs_wait_meta_page_writeback(struct f2fs_sb_info *sbi, struct page *page)
{
    if (!page)
        return 0;

    f2fs_wait_on_page_writeback(page, META, true, true);
    unlock_page(page);

    return 0;
}
```

### 待验证

1. 重新编译模块后运行 MySQL TPCC 测试
2. 观察是否仍有长时间阻塞（>120 秒）
3. 检查 dmesg 中是否有 "page writeback timeout, forcing sync" 警告
4. 评估 I/O 吞吐量和延迟是否有改善

---

## 2026/04/23 - 添加并发调试日志（第八轮）

### 问题描述

MySQL TPCC 测试期间，系统出现死锁：
- 多个线程阻塞超过 122 秒
- 阻塞在 `f2fs_get_meta_page` → `snapfs_batch_apply_one`
- 单文件测试没有问题，**怀疑是多文件 COW 并发导致的问题**

### 根因假设

多文件并发 COW 时，可能存在以下竞争点：
1. **同一个 segment 的 sum page 竞争**：多个文件的数据块可能在同一个 segment
2. **同一个 SIT block 的 sit page 竞争**：多个 segment 可能在同一个 SIT block
3. **内存压力**：多文件并发导致 meta pages 累积
4. **Page 锁竞争**：不同 batch 操作同一 meta page

### 添加的调试日志

#### 1. f2fs_cow_node_block_batch 函数

```c
// 开始时的日志
pr_info("[snapfs batch][%lu] PID=%d START src_ino=%u snap_ino=%lu node=(%u,%u) nr_blks=%d slot=%u\n",
    jiffies, current->pid, src_ino, inode->i_ino, node_nid, node_ofs, nr_data_blks, slot_id);

// 结束时的日志
pr_info("[snapfs batch][%lu] PID=%d END src_ino=%u snap_ino=%lu node=(%u,%u) slot=%u entries=%d dirty_mr=%d dirty_sum=%d dirty_sit=%d duration=%ums\n",
    jiffies, current->pid, src_ino, inode->i_ino, node_nid, node_ofs,
    batch_ctx->slot_id, batch_ctx->entry_count,
    batch_ctx->dirty_mr_page ? 1 : 0,
    batch_ctx->dirty_sum_count,
    batch_ctx->dirty_sit_count,
    jiffies_to_msecs(jiffies - start_jiffies));
```

**关键信息**：

| 字段 | 含义 | 用途 |
|------|------|------|
| `src_ino` | 源 inode 号 | 区分不同文件 |
| `snap_ino` | 快照 inode 号 | 区分快照 |
| `PID` | 进程/线程号 | 区分并发操作 |
| `slot` | batch slot id | 追踪单个 batch 生命周期 |
| `nr_blks` | 处理的数据块数 | 评估 batch 大小 |
| `dirty_sum` | 访问的 sum page 数 | 评估 segment 竞争 |
| `dirty_sit` | 访问的 sit page 数 | 评估 SIT block 竞争 |
| `duration` | 处理耗时 | 识别慢 batch |

#### 2. snapfs_batch_apply_one 函数（依赖 SNAPFS_DEBUG=1）

```c
// 进入时的日志
pr_info("[snapfs apply][%lu] PID=%d slot=%u bit=%u mr=%u data_blk=%u segno=%u\n",
    jiffies, current->pid, ctx->slot_id, bitno,
    le32_to_cpu(entry->mulref.mr_blkaddr),
    le32_to_cpu(entry->data_blkaddr),
    GET_SEGNO(sbi, le32_to_cpu(entry->data_blkaddr)));

// 获取 MR page
pr_info("[snapfs apply][%lu] PID=%d slot=%u bit=%u getting MR page blkaddr=%u\n", ...);
pr_info("[snapfs apply][%lu] PID=%d slot=%u bit=%u got MR page OK\n", ...);

// 获取 SUM page
pr_info("[snapfs apply][%lu] PID=%d slot=%u bit=%u getting SUM page blkaddr=%u segno=%u\n", ...);
pr_info("[snapfs apply][%lu] PID=%d slot=%u bit=%u got SUM page OK blkaddr=%u\n", ...);

// 获取 SIT page
pr_info("[snapfs apply][%lu] PID=%d slot=%u bit=%u getting SIT page blkaddr=%llu\n", ...);
pr_info("[snapfs apply][%lu] PID=%d slot=%u bit=%u got SIT page OK blkaddr=%llu\n", ...);
```

**关键信息**：

| 字段 | 含义 | 用途 |
|------|------|------|
| `mr` | mulref block 地址 | 识别 MR page 竞争 |
| `data_blk` | 数据块地址 | 计算 segno |
| `segno` | segment 号 | **识别同一 segment 的竞争** |
| `sit_blkaddr` | SIT block 地址 | 识别 SIT page 竞争 |

#### 3. snapfs_batch_flush_all 函数

```c
// 开始时的日志
pr_info("[snapfs flush][%lu] PID=%d slot=%u START total_pages=%d\n", ...);

// 等待每个 page
pr_info("[snapfs flush][%lu] PID=%d slot=%u waiting page[%d]=%p\n", ...);

// 等待完成
pr_info("[snapfs flush][%lu] PID=%d slot=%u waited page[%d]=%p duration=%ums ret=%d\n", ...);

// 结束时的日志
pr_info("[snapfs flush][%lu] PID=%d slot=%u END total_pages=%d duration=%ums\n", ...);
```

**关键信息**：

| 字段 | 含义 | 用途 |
|------|------|------|
| `total_pages` | dirty pages 总数 | 评估 batch 大小 |
| `page[%d]` | page 指针 | 识别同一 page 的竞争 |
| `duration` | 等待每个 page 的时间 | **识别慢 IO** |

### 日志分析验证手段

#### 1. 收集日志

```bash
# 完整收集
sudo dmesg > /tmp/dmesg_full.log

# 或者实时查看
sudo dmesg -w | grep snapfs
```

#### 2. 分析并发模式

```bash
# 2.1 查看 batch 并发数量（同一时刻 START 的 batch 数量）
grep "\[snapfs batch\].*START" /tmp/dmesg_full.log | awk '{print $1}' | sort | uniq | wc -l

# 2.2 统计不同文件的 batch 分布
grep "\[snapfs batch\].*START" /tmp/dmesg_full.log | \
    awk '{print $6}' | sed 's/src_ino=//' | sort | uniq -c | sort -rn

# 2.3 查看同一 segment 的并发访问（segno 重复说明存在竞争）
grep "segno=" /tmp/dmesg_full.log | \
    awk -F'segno=' '{split($2,a," "); print a[1]}' | sort | uniq -c | \
    awk '$1 > 1 {print}' | sort -rn
```

#### 3. 识别慢操作

```bash
# 3.1 查看 flush 耗时 > 100ms 的情况
grep "\[snapfs flush\].*waited" /tmp/dmesg_full.log | \
    awk -F'duration=' '{split($2,a,"ms"); if(int(a[1]) > 100) print}'

# 3.2 查看 batch 处理耗时 > 100ms 的情况
grep "\[snapfs batch\].*END" /tmp/dmesg_full.log | \
    awk -F'duration=' '{split($2,a,"ms"); if(int(a[1]) > 100) print}'

# 3.3 统计 flush 等待时间的分布
grep "\[snapfs flush\].*waited" /tmp/dmesg_full.log | \
    awk -F'duration=' '{split($2,a,"ms"); print int(a[1])}' | \
    sort -n | uniq -c | awk '{print "等待"$1"次的时长:", $2"ms"}'
```

#### 4. 追踪单个 batch 的生命周期

```bash
# 4.1 查找 slot=xxx 的所有日志（将 xxx 替换为实际 slot 号）
grep "slot=xxx" /tmp/dmesg_full.log

# 4.2 查找特定 src_ino 的 batch 操作
grep "src_ino=12345" /tmp/dmesg_full.log

# 4.3 查找特定 PID 的 batch 操作
grep "PID=54321" /tmp/dmesg_full.log
```

#### 5. 识别竞争点

```bash
# 5.1 识别同一 MR page 的并发访问
grep "getting MR page" /tmp/dmesg_full.log | \
    awk -F'blkaddr=' '{split($2,a,"\n"); print a[1]}' | sort | uniq -c | \
    awk '$1 > 1 {print "MR blkaddr=" $2 " 访问次数=" $1}'

# 5.2 识别同一 SUM page 的并发访问
grep "getting SUM page" /tmp/dmesg_full.log | \
    awk -F'blkaddr=' '{split($2,a," "); print a[1]}' | sort | uniq -c | \
    awk '$1 > 1 {print "SUM blkaddr=" $2 " 访问次数=" $1}'

# 5.3 识别同一 SIT page 的并发访问
grep "getting SIT page" /tmp/dmesg_full.log | \
    awk -F'blkaddr=' '{split($2,a," "); print a[1]}' | sort | uniq -c | \
    awk '$1 > 1 {print "SIT blkaddr=" $2 " 访问次数=" $1}'
```

#### 6. 系统资源检查

```bash
# 6.1 阻塞时的内存状态
free -m
cat /proc/meminfo | grep -E "MemAvailable|Cached|AnonH"

# 6.2 阻塞时的 IO 状态
iostat -x 1 5

# 6.3 阻塞时的进程状态
ps aux | grep -E "ib_log_writer|f2fs|mysqld" | head -20
```

### 预期日志示例

正常情况下，日志应该显示：
```
[  123.456] [snapfs batch][12345678] PID=1234 START src_ino=100 snap_ino=200 node=(10,0) nr_blks=12 slot=5
[  123.459] [snapfs apply][12345679] PID=1234 slot=5 bit=0 mr=12345 data_blk=67890 segno=42
[  123.460] [snapfs apply][12345679] PID=1234 slot=5 bit=0 got MR page OK
[  123.460] [snapfs apply][12345679] PID=1234 slot=5 bit=0 getting SUM page blkaddr=99 segno=42
[  123.460] [snapfs apply][12345679] PID=1234 slot=5 bit=0 got SUM page OK
[  123.462] [snapfs flush][12345681] PID=1234 slot=5 START total_pages=6
[  123.463] [snapfs flush][12345682] PID=1234 slot=5 waited page[0]=pfn 等待时间=1ms
[  123.464] [snapfs flush][12345683] PID=1234 slot=5 waited page[1]=pfn 等待时间=1ms
[  123.465] [snapfs flush][12345684] PID=1234 slot=5 END total_pages=6 duration=3ms
[  123.466] [snapfs batch][12345686] PID=1234 END src_ino=100 snap_ino=200 node=(10,0) slot=5 entries=12 dirty_mr=1 dirty_sum=2 dirty_sit=1 duration=10ms
```

异常情况下（日志大量堆积，等待时间超长）：
```
[  234.567] [snapfs flush][23456789] PID=1234 slot=5 START total_pages=6
[  239.567] [snapfs flush][23956789] PID=1234 slot=5 waited page[0]=pfn 等待时间=5000ms  ← 异常！
[  244.567] [snapfs flush][24456789] PID=5678 slot=7 START total_pages=6  ← 并发
[  249.567] [snapfs flush][24956789] PID=5678 slot=7 waited page[0]=pfn 等待时间=5000ms  ← 异常！
```

### 识别竞争的具体方法

**场景分析**：

如果观察到以下模式，说明存在 segment 竞争：
```
# 日志显示不同文件访问相同 segno
PID=1111 slot=1 bit=0 segno=42  ← 文件 A
PID=2222 slot=2 bit=0 segno=42  ← 文件 B（同一 segno！）
```

**死锁场景重建**：
```
线程 A: batch slot=1, 获取 sum page of segno=42
线程 B: batch slot=2, 也需要 sum page of segno=42
线程 A: flush slot=1, 等待 IO 完成（page locked）
线程 B: snapfs_batch_apply_one, 尝试获取 sum page of segno=42
     → lock_page(page) 被阻塞（等待线程 A 的 IO）
线程 A: flush 完成，但被其他操作阻塞
→ 形成等待环
```

### 待验证

1. 重新编译模块：`make clean && make`
2. 加载模块：`insmod snapfs.ko`
3. 运行 MySQL TPCC 测试
4. 收集并分析 dmesg 日志
5. 根据日志识别具体的竞争点

*最后更新: 2026/04/23*

---

## 2026/04/23 - 添加无条件调试日志（第九轮）

### 问题背景

在分析死锁问题时，需要验证以下假设：
1. 不同文件的数据块可能分布在同一个 segment，共用一个 sum_page
2. 不同 batch 操作可能同时访问同一个 sum_page，存在竞争
3. 如果某个 batch 持有 sum_page 并长时间处于 writeback 状态，会导致其他 batch 阻塞

### 添加的调试日志

为了追踪 segment 竞争问题，在 `snapfs_batch_apply_one` 函数中添加了**无条件调试日志**（不依赖 `SNAPFS_DEBUG` 宏）：

| 日志位置 | 日志内容 | 用途 |
|----------|----------|------|
| `snapfs_batch_apply_one` 入口 | `[snapfs apply][jiffies] PID=x slot=x bit=x START segno=x` | 追踪每个 entry 处理开始 |
| MR page 获取前 | `[snapfs apply][jiffies] PID=x slot=x bit=x getting MR page blkaddr=x` | 识别 MR page 竞争 |
| MR page 获取后 | `[snapfs apply][jiffies] PID=x slot=x bit=x got MR page OK` | 确认获取成功 |
| SUM page 获取前 | `[snapfs apply][jiffies] PID=x slot=x bit=x getting SUM page blkaddr=x segno=x` | **识别 SUM page 竞争** |
| SUM page 获取后 | `[snapfs apply][jiffies] PID=x slot=x bit=x got SUM page OK blkaddr=x` | 确认获取成功 |
| SIT page 获取前 | `[snapfs apply][jiffies] PID=x slot=x bit=x getting SIT page blkaddr=x` | 识别 SIT page 竞争 |
| SIT page 获取后 | `[snapfs apply][jiffies] PID=x slot=x bit=x got SIT page OK blkaddr=x` | 确认获取成功 |
| `snapfs_batch_apply_one` 出口 | `[snapfs apply][jiffies] PID=x slot=x bit=x END dirty_mr=x dirty_sum=x dirty_sit=x` | 确认 entry 处理完成 |
| `snapfs_batch_flush_all` 入口 | `[snapfs flush][jiffies] PID=x slot=x START total_pages=x (mr=x sum=x sit=x)` | 追踪 dirty pages 数量 |

### 修改位置

| 文件 | 行号 | 修改内容 |
|------|------|----------|
| snapshot.c | 2026-2030 | 添加 apply START 日志 |
| snapshot.c | 2032-2046 | MR page 获取日志（无条件） |
| snapshot.c | 2096-2113 | SUM page 获取日志（无条件） |
| snapshot.c | 2115-2135 | SIT page 获取日志（无条件） |
| snapshot.c | 2199-2202 | apply END 日志（无条件） |
| snapshot.c | 2262-2267 | flush START 日志增加 dirty pages 统计 |

### 日志分析命令

```bash
# 1. 提取所有 apply START 日志，查看 segno 重复情况
dmesg | grep "\[snapfs apply\].*START" | awk '{print $6}' | sed 's/segno=//' | sort | uniq -c | sort -rn | head -20

# 2. 检查是否有 apply START 但没有对应的 END（说明卡在 apply_one 中）
dmesg | grep "\[snapfs apply\].*START" > /tmp/apply_start.log
dmesg | grep "\[snapfs apply\].*END" > /tmp/apply_end.log
# 对比 START 和 END 的数量是否一致

# 3. 检查 SUM page 竞争（查看相同 segno 的并发访问）
dmesg | grep "getting SUM page" | awk '{print $10}' | sed 's/segno=//' | sort | uniq -c | sort -rn | head -20

# 4. 检查 MR page 竞争
dmesg | grep "getting MR page" | awk '{print $9}' | sed 's/blkaddr=//' | sort | uniq -c | sort -rn | head -20

# 5. 检查 SIT page 竞争
dmesg | grep "getting SIT page" | awk '{print $9}' | sed 's/blkaddr=//' | sort | uniq -c | sort -rn | head -20

# 6. 检查 flush 是否正常完成
dmesg | grep "\[snapfs flush\].*END"

# 7. 检查是否有超过 1 秒的等待时间
dmesg | grep "waited page.*duration=[0-9]*ms" | awk -F'duration=' '{split($2,a,"ms"); if(int(a[1]) > 1000) print}'

# 8. 检查 dirty pages 数量是否正常
dmesg | grep "flush.*START.*total_pages"
```

### 关键观察点

1. **segment 竞争**：如果多个不同的 batch（不同 PID/slot）访问相同的 segno，说明存在竞争
   ```
   # 示例：不同 batch 访问相同 segno
   [  189.768] [snapfs apply] PID=1111 slot=1 bit=0 START segno=42
   [  189.769] [snapfs apply] PID=2222 slot=2 bit=0 START segno=42  ← 竞争！
   ```

2. **apply_one 卡住**：如果 START 日志很多但 END 日志很少，说明 apply_one 卡住了
   ```
   # 检查数量
   dmesg | grep -c "\[snapfs apply\].*START"   # 应该有 N 条
   dmesg | grep -c "\[snapfs apply\].*END"     # 也应该有 N 条
   ```

3. **flush 阻塞**：如果 flush 的等待时间很长（>100ms），说明 I/O 有问题
   ```
   [  369.772] [snapfs flush] PID=3189 slot=0 waited page[0]=... duration=5000ms  ← 异常！
   ```

4. **dirty pages 泄漏**：如果 flush START 显示 mr/sum/sit 非零但没有对应的 END，说明 pages 可能被泄漏了

### 预期日志示例

**正常情况**：
```
[  189.768] [snapfs apply] PID=3189 slot=0 bit=0 START segno=100
[  189.768] [snapfs apply] PID=3189 slot=0 bit=0 getting MR page blkaddr=12345
[  189.768] [snapfs apply] PID=3189 slot=0 bit=0 got MR page OK
[  189.768] [snapfs apply] PID=3189 slot=0 bit=0 getting SUM page blkaddr=99 segno=100
[  189.768] [snapfs apply] PID=3189 slot=0 bit=0 got SUM page OK blkaddr=99
[  189.768] [snapfs apply] PID=3189 slot=0 bit=0 getting SIT page blkaddr=1000
[  189.768] [snapfs apply] PID=3189 slot=0 bit=0 got SIT page OK blkaddr=1000
[  189.768] [snapfs apply] PID=3189 slot=0 bit=0 END dirty_mr=xxx dirty_sum=xxx dirty_sit=xxx
```

**异常情况（segment 竞争）**：
```
[  189.768] [snapfs apply] PID=3189 slot=0 bit=0 START segno=100
[  189.768] [snapfs apply] PID=3189 slot=0 bit=0 getting SUM page blkaddr=99 segno=100
[  189.769] [snapfs apply] PID=3225 slot=1 bit=5 START segno=100  ← 不同 batch，相同 segno
[  189.769] [snapfs apply] PID=3225 slot=1 bit=5 getting SUM page blkaddr=99 segno=100  ← 等待！
```

### 待验证

1. 重新编译模块：`make`
2. 加载模块：`insmod snapfs.ko`
3. 运行测试
4. 收集 dmesg 日志
5. 使用上述命令分析日志，验证是否存在 segment 竞争

---

## 2026/04/23 - Multi-file 并发导致 redo slot 检查阻塞（第十轮）

### 问题描述

MySQL TPCC 测试期间，系统出现死锁：
- 多个线程阻塞超过 122 秒
- 阻塞在 `f2fs_get_meta_page` → `snapfs_batch_slot_overwritable`
- 单文件测试没有问题，**多文件并发导致问题**

### dmesg 关键信息

```
[  369.997305]  snapfs_batch_apply_one.cold+0x37c/0xae4 [snapfs]
[  369.997348]  f2fs_cow_node_block_batch.cold+0x499/0xba6 [snapfs]
[  369.997406]  __get_meta_page+0x90/0x1a0 [snapfs]
[  369.997348]  f2fs_get_meta_page+0x13/0x20 [snapfs]
[  369.997348]  snapfs_batch_apply_one.cold+0x37c/0xae4 [snapfs]
```

### 根因分析

**单文件 vs 多文件并发的区别**：

| 场景 | 行为 | 结果 |
|------|------|------|
| 单文件 | 一个 batch 完成后再开始下一个 | 无竞争 |
| 多文件 | 多个文件同时 COW，11 个 slot 并发操作 | **存在竞争** |

**竞争点**：`snapfs_batch_slot_overwritable` 函数在检查 slot 状态时需要读取 header page：

```c
// snapshot.c:849-854
page = f2fs_get_meta_page(sbi,
    redo->journal_blkaddr + slot_id * redo->batch_slot_blocks);
```

**问题链路**：
1. 多个文件同时执行 `snapfs_batch_commit`
2. 每个 commit 提交 43 个 blocks 的 writeback
3. 所有 slot 的 header blocks 都在同一个 segment（redo journal segment）
4. 当某个 slot 的 header page 处于 Writeback 状态时
5. `f2fs_get_meta_page` 会等待 writeback 完成
6. **如果 I/O 系统繁忙，等待超过 120 秒**
7. 所有等待 `f2fs_get_meta_page` 的线程都阻塞，系统假死

### 死锁场景

```
时间线：
─────────────────────────────────────────────────────────────────────
T1: 文件 A 的 batch 开始 commit
    → 提交 header + 42 blocks 的 writeback
    → pages 进入 Writeback 状态

T2: 文件 B 的 batch 开始 commit
    → 提交 writeback

T3: 文件 C 的 batch 开始 commit
    → 提交 writeback

T4: 文件 D 尝试分配 slot
    → snapfs_batch_find_free_slot 遍历所有 slot
    → snapfs_batch_slot_overwritable 读取 slot 0 的 header
    → 但 slot 0 的 header page 还在 Writeback 状态！
    → f2fs_get_meta_page 阻塞等待

T5: 同时，文件 E, F, G... 也在分配 slot
    → 都在调用 snapfs_batch_slot_overwritable
    → 都在等待 Writeback 完成
    → 系统假死
```

### 修复方案

**核心思路**：在 `snapfs_batch_slot_overwritable` 中添加超时机制，避免无限等待。

**修改内容**：

1. **新增 `snapfs_get_meta_page_timeout` 函数**（snapshot.c:480-536）
   - 默认 2 秒超时
   - 如果 page 正在 writeback，轮询等待，最多等待超时时间
   - 超时后返回 `ERR_PTR(-ETIMEDOUT)`

2. **修改 `snapfs_batch_slot_overwritable`**（snapshot.c:838-901）
   - 将 `f2fs_get_meta_page` 替换为 `snapfs_get_meta_page_timeout`
   - 如果获取 header page 超时，返回 `false`（跳过该 slot）

3. **修改 `snapfs_batch_find_free_slot`**（snapshot.c:919-962）
   - 增强日志输出，记录超时/失败的次数

### 新增代码

**`snapfs_get_meta_page_timeout` 函数**：

```c
/*
 * snapfs_get_meta_page_timeout - 带超时的 meta page 获取
 *
 * 问题背景：
 * 在多文件并发 COW 时，snapfs_batch_slot_overwritable 需要读取 slot header
 * 如果 header page 正在 writeback，f2fs_get_meta_page 会无限期等待
 * 导致系统假死（所有线程阻塞在 meta page 获取上）
 *
 * 解决方案：
 * - 添加 2 秒超时机制
 * - 超时后返回 -ETIMEDOUT，让调用者跳过该 slot
 * - 避免单个 slot 的问题影响整个系统的并发处理
 */
static struct page *snapfs_get_meta_page_timeout(struct f2fs_sb_info *sbi,
						 block_t blkaddr,
						 unsigned int timeout_ms)
{
	struct page *page;
	unsigned long timeout;
	unsigned long start_jiffies;

	if (timeout_ms == 0)
		timeout_ms = 2000;  /* 默认 2 秒超时 */

	page = f2fs_get_meta_page(sbi, blkaddr);
	if (IS_ERR(page))
		return page;

	if (PageUptodate(page))
		return page;

	if (PageWriteback(page)) {
		start_jiffies = jiffies;
		timeout = jiffies + msecs_to_jiffies(timeout_ms);

		while (time_before(jiffies, timeout)) {
			msleep(100);
			if (!PageWriteback(page))
				return page;
			if (PageError(page))
				break;
			cond_resched();
		}

		/* 超时，释放 page 并返回错误 */
		pr_warn("[snapfs meta] timeout waiting for page blkaddr=%llu\n",
			(unsigned long long)blkaddr);
		f2fs_put_page(page, 1);
		return ERR_PTR(-ETIMEDOUT);
	}

	f2fs_put_page(page, 1);
	return ERR_PTR(-EIO);
}
```

### 修改位置

| 文件 | 行号 | 修改内容 |
|------|------|----------|
| snapshot.c | 480-536 | 新增 `snapfs_get_meta_page_timeout` 函数 |
| snapshot.c | 838-901 | `snapfs_batch_slot_overwritable` 使用超时版本 |
| snapshot.c | 919-962 | `snapfs_batch_find_free_slot` 增强日志 |

### 预期效果

| 场景 | 修改前 | 修改后 |
|------|--------|--------|
| slot header 在 writeback | 无限等待 → 阻塞 | 最多等待 2 秒 → 跳过 |
| 所有 slot 都不可用 | 全部阻塞 | 全部检查后进入等待 |
| I/O 系统繁忙 | 系统假死 | 保持一定程度的并发 |

### 问：是否退化成串行处理？

**不是完全串行化**，但会有一定程度的串行化：

| 场景 | 行为 |
|------|------|
| 所有 slot 都是 EMPTY | ✓ 并行，不受影响 |
| 部分 slot 可用 | ✓ 并行，不受影响 |
| 所有 slot IN-USE | 检查全部超时 → 等待 → 有 slot 释放后唤醒 |

修改后：
- 正常情况下（slot 可用），处理是并行的
- 高负载下（所有 slot 忙），会退化为类似串行，但不会完全卡死
- 等待的线程会在有 slot 释放后被唤醒

### 待验证

1. 重新编译模块：`make`
2. 加载模块：`insmod snapfs.ko`
3. 运行多文件并发测试
4. 观察 dmesg 日志中是否有 "get_meta_page timeout/failed, skip"
5. 观察是否仍有长时间阻塞（>120 秒）

---

*最后更新: 2026/04/23*
