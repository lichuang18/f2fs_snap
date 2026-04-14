# SnapFS 快照 COW 崩溃一致性设计

## 1. 设计目标

本文档给出 SnapFS 在**快照 COW 过程中**的崩溃一致性设计，目标是：

- 当文件第一次写触发快照 COW 时，哪怕系统在处理中途崩溃；
- 重启后，系统也能恢复到**一个一致状态**；
- 恢复后不会出现：
  - mulref 链半更新
  - SSA / summary 与 mulref 状态不匹配
  - SIT mulref 标记与实际状态不一致
  - “做到一半但无法继续”的文件级中间态
- 同时尽量降低 redo 带来的写放大和性能开销。

本文档聚焦的是：

# 文件第一次写触发的快照 COW 过程中的崩溃恢复

而不是整个 snapshot create/delete 的高层事务原子性。

---

## 2. 问题背景

当前 SnapFS 的危险点不在“创建快照目录那一刻”，而在于：

- 文件第一次写时触发 COW；
- 代码会遍历该文件的数据块；
- 对每个块更新：
  - mulref entry
  - summary / SSA
  - sit mulref 标记
- 如果处理中途崩溃，文件可能处于“部分块已处理、部分块未处理”的状态。

因此，系统需要同时解决两类问题：

## 2.1 块级一致性
某一个块在更新过程中崩溃时：
- 不能留下“mulref 已改，summary 未改”之类的撕裂状态
- 当前块必须能恢复到一个自洽状态

## 2.2 文件级进度恢复
一个文件可能有很多块，遍历处理中途崩溃时：
- 系统必须知道这个文件处理到哪里了
- 已完成的块不应重复破坏
- 未完成的块应该能继续处理

因此，**仅靠块级 redo 不够**，也**仅靠文件级状态标志不够**。

必须组合：

# 块组进度记录 + 当前块的小型 redo

---

## 3. 总体方案概览

最终设计采用：

# 块组级进度 bitmap + 当前块级 compact redo

它们合并存放在一个固定 4KB slot 中。

### 核心思想

- 不为整个文件永久保存一个大 bitmap；
- 只记录“当前正在处理的块组”的进度 bitmap；
- 只为“当前正在处理的那个块”保存一份最小 redo；
- 每次完成一个块，才把 bitmap 对应 bit 置 1；
- 崩溃恢复时：
  1. 先恢复当前块的小 redo；
  2. 然后严格从 slot 记录的 current group（`node_nid + node_ofs + valid_bits`）继续，而不是从文件头重新扫描；
  3. 在该组内根据 bitmap 找第一个未完成 bit 继续顺序处理，完成当前组后再继续后续组。

这套设计同时覆盖：

- **块级原子性**：当前块不会撕裂
- **文件级可继续性**：处理中断后知道从哪继续

---

## 4. journal 物理布局

继续保留当前：

- 从 magic 区前部保留 1 个 segment 作为 journal

布局如下：

```text
[CP][SIT][NAT][COW_JOURNAL][MAGIC_ENTRIES][MULREF_FLAG][MULREF_AREA][SSA][MAIN]
```

其中：

- `COW_JOURNAL` 使用 1 个 segment
- `MAGIC_ENTRIES`、`MULREF_FLAG`、`MULREF_AREA` 整体后移 1 个 segment

这样：
- journal 有固定位置
- 现有 magic/mulref 区域仍然保持连续管理

---

## 5. 为什么 1 个 segment 足够

journal 不是用来保存“整个文件所有块的完整 redo”。

它只保存：

1. 当前正在处理的文件信息；
2. 当前正在处理的块组进度；
3. 当前正在处理的那个块的最小 redo。

因此，每次占用：

# 1 个 4KB slot

即可。

如果：
- 1 个 segment = 512 blocks
- 每个 block = 1 个 slot

那么：

# 1 个 segment 一共有 512 个 slot

这对“同时挂起的未完成文件 COW 上下文”而言通常足够。

即便系统同时处理中多个文件，也只需为每个文件保留一个 slot，而不是为每个块保留一个 slot。

---

## 6. 为什么不能只做 redo，也不能只做 bitmap

## 6.1 只做 redo 不够
如果只记录“当前块事务”，那恢复后只能修复：
- 当前块的撕裂状态

但不知道：
- 整个文件做到第几个块组了
- 当前块组内哪些 bit 已完成
- 下一步从哪里继续

## 6.2 只做 bitmap 不够
如果只记录 bitmap：
- 知道某个 bit 还没完成
- 但如果该 bit 对应的块已经做了一半就崩了，重做这个块时仍可能出现重复更新风险

因此：

# bitmap 负责大进度，redo 负责当前块的原子提交

这是最合理的组合。

---

## 7. 当前 slot 结构设计（最终推荐）

### 7.1 设计原则

该 slot 必须同时保存：

- 当前文件是谁
- 当前块组是谁
- 当前块组的 bitmap
- 当前块的小事务最终值
- 基本状态与 crc

而且不要引入多余字段。

### 7.2 不保留 `start_lblk`

`start_lblk` 只是文件逻辑块起始编号，不是物理块地址。理论上它有意义，但不是必须字段。

为了精简结构，只保留：

- `src_ino`
- `snap_ino`
- `node_nid`
- `node_ofs`
- `valid_bits`
- `bitmap`

已经足够定位当前块组。

---

## 8. 采用 F2FS 原有语义来描述块组，而不是自定义层级

这里不要再自定义一套模糊的：
- `LEVEL_DIRECT`
- `LEVEL_INDIRECT1`
- `LEVEL_INDIRECT2`

因为 F2FS 本来就已经有成熟的描述方式。

建议尽量复用：

- `node_nid`
- `node_ofs`
- `ofs_of_node(page)`
- `get_node_path()`
- `ADDRS_PER_INODE(inode)`
- `ADDRS_PER_BLOCK(inode)`

这样当前块组的含义就变成：

- `node_nid = 0`：表示 inode 自带直址区
- `node_nid != 0`：表示某个具体 node block
- `node_ofs`：表示该 node 在 F2FS 语义中的 offset
- `valid_bits`：表示当前组实际有效 bit 数

这比自定义 layer 枚举更稳，也更容易和现有代码对应。

---

## 9. 推荐 slot 结构体

```c
struct snapfs_cow_progress_slot {
    __le32 magic;
    __le16 version;
    __le16 state;

    __le32 src_ino;      /* 正在处理的源文件 inode */
    __le32 snap_ino;     /* 对应快照文件 inode */

    __le32 node_nid;     /* 当前块组所属 node nid；inode 直址区时为 0 */
    __le16 node_ofs;     /* F2FS 语义下的 node offset */
    __le16 valid_bits;   /* 当前 bitmap 有效 bit 数：ADDRS_PER_INODE/ADDRS_PER_BLOCK */

    __u8 bitmap[128];    /* 足够覆盖最多 1018 bit */

    __u8 has_pending_txn;  /* 当前是否有已 committed 但未完成 apply 的块级事务 */
    __u8 nr_mulref_ops;
    __u8 flags;
    __u8 reserved0;

    struct snap_redo_mulref_op mulref_ops[SNAP_REDO_MAX_MULREF_OPS];
    struct snap_redo_summary_op summary_op;
    struct snap_redo_sit_op sit_op;

    __le32 crc;
} __packed;
```

---

## 10. 每个字段解释

### `magic`
识别这是 SnapFS 的进度 / redo slot。

### `version`
结构版本，后续扩展兼容用。

### `state`
当前 slot 状态。

### `src_ino`
当前正在处理的源文件 inode。

### `snap_ino`
对应快照文件 inode。

### `node_nid`
当前块组属于哪个 node。

### `node_ofs`
当前 node 的 offset，尽量使用 F2FS 原有语义，而不是重新定义层级。

### `valid_bits`
当前块组 bitmap 中有效 bit 数。
- inode 自带直址区：`ADDRS_PER_INODE(inode)`
- direct/indirect child node：`ADDRS_PER_BLOCK(inode)`

### `bitmap[128]`
当前块组内的块完成位图。
- `0`：该 bit 对应的块还未完成
- `1`：该 bit 对应的块已完成

### `has_pending_txn`
表示当前是否有一个“当前块的小事务”已经 committed 但还没彻底 apply 完。

### `nr_mulref_ops`
当前块事务中 mulref op 数量。

### `flags`
标记该块事务是否包含：
- summary 更新
- sit 更新

### `mulref_ops[]`
当前块事务中的 mulref 最终值记录。

### `summary_op`
当前块事务中的 summary 最终值记录。

### `sit_op`
当前块事务中的 sit 最终值记录。

### `crc`
保护整个 4KB slot 的一致性。

---

## 11. 状态机设计

### 11.1 状态定义

#### `EMPTY`
表示：
- 当前 slot 没有正在处理的文件
- 恢复时跳过

#### `GROUP_IN_PROGRESS`
表示：
- 当前文件有一个块组正在处理中
- 但当前没有挂起的块事务

#### `BLOCK_TXN_COMMITTED`
表示：
- 当前文件块组正在处理中
- 当前某个 bit 对应的块事务已经 durable 到 slot
- 但 home apply 可能还没完成

---

## 12. bit 的语义和置位时机

### 12.1 bit 语义
- `0`：该块还未完成
- `1`：该块已完成

### 12.2 置位时机（非常关键）
bit 必须在：

1. 当前块事务写入 slot 并 committed；
2. 当前块 home 更新已完成；
3. home flush 已完成；

之后才能置 `1`。

不能提前。

如果提前置位：
- 崩溃后会误以为该块已完成
- 实际上 home 可能只更新了一半

---

## 13. 当前块级小 redo 记录什么

当前块的小 redo 不记录增量操作，只记录最终值。

### 13.1 mulref op
- `mr_blkaddr`
- `idx`
- `valid`
- `entry`（最终 entry 内容）

### 13.2 summary op
- `data_blkaddr`
- `new_sum`

### 13.3 sit op
- `data_blkaddr`
- `set = 0/1`

这使得 replay 是幂等的：
- replay 两次不会多加计数
- 不会重复挂链
- 不会重复清/设 bit 出错

---

## 14. 恢复流程

### 14.1 恢复入口
挂载时扫描 slot。

### 14.2 情况 1：`state = EMPTY`
- 什么都不做

### 14.3 情况 2：`state = GROUP_IN_PROGRESS`
说明：
- 当前文件某个块组在处理中
- 但没有挂起块事务

恢复时：
1. 找到 `src_ino` 和 `snap_ino`
2. 通过 `node_nid + node_ofs` 直接定位到当前块组在文件遍历中的起点
3. 从该组 bitmap 找第一个 `0` bit
4. 从这个 bit 继续顺序处理该组
5. 当前组完成后，再继续后续块组

### 14.4 情况 3：`state = BLOCK_TXN_COMMITTED`
说明：
- 当前块事务已 durable
- 但可能还没完全 apply

恢复时：
1. 先 replay 当前块事务：
   - `mulref_ops[]`
   - `summary_op`
   - `sit_op`
2. flush home
3. bitmap 对应 bit 置 `1`
4. 把 slot 改回 `GROUP_IN_PROGRESS`
5. 再继续找下一个 `0` bit

---

## 15. 为什么 1 个 segment 足够

因为现在 journal 不再存：
- 多个 home block 的完整 4KB 镜像

它只存：
- 当前文件
- 当前块组 bitmap
- 当前块的小 redo

所以：

- 一个 slot = 一个文件/块组进度上下文
- 1 个 segment = 512 个 slot

通常已经足够。

即使系统同时处理多个文件，也只需要每个文件占一个 slot，而不是每个块占一个 slot。

---

## 16. interval 配置

### 16.1 配置项
当前保留：

```text
snap_redo_interval_ops
```

### 16.2 语义
#### `interval_ops = 1`
- 默认值
- 每次块事务都 durable
- 强一致模式

#### `interval_ops > 1`
- 每隔 N 次块事务才真正 durable 一次 slot
- 中间事务允许回退
- 适合用户接受回退窗口时使用

### 16.3 使用方式

```bash
cat /sys/fs/f2fs/<device>/snap_redo_interval_ops
```

```bash
echo 1 > /sys/fs/f2fs/<device>/snap_redo_interval_ops
```

```bash
echo 3 > /sys/fs/f2fs/<device>/snap_redo_interval_ops
```

写入 `0` 时自动按 `1` 处理。

---

## 17. 性能分析

### 17.1 相比 full-block redo 的收益
旧方案：
- 一个事务可能写 1 个 header block + 2~3 个 payload block
- 写放大较大

新方案：
- 一个事务只写 1 个 4KB slot
- 同时记录当前块组进度和当前块事务
- journal 写放大显著降低

### 17.2 仍然存在的开销
- 每个块事务仍需先 durable 一次 `BLOCK_TXN_COMMITTED` slot
- 当前块 home apply + flush 完成后，还需再 durable 一次 `GROUP_IN_PROGRESS + bitmap` slot
- 这两次写不能合并成一次 durable 写：前者保证“当前块最终值已落 journal”，后者保证“该 bit 仅在 home 完成后才宣告完成”
- recovery 时不需要从文件头重扫，只需先定位 current group，再在组内按 bitmap 续跑

### 17.3 关于是否能合并为一次写
对于单个块事务，journal 至少需要两个持久化阶段：

1. `BLOCK_TXN_COMMITTED`
   - 表示当前块事务最终值已经 durable 到 slot；
   - 如果随后在 home apply 途中崩溃，可以靠 slot replay 收敛。

2. `GROUP_IN_PROGRESS + bitmap(bit=1)`
   - 只能在当前块所有 home 更新及 flush 完成后写入；
   - 表示该 bit 对应的数据块引用信息更新已经真正完成。

如果把这两步合并成一次 durable 写，那么 slot 会在 home 尚未完全落盘前就宣称 bit=1，恢复时将失去“该块是否还需要 replay/补做”的依据，因此语义上不成立。

能优化的点是：
- group 不切换时，不额外写纯 progress slot；
- 恢复时直接从 current group 继续，减少无意义重扫。

### 17.4 整体评价
这是当前语义正确性与性能之间更平衡的方案。

---

## 18. 当前方案的关键优点

1. **既能知道当前块做到哪了，又能知道整个块组做到哪了**
2. **1 个 4KB slot 就足够**
3. **不需要整个文件的大 bitmap**
4. **不需要 full-block payload**
5. **恢复时不需要猜“之前做到第几个块”**
6. **语义上更适合当前顺序遍历的 COW 实现**

---

## 19. 一句话总结

最终推荐方案是：

# 用 1 个 4KB slot 同时保存“当前文件块组的进度 bitmap”和“当前块的小型 redo 事务”

其中：
- `node_nid + node_ofs + valid_bits` 用于定位当前块组；
- `bitmap` 用于表示当前块组内哪些块已完成；
- 当前块事务用 compact redo 记录最终值；
- bit 只在当前块完全 durable 后置 1；
- 默认 `interval_ops = 1` 提供强一致语义。

这套设计既能解决“处理中途崩溃后如何恢复到一致状态”，也兼顾了性能影响，是当前 SnapFS 快照 COW 崩溃恢复最合理的实现方向。
