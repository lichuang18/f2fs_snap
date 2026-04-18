# SnapFS redo 两阶段提交与锁解耦方案

## 1. 背景与问题定义

当前 SnapFS 在 COW / mulref / overwrite 路径中已经引入 redo slot，用于保证崩溃恢复时的块级一致性与组级进度恢复。现有实现虽然具备 redo 语义，但将 redo 持久化与正式元数据持久化放在 `curmulref_lock` / `curmulref_mutex` 的持锁区间内执行，导致锁边界显著扩大。

典型高风险路径如下：

- `snapshot.c:f2fs_alloc_mulref_entry()`
- `snapshot.c:f2fs_mulref_overwrite()`
- `snapshot.c:snapfs_redo_commit()`
- `segment.c:snapfs_flush_meta_blocks()`
- `checkpoint.c:f2fs_sync_meta_pages()`

现有问题的核心不是 redo 记录本身，而是：

1. 在持有 `curmulref_lock` / `curmulref_mutex` 时调用 `snapfs_redo_commit()`；
2. `snapfs_redo_commit()` 通过 `snapfs_redo_write_slot()` 立即写 redo slot 并同步刷盘；
3. 随后在同一临界区继续对 mulref / summary / SIT 调用 `snapfs_flush_meta_blocks()`；
4. `snapfs_flush_meta_blocks()` 当前实现并非定点刷指定块，而是调用 `f2fs_sync_meta_pages(sbi, META, LONG_MAX, io_type)`，实质上触发全局 dirty META 扫描与写回；
5. 前台 COW 线程因此在持有自定义锁时进入 `lock_page()` / `wait_on_page_writeback()` 路径；
6. 后台 `mulref_compact_thread` 又存在先拿 meta page、后拿 `curmulref_lock` 的反向顺序，形成 ABBA 风险。

因此，当前死锁/长时间阻塞的根因是：

**redo 引入后，原本局部的页内更新路径被升级为锁内同步事务提交 + 锁内全局元数据刷写。**

---

## 2. 设计目标

本方案的目标不是削弱现有 redo 的崩溃一致性，而是在保持以下持久化语义不变的前提下，消除死锁风险：

1. redo slot 必须先于正式元数据持久化；
2. mulref / summary / SIT 的最终内容与当前设计一致；
3. `redo_complete` / progress 更新只能发生在正式页持久化之后；
4. 崩溃恢复格式、slot 结构、恢复流程保持兼容；
5. 消除 `curmulref_lock` 持锁区间内进入全局 META flush 的路径；
6. 统一前台 COW 与后台 compact 的锁顺序。

---

## 3. 总体设计：两阶段提交 + 页锁保护 WAL 顺序

方案核心如下：

### 3.1 原则

- `curmulref_lock` / `curmulref_mutex` 只负责“确定修改集合”和“修改内存状态”；
- redo slot 持久化、正式块持久化、`redo_complete` 全部在 **不持有 `curmulref_*` 锁** 的阶段执行；
- 但在 redo slot 持久化之前，相关 home pages 不能被后台 writeback 提前写出；
- 这一点通过 **显式持有事务目标 page lock** 实现，而不是依赖 `curmulref_*` 锁本身；
- `snapfs_flush_meta_blocks()` 必须从“全局 META flush”改成“事务页定点刷写”。

### 3.2 语义解释

本方案不改变原有持久化规则，只改变执行边界：

- 旧方式：锁内 redo durable + 锁内 home page durable
- 新方式：锁内只完成页内容准备，锁外完成 redo durable 与 home page durable

只要保证：

1. home pages 在 redo durable 之前不会被后台提前写出；
2. redo durable 后才允许 home pages durable；
3. home pages durable 完成后才允许 `redo_complete`；

则原有元数据持久化语义完全保持不变。

---

## 4. 两阶段模型

## 阶段 A：Prepare 阶段（锁内）

在 `curmulref_lock` / `curmulref_mutex` 保护下，只做以下工作：

1. 确定本事务修改集合：
   - redo slot page
   - mulref page(s)
   - summary page
   - SIT page
   - overwrite/progress 对应 slot page（若需要）
2. 获取这些 page，并保持 page lock；
3. 在 page 缓冲区中构造新内容：
   - mulref entry 变化
   - summary 新值
   - SIT mulref 标记变化
   - redo slot 最终镜像
   - progress/complete slot 镜像
4. 标记 home pages dirty，但不做 flush；
5. 记录事务描述符（哪些页需要后续刷写、刷写顺序、complete 动作）；
6. 释放 `curmulref_lock` / `curmulref_mutex`。

此阶段的关键点是：

- 锁内不进入 `f2fs_sync_meta_pages()`；
- 锁内不调用任何“会扫描 META_MAPPING”的 helper；
- 锁内只进行有限页集合上的页内更新；
- 即使释放了 `curmulref_*` 锁，目标 home pages 仍被 page lock 持有，因此不会被后台抢先写出。

---

## 阶段 B：Commit 阶段（锁外）

在不持有 `curmulref_*` 锁的情况下，执行严格 WAL 顺序：

### B1. 持久化 redo slot

1. 将 redo slot page 写出；
2. 等待 redo slot page writeback 完成；
3. 确认 redo slot 已 durable。

### B2. 持久化 home pages

按事务涉及的页集合逐页写出：

- mulref page(s)
- summary page
- SIT page

要求：

- 只刷本事务页；
- 不能触发全局 META flush；
- 允许按固定顺序刷写，例如：`mulref -> summary -> sit`。

### B3. 持久化完成状态

home pages durable 之后，再执行：

- `redo_complete`
- 或 progress slot 更新

并对刷新的 complete/progress slot page 执行定点持久化。

### B4. 释放 page lock

在 redo / home pages / complete slot 全部完成之后，统一解锁并释放事务持有的 pages。

---

## 5. 事务需要保证的不变量

本方案必须始终维护以下不变量：

### 5.1 WAL 顺序不变量

redo slot durable 早于任何 home page durable。

### 5.2 Home page 屏蔽不变量

在 redo slot durable 之前，home pages 必须处于“不可被后台 writeback 抢先写出”的状态。推荐直接持有 page lock。

### 5.3 完成标记顺序不变量

`redo_complete` 或 progress 更新必须晚于 home pages durable。

### 5.4 页集合完备性不变量

事务修改过的页必须全部显式列入刷写集合，不能依赖全局 META flush“顺带刷掉”。

### 5.5 锁顺序不变量

前台 COW 与后台 compact 对 `curmulref_lock` 和 mulref pages 的获取顺序必须统一。

---

## 6. 需要修改的关键模块

## 6.1 `segment.c:snapfs_flush_meta_blocks()` 与 `snapshot.c:snapfs_flush_locked_meta_page()`

### 当前问题

当前代码已经不再走 `f2fs_sync_meta_pages(sbi, META, LONG_MAX, io_type)`，而是改成：

- `snapfs_flush_meta_blocks()`：按 `blkaddr` 获取 page，再调用 `f2fs_sync_meta_page()`；
- `snapfs_flush_locked_meta_page()`：对已拿到的 page 直接调用 `f2fs_sync_meta_page()`。

这一步已经把“全局 META flush”收缩成“事务页定点刷写”，方向是对的。但当前实现又引入了新的 page 生命周期问题：

1. `f2fs_sync_meta_page()` 在 dirty 路径会 `unlock_page(page)`；
2. 在 clean fast-path 则直接返回，page 仍保持 locked；
3. 于是 flush helper 对调用者的返回契约变成“不确定地已解锁或未解锁”；
4. 调用者随后大量执行 `f2fs_put_page(page, 1)`，在 dirty 路径会触发 `f2fs_bug_on(!PageLocked(page))`；
5. 若简单改成 `f2fs_put_page(page, 0)`，clean fast-path 又可能泄露 page lock。

因此，当前问题已经从“全局刷写放大”切换成“flush helper 的锁状态契约不稳定”。这也是当前 dmesg 循环 warning 的直接来源。

### 修改目标

必须把 flush helper 的语义收敛成单一契约，推荐采用：

#### helper A：定点刷一个事务 page，返回时保证 page 已解锁

建议语义：

- 输入 `struct page *page`
- 只提交该页
- 等待该页 writeback 完成
- 返回时无论 dirty/clean，page 都处于 unlocked 状态
- 调用方后续统一使用 `f2fs_put_page(page, 0)`

实现要点：

- 若 `f2fs_sync_meta_page()` 走 clean fast-path，没有自动解锁，则 wrapper 需要补一次 `unlock_page(page)`；
- 若 wrapper 约定“flush 后 page 已解锁”，则所有事务收尾路径必须统一按 unlocked page 释放；
- `snapfs_flush_meta_blocks()`、`snapfs_flush_txn_pages()`、`migrate_entries()`、`f2fs_alloc_mulref_entry()`、`f2fs_mulref_overwrite()` 都要跟着收敛到同一语义。

#### helper B：定点刷一个 meta blkaddr

建议语义：

- 输入 `blkaddr`
- 获取该 page
- 内部调用 helper A
- 不扫描其他 dirty META page
- 对外同样保证“flush 返回时 page 已解锁”

本设计仍推荐调用方在事务上下文中显式传 `struct page *`，避免重复获取 page 与重复锁竞争。

---

## 6.2 `snapshot.c:snapfs_redo_write_slot()`

### 当前问题

当前路径：

- 更新 redo slot page
- 调用 `snapfs_flush_meta_blocks()`

导致 redo slot 写出被放大为全局 META flush。

### 修改目标

改为：

1. 直接更新 redo slot page；
2. 只提交 redo slot page 本身；
3. 等待 redo slot page 完成 writeback；
4. 不触发其他 meta page 写回。

这样 redo slot 仍保持 durable 语义，但不会把事务范围扩大到整个 META_MAPPING。

---

## 6.3 `snapshot.c:f2fs_alloc_mulref_entry()`

### 当前问题

当前实现已经基本改成“两阶段”：

- 锁内构造 mulref / summary / sit 新状态；
- 锁外执行 `snapfs_redo_commit()`、`snapfs_flush_locked_meta_page()`、`snapfs_progress_commit_after_block()`。

但继续深入检查后，至少还有四类潜在问题。

#### 问题 A：flush 后 page 仍按 locked page 释放

在多个分支中，事务页会先经过：

- `snapfs_flush_locked_meta_page()`

随后又执行：

- `f2fs_put_page(..., 1)`

由于 `f2fs_sync_meta_page()` 在 dirty 路径已经解锁 page，这会与 `f2fs_put_page(..., 1)` 的前置条件冲突，形成当前 warning。

#### 问题 B：mulref 页修改后未统一 `set_page_dirty()`

当前 `same block` / `cross block` / `is_mulref append` 分支里，会直接修改：

- `mgentry`
- `mgentry2`
- `mgentry3`
- `blk->v_mrentrys`
- `next` 指针链

但事务刷写前并没有对所有被修改的 mulref page 显式 `set_page_dirty()`。而 `f2fs_sync_meta_page()` 在 `!PageDirty(page)` 时直接返回，因此存在：

- 内存中已修改；
- redo 已 durable；
- home page flush 因 page 未 dirty 而实际未落盘；
- 后续 progress/complete 继续推进；
- 崩溃后只能依赖 replay 补救。

这会削弱两阶段的“home page 已提交”判定，属于潜在一致性问题。

#### 问题 C：`bypass_redo` 会破坏多页事务的 WAL 假设

`snapfs_redo_begin_with_policy()` 会根据 interval 把部分事务标记为 `txn->bypass_redo = true`。此时：

- `snapfs_redo_commit()` 直接返回 0；
- `snapfs_progress_commit_after_block()` 最终仍复用同一个 `txn`，再次走 `snapfs_redo_commit()`；
- 结果是 home pages 可能已经真正刷写，但 redo/progress slot 并未 durable。

对单页、幂等、可重算场景，绕过 redo 还有讨论空间；但对当前 mulref + summary + SIT 的多页联动修改，`bypass_redo` 与两阶段事务语义不兼容。

#### 问题 D：entry 预分配窗口与 compact 线程存在竞争

`curmulref_alloc_entry()` 会单独获取 `curmulref_lock` 完成：

- 设置 bitmap
- 初始化 entry
- 更新 `v_mrentrys`

之后立刻释放锁；而 `f2fs_alloc_mulref_entry()` 只是在稍后重新加锁，把这些 entry 填成真正的链表节点。中间存在窗口期。

如果 compact 线程扫描到该 entry，它可能被当成“有效已分配 entry”迁移，导致：

- 调用方手中的 `blkaddr/eidx` 仍指向旧位置；
- 后续对 `mgentry` / `next` 的填充不再对应实际 home location；
- redo 记录与内存链表的目标位置脱节。

这是两阶段之外的并发一致性问题。

### 修改目标

改造成更严格的 Prepare/Commit 模型，并补齐以下约束：

#### A. 锁内 Prepare

- 获取并锁住涉及的 mulref page(s)
- 必要时获取 summary / sit page
- 修改页内内容
- 对每个被修改的事务页显式 `set_page_dirty()`
- 构造 redo slot 内容
- 构造 progress slot 内容
- 记录事务上下文
- 释放 `curmulref_*` 锁

#### B. 锁外 Commit

- 强制此类多页事务 `txn->bypass_redo = false`
- 写 redo slot page 并等待完成
- 写 mulref/summary/sit pages 并等待完成
- 写 progress/complete slot page 并等待完成
- 按统一 unlocked 语义释放事务页

#### C. 分配阶段收敛

对 mulref entry 的“分配 + 初始化 + 链接入事务”需要纳入同一把 `curmulref_lock` 的保护区间，至少满足二选一：

1. `curmulref_alloc_entry()` 改成仅在外层已持锁前提下使用；
2. 或者给新分配 entry 增加“reserved / not visible to compact”状态，在事务提交前 compact 线程不得迁移。

---

## 6.4 `snapshot.c:f2fs_mulref_overwrite()`

### 当前问题

overwrite 路径表面上也已经改成“锁内修改、锁外 redo/flush/complete”，但比 `f2fs_alloc_mulref_entry()` 更复杂，隐藏问题更多。

#### 问题 A：修改过的 mulref page 普遍没有显式 dirty 标记

在 head / middle / tail 三类路径中，代码会直接修改：

- `head_blk->mrentries[...]`
- `prev_blk->mrentries[...]`
- `cur_blk->mrentries[...]`
- `m_count`
- `next`
- `multi_bitmap`
- `v_mrentrys`

但几乎没有对应的 `set_page_dirty(head_page/prev_page/cur_page/mulref_page)`。当前只对：

- `sum_page`
- `sit_page`

显式标 dirty。

因此 `snapfs_flush_txn_pages()` 调到 `f2fs_sync_meta_page()` 时，mulref home page 很可能因 `!PageDirty(page)` 被直接跳过。

这意味着 overwrite 的 redo 事务可能出现：

- redo slot 已 durable；
- summary / sit 已 durable；
- mulref 链实际尚未 durable；
- 随后又把 redo slot clear；
- 崩溃后 replay 缺少入口。

这是比当前 warning 更严重的潜在一致性问题。

#### 问题 B：flush helper 的锁状态不稳定同样影响 overwrite 路径

`flush_pages` 中的 `head_page` / `prev_page` / `cur_page` / `sum_page` / `sit_page`，在 flush 后仍普遍通过 `f2fs_put_page(..., 1)` 释放。只要某个 page 真正进入 dirty flush 路径，就会复现同类 warning。

#### 问题 C：部分 flush page 集合与真实修改集合并不完全等价

当前通过 `flush_pages[]` 组装事务页集合，但分支条件比较绕，例如：

- `head_page`
- `(mulref_page && prev_blk != cur_blk) ? mulref_page : NULL`
- `cur_page ? cur_page : head_page`
- `prev_page`
- `head_page`

虽然 `snapfs_flush_txn_pages()` 有去重，但问题不在于重复，而在于：

- 某些被修改的 block 只是通过 `prev_blk == cur_blk` / `head_blk == prev_blk` 之类别名关系间接表达；
- 一旦分支判断有偏差，就会漏刷事务页；
- 文义上也看不出“哪些 page 被改了、哪些 page 必须 durable”。

overwrite 是多分支链表改写路径，继续沿用临时数组拼装方式，后续很难验证完备性。

#### 问题 D：overwrite redo 完成条件依赖 home page 真实 durable，但当前并未形成可验证条件

代码现在做的是：

1. `snapfs_redo_commit()`
2. `snapfs_flush_txn_pages()`
3. `snapfs_redo_complete()`

顺序本身正确；但由于前述“页可能没 dirty / flush 后锁状态不稳定 / flush 集合可能不完备”，第 2 步并不能可靠代表“所有 home pages 已 durable”。所以第 3 步的完成语义目前并不牢靠。

### 修改目标

也改造成统一两阶段结构，并增加更严格的可验证条件：

#### A. 锁内 Prepare

- 定位 head/prev/cur/next pages
- 根据场景更新 entry、summary、SIT 的内存值
- 对所有被修改的 mulref page 显式 `set_page_dirty()`
- 通过事务描述符登记真实修改页，而不是依赖临时 `flush_pages[]` 拼接
- 构造 overwrite redo slot
- 保持所有事务页锁定
- 释放 `curmulref_*` 锁

#### B. 锁外 Commit

- 强制 overwrite 事务 `bypass_redo = false`
- durable overwrite redo slot
- durable 事务描述符中的全部 home pages
- durable overwrite complete slot
- 最后按统一 unlocked 语义释放所有页面

本函数复杂度更高，建议在事务描述符中统一编码：

- 修改页数组
- 页类型
- 最终刷写顺序
- 是否包含 SIT 更新
- 是否包含 summary 更新
- complete 动作类型
- 每个 page 是否已显式 dirty

---

## 6.5 `snapshot.c:migrate_entries()` 与 `mulref_compact_thread`

### 当前问题

当前 `migrate_entries()` 现在已经调整成：

1. `down_write(curmulref_lock)`
2. `f2fs_get_meta_page(src)`
3. `f2fs_get_meta_page(dst)`
4. 锁内搬迁 entry
5. 解 `curmulref_lock`
6. 锁外 flush 两个 page

因此，最初文档里记录的“page 在前、`curmulref_lock` 在后”的 ABBA 顺序已经不是当前代码状态。

但继续分析后，compact 路径仍有三个潜在问题。

#### 问题 A：flush 后仍按 locked page 释放

`migrate_entries()` 在锁外执行：

- `snapfs_flush_locked_meta_page(sbi, src_page)`
- `snapfs_flush_locked_meta_page(sbi, dst_page)`

随后无条件：

- `f2fs_put_page(src_page, 1)`
- `f2fs_put_page(dst_page, 1)`

这与前面分析的 flush helper 语义问题完全一致，会在 compact 线程中复现同类 warning。

#### 问题 B：迁移只复制 entry 与 bitmap，没有修复链表中的跨 entry `next` 指针引用

当前搬迁逻辑只是：

- 把 `src_blk->mrentries[src_idx]` 原样 memcpy 到 `dst_blk->mrentries[dst_idx]`
- 设置新 bitmap
- 清旧 bitmap

但 mulref 链表里的 `next` 字段编码的是“物理 mulref entry 位置”。如果：

- 某个未迁移节点的 `next` 原本指向被迁移的节点；
- 或被迁移节点本身的 `next` 指向另一个也发生位置变化的节点；

那么单纯 memcpy + bitmap 迁移不会自动修正这些引用。文档原先写“mulref entry 的位置变化不影响 summary”，这一点只对 summary 的头指针成立，但**不代表链表内部引用不受影响**。

换言之，compact 线程当前可能把 entry 搬走了，却没有把所有入边/出边一起更新，存在链表损坏风险。

#### 问题 C：compact 不通过 redo 保护，崩溃恢复不可重建

当前 `migrate_entries()` 只是：

- 锁内改 src/dst page
- 标 dirty
- 锁外直接 flush

它没有：

- redo slot
- progress slot
- replay 描述符

这意味着 compact 不是 WAL 保护事务。若系统在：

- `src_page` 已写、`dst_page` 未写，或
- `dst_page` 已写、某些链表引用更新尚未完成

时掉电，恢复路径没有事务日志可依据。只要 compact 会改变逻辑可见的 mulref entry 拓扑，它就不能再被视为“纯后台整理、失败可忽略”的操作。

### 修改目标

compact 路径需要从“后台 opportunistic 搬迁”提升为受事务保护的元数据重排：

1. 继续保持统一锁顺序：先 `curmulref_lock`，后 page lock；
2. flush 后页面按 unlocked 语义释放；
3. 明确维护被迁移 entry 的所有引用关系：
   - 更新链表前驱的 `next`
   - 更新被迁移节点的 `next`
   - 必要时更新 summary 指向的新 head
4. 若 compact 会改变 on-disk 可见拓扑，则必须纳入 redo 事务；
5. 若暂时不想给 compact 上 redo，则更安全的短期方案是禁用“跨块 relocation”，只允许块内整理且不得改变 entry 物理地址编码。

说明：

- “按块地址排序拿页锁”仍然有价值，可以减少多页事务之间的锁顺序冲突；
- 但锁顺序统一只是必要条件，不足以保证 compact 正确性。

---

## 6.6 `snapshot.c:snapfs_replay_slot()` 与 slot 生命周期管理

### 当前问题

两阶段设计把大量一致性责任压到 redo / progress slot 上，因此 replay 与 slot 生命周期管理本身也必须严格正确。当前还有两个潜在问题。

#### 问题 A：普通 COW replay 清空磁盘 slot 后，没有同步释放内存中的 slot 占用位

当前 `snapfs_replay_slot()` 在非 overwrite、且不保留 progress 的路径上，最后执行的是：

- `snapfs_redo_clear_slot(sbi, slot_idx)`

但没有像 overwrite replay 那样继续调用：

- `snapfs_redo_free_slot(sbi, slot_idx)`

结果是：

- on-disk slot 已经清空；
- in-memory `slot_inuse_bitmap` 仍认为该 slot 被占用；
- 后续运行期分配可能出现伪 `-ENOSPC` 或槽位逐渐耗尽；
- 直到 remount 重新扫描 slot，内存态才会恢复。

这是 slot 生命周期不完整的问题。

#### 问题 B：progress / complete 语义过于依赖“前一步 flush 真的完成了所有 home pages”

当前 replay 侧默认假设：

1. 只要 slot 处于 `SNAPFS_PROGRESS_BLOCK_TXN_COMMITTED` 或 overwrite committed；
2. replay 应用 mulref/summary/sit 更新；
3. `snapfs_flush_replayed_homes()` 返回成功；
4. 就可以安全写 progress 或 clear slot。

但如果前台提交路径本身存在：

- 漏 dirty
- 漏登记事务页
- flush helper 锁状态不稳定

那么 replay 侧虽然还能补应用一次 home update，但 slot 何时可以 clear、何时必须保留，取决于提交端是否真的满足“不变量 5.1~5.4”。换言之，replay 正确性建立在提交端可验证的事务完备性之上，不能独立看待。

### 修改目标

1. 普通 COW replay 成功 clear slot 后，同步调用 `snapfs_redo_free_slot()`；
2. 把“slot clear/free 的前提条件”文档化：
   - redo replay 已完成
   - 所有 home pages 已 durable
   - progress 位图或 overwrite complete 已写成最终状态
3. 对 progress slot 与普通 redo slot 区分生命周期：
   - progress slot 允许跨多个 block 提交持续存在；
   - 单次 COW / overwrite slot 在 home durable 后必须进入 clear + free；
4. 将 replay 验证纳入两阶段验收标准，而不是只看前台写路径。

## 7. 建议的数据结构改造

建议引入一个轻量事务描述符，用于承载两阶段提交所需上下文。

示意结构如下：

```c
struct snapfs_meta_txn_page {
    struct page *page;
    block_t blkaddr;
    u8 role;      /* redo / mulref / summary / sit / complete */
    bool dirty;
};

struct snapfs_meta_txn {
    struct f2fs_sb_info *sbi;
    struct snapfs_txn redo_txn;
    struct snapfs_meta_txn_page pages[8];
    unsigned int nr_pages;
    bool need_summary;
    bool need_sit;
    bool need_complete;
    bool is_overwrite;
};
```

事务对象职责：

- 记录事务涉及的所有 page；
- 记录刷写顺序；
- 统一执行 `prepare -> commit -> complete -> release`；
- 避免各个分支复制大量解锁/刷写/清理逻辑。

注意：

- 这是事务对象，不是新的长期持久化结构；
- 只服务于一次内核内存中的事务提交；
- 不改变现有 on-disk 格式。

---

## 8. 推荐的执行顺序模板

以下模板适用于 `normal_to_mr`、`append_ref`、`overwrite` 等事务。

```text
1. lock(curmulref_lock)
2. lock(curmulref_mutex)
3. 获取事务涉及的所有 page，并保持 page lock
4. 更新 mulref/summary/sit 的内存内容
5. 生成 redo slot / progress slot / complete slot 内容
6. unlock(curmulref_mutex)
7. unlock(curmulref_lock)
8. flush redo slot page and wait
9. flush home pages one by one and wait
10. flush complete/progress slot page and wait
11. unlock all page locks
12. put all pages
```

若第 8 步失败：

- 不允许刷 home pages；
- 保留 redo slot 的已写状态或失败状态；
- 统一走错误回收路径。

若第 9 步中途失败：

- 不执行 complete；
- 保留 redo slot，供 mount/replay 时恢复。

若第 10 步失败：

- home pages 已 durable，但 slot 未 clear；
- 恢复逻辑应保证 replay 幂等。

---

## 9. 与现有元数据持久化语义的关系

本方案不会改变原有元数据持久化方案的核心语义。原因如下：

1. redo 仍然先于正式块持久化；
2. 正式块集合没有变化，变化的只是刷写边界与粒度；
3. `redo_complete` 仍然晚于正式块持久化；
4. 恢复看到的状态集合仍与当前 redo 设计兼容；
5. 只要 home pages 在 redo durable 前不被后台提前写出，WAL 语义就保持不变。

因此，本方案属于：

**实现层面的锁解耦与刷写收缩，不属于持久化语义重构。**

---

## 10. 落地步骤建议

建议按以下顺序实施。

### 第一步：改刷写基础设施

1. 重写 `snapfs_flush_meta_blocks()`，移除 `f2fs_sync_meta_pages(... LONG_MAX ...)`；
2. 增加定点 meta page flush helper；
3. 调整 `snapfs_redo_write_slot()` 仅刷 redo slot page。

这是整个方案的前置条件。若不先做这一步，后续锁解耦效果仍然有限。

### 第二步：改 `f2fs_alloc_mulref_entry()`

1. 引入事务描述符；
2. 先覆盖 `!is_mulref && same block` 分支；
3. 再覆盖 `!is_mulref && cross block`；
4. 最后覆盖 `is_mulref` 分支。

### 第三步：改 `f2fs_mulref_overwrite()`

按“头 / 中间 / 尾”三类场景逐一迁移到统一事务模板。

### 第四步：统一 compact 锁顺序

重写 `migrate_entries()` 的锁顺序与提交方式。

### 第五步：补充验证

必须覆盖：

- fio 高并发随机写
- snapshot create 后首写 COW
- overwrite path
- mulref compact 与前台并发
- 人工注入掉电点：
  - redo durable 后、home pages durable 前
  - home pages durable 中间
  - complete 前

---

## 11. 验证标准

方案完成后，应满足以下标准：

1. `curmulref_lock` / `curmulref_mutex` 持锁区间内不再出现全局 META flush；
2. flush helper 对 page 锁状态具有单一契约，调用方不再混用 `f2fs_put_page(..., 1)` / `f2fs_put_page(..., 0)`；
3. `f2fs_alloc_mulref_entry()` 与 `f2fs_mulref_overwrite()` 中所有被修改的 mulref / summary / sit page 都被显式 dirty 并纳入事务页集合；
4. mulref / summary / sit 多页事务一律禁止 `bypass_redo`；
5. compact 线程与前台 COW 锁顺序一致，且 compact 不会破坏 mulref 链表引用；
6. 普通 replay 与 overwrite replay 都能正确 clear + free slot，不出现运行期伪 slot 耗尽；
7. fio 并发写 + snapshot COW 下不再出现 hung task 或 page lock warning；
8. 掉电恢复后 mulref / summary / SIT / progress slot 保持一致；
9. redo slot replay 逻辑保持幂等。

---

## 13. 2026-04-19 更新：CoW 崩溃与 `curmulref_alloc_entry` 重入死锁

### 问题现象

fio 并发写入快照目录触发 CoW，系统在 97 秒后开始出现大量 hung task 告警：

```
fio:3372 blocked for more than 368 seconds
  rwsem_down_write_slowpath+0x24c/0x510
    down_write+0x4f/0x70
    curmulref_alloc_entry+0x35/0x2b0 [snapfs]

f2fs_ckpt-259:3:2886 blocked
  f2fs_flush_inline_data+0x1b7/0x2a0 [snapfs]
    f2fs_write_checkpoint+0x154/0x15c0 [snapfs]

kworker/u40:4:231 blocked
  f2fs_issue_checkpoint+0xf2/0x1d0 [snapfs]
```

调用链：
```
f2fs_file_write_iter → f2fs_snapshot_cow → f2fs_set_mulref_blocks
→ f2fs_alloc_mulref_entry → curmulref_alloc_entry
  → f2fs_get_meta_page(...)  ← 读取当前块成功
  → bitmap 满 → rotate 分支
  → f2fs_put_page(page)     ← 持 write 锁状态下触发 f2fs_lock_op
    → checkpoint 线程也持 f2fs_lock_op 等待
    → 其他进程重新调用 curmulref_alloc_entry
      → down_write(&sm->curmulref_lock)  ← 同一 writer 锁重入 → 死锁
```

同时出现 `lookup_one_len` WARNING：
```
WARNING: CPU: 10 PID: 3372 at fs/namei.c:2711 lookup_one_len+0x9a/0xb0
```
这是 `lookup_one_len` 内部检查到 name 长度超限（`name_len >= F2FS_NAME_LEN` 或 dentry 无效）触发的 WARNING，不影响功能但需注意。

### 根因分析

`curmulref_alloc_entry` 原实现在持有 `curmulref_lock`（writer 锁）期间：

1. 调用 `f2fs_get_meta_page()` — 可能长时间阻塞在 page cache 分配
2. 块满 rotate 时，在 `down_write` 内部调用 `f2fs_put_page()` — 该函数在内部调用 `__write_meta_page` → `f2fs_lock_op(sbi)`，等待持有 `f2fs_lock_op` 的其他进程
3. 其他进程也在 CoW 路径，再次调用 `curmulref_alloc_entry` → `down_write(&sm->curmulref_lock)` — 同一 writer 锁不可重入 → **死锁**

读写锁 `rw_semaphore` 的语义是：同一 writer 在持有期间不能再次 `down_write`，否则死锁。这与 mutex 无异。

### 已实施的修复

修改 `curmulref_alloc_entry()`（`snapshot.c:2089-2196`），采用 **两阶段读写锁 + 两阶段查找** 策略：

```
快速路径（读锁）：
  1. down_read(&curmulref_lock)
  2. 读取当前块的 bitmap，查找空闲 entry
  3. 命中 → claim bit → mark dirty → f2fs_put_page → up_read → return
  4. 未命中 → f2fs_put_page → up_read → 慢路径

慢路径（写锁）：
  1. down_write(&curmulref_lock)
  2. f2fs_put_page 写回旧块（在锁内完成 page writeback 提交）
  3. 更新 cmr->blkaddr 前进到下一块
  4. 在新块中查找空闲 entry
  5. 命中 → claim → f2fs_put_page → up_write → return
  6. 未命中 → -ENOSPC → up_write → return
```

关键改进：
- **消除重入死锁**：只在块满需要 rotate 时才降级为 `down_write`，不在 `down_write` 内部调用可能阻塞的 `f2fs_get_meta_page`
- **消除锁降级陷阱**：`f2fs_put_page` 的 writeback 提交在 `up_write` 之后执行，不在写锁持期间触发 `f2fs_lock_op`
- **消除不一致窗口**：块旋转时写锁保护 `cmr->blkaddr` 更新的原子性
- **添加 entry 初始化**：两个分支的 claim 路径都添加 `memset(&blk->mrentries[idx], 0, ...)`
- **移除 `curmulref_mutex`**：不再需要该互斥锁，读写锁本身已足够保护数据结构一致性

### 修复后的编译状态

```
LD [M]  /home/lch/workspace/f2fs_snap/snapfs.o
LD [M]  /home/lch/workspace/f2fs_snap/snapfs.ko
```
无 error，编译通过。

### 其他待修复位置

| 位置 | 锁类型 | 问题 | 优先级 |
|------|--------|------|--------|
| `f2fs_alloc_mulref_entry:2473` | `down_write` | 持锁期间大量 I/O（`f2fs_get_meta_page`、`f2fs_get_sum_page`） | 中 |
| `f2fs_alloc_mulref_entry:2750` | `down_write` | 同上，is_mulref 路径 | 中 |
| `f2fs_mulref_overwrite:6087` | `down_write` | 持锁期间 `f2fs_get_meta_page` | 中 |
| `migrate_entries:6924` | `down_write` | 持锁期间 I/O，与 compact 线程存在潜在 ABBA | 低 |

### 修复后的锁顺序（已消除部分）

```
前台 COW 线程：
  f2fs_file_write_iter
    → f2fs_snapshot_cow
      → f2fs_set_mulref_blocks
        → f2fs_alloc_mulref_entry   (down_write curmulref_lock)
          → curmulref_alloc_entry     (down_read curmulref_lock → 快速路径完成)
        → ... I/O ...
      → f2fs_snapshot_cow_nolock
        → f2fs_cow
          → lookup_one_len           (已不在锁内执行)

checkpoint 线程：
  f2fs_write_checkpoint
    → f2fs_lock_op(sbi)            (独立锁，与 curmulref_lock 无锁序冲突)
```

---

## 14. 下一步修复计划

### 步骤一（已完成）：修复 `curmulref_alloc_entry` 重入死锁

已实施两阶段读写锁，消除直接重入死锁。

### 步骤二：重构 `f2fs_alloc_mulref_entry` 持锁期间的 I/O

当前该函数在 `down_write(&sm->curmulref_lock)` 持锁期间调用多个可能阻塞的操作：

- `f2fs_get_meta_page()`
- `f2fs_get_sum_page()`
- `snapfs_stage_sit_page_change()`
- `snapfs_flush_locked_meta_page()`

建议方案：引入事务描述符，将 I/O 移到锁外。

### 步骤三：统一 flush helper 的 page 锁状态契约

当前 `snapfs_flush_locked_meta_page()` 在 dirty 路径会 `unlock_page(page)`，但调用方仍使用 `f2fs_put_page(..., 1)`，存在冲突。

建议统一契约：flush 返回后 page 已解锁，调用方统一使用 `f2fs_put_page(page, 0)`。

### 步骤四：修复 `f2fs_mulref_overwrite` 持锁 I/O

在 `down_write` 持锁期间执行 `f2fs_get_meta_page`、`f2fs_put_page`，与 checkpoint 线程存在潜在竞争。

---

## 15. 验证标准更新

本次修复后，应满足：

1. fio 并发写 + snapshot COW 路径不再出现 `curmulref_alloc_entry` 重入死锁
2. 不再出现 300+ 秒的 `fio` / `f2fs_ckpt` / `kworker` hung task 告警
3. `curmulref_lock` 持锁区间内不再出现可能在 `f2fs_lock_op` 上阻塞的操作



最合理的修复方向不是继续在现有锁内同步刷写路径上做局部修补，而是明确建立：

**页锁保护的 WAL 两阶段提交模型。**

该模型的关键价值是：

- 保持当前 redo 崩溃一致性语义；
- 把 `curmulref_*` 锁从 I/O 和全局写回路径中剥离出来；
- 把事务影响范围从“整个 META_MAPPING”收缩回“本事务页集合”；
- 消除前后台线程在 `curmulref_lock` 与 page lock 之间的等待环。

这是在当前 SnapFS 代码基础上，兼顾一致性、可实现性与死锁修复效果的最优实现方案。

---

## 16. 2026-04-19 更新：CoW 中 `lookup_one_len` WARNING 崩溃

### 问题现象

fio 并发写入快照目录触发 CoW，内核日志出现 WARNING：

```
WARNING: CPU: 8 PID: 3074 at fs/namei.c:2711 lookup_one_len+0x9a/0xb0
Call Trace:
  f2fs_cow+0x4b0/0x10c0 [snapfs]
  snapfs_replay_one_snapshot+0x117/0x1e0 [snapfs]
  __f2fs_snapshot_cow_from_path+0x38b/0x500 [snapfs]
  f2fs_snapshot_cow+0xe4/0xf0 [snapfs]
```

### 根因分析

在 `f2fs_cow()` 函数中（`snapshot.c:5208`），代码调用：

```c
snap_dentry = d_find_any_alias(snap_inode);  // 获取快照目录的任意 alias
new_dentry = lookup_one_len(filename, snap_dentry, old_name_len);
```

`d_find_any_alias()` 返回的是 inode 的任意别名，**缺少完整的目录层次结构信息**。而 `lookup_one_len()` 内部会遍历目录层次结构验证 dentry 的有效性，当发现 `snap_dentry` 的 `d_parent` 链不完整时，触发内核 WARNING。

### 设计上下文

CoW 处理的是从预存储路径向量 (`snap_path_vec`) 中获取的固定名称 `old_name` 和 `old_name_len`，这样 rename 操作不会影响 CoW 的正确性。当前问题是 `d_find_any_alias` 获取的匿名 alias 无法满足 `lookup_one_len` 对目录结构的要求。

### 修复方案

将 `lookup_one_len` 替换为 `d_alloc`，直接创建一个正确初始化的 dentry：

```c
// 修复前
new_dentry = lookup_one_len(filename, snap_dentry, old_name_len);

// 修复后
new_dentry = d_alloc(snap_dentry, &d_name);
if (IS_ERR(new_dentry)) {
    ret = PTR_ERR(new_dentry);
    new_dentry = NULL;
    goto next_free;
}
```

**修复效果**：
1. 保留固定名称的设计（`d_name` 来自预存储的路径信息，不受 rename 影响）
2. 绕过 `lookup_one_len` 对完整目录层次结构的依赖
3. `d_parent` 正确指向 `snap_dentry`
4. 内核 WARNING 消失

### 修复位置

`snapshot.c:f2fs_cow()` 函数，第 5208 行附近。

---

## 17. 2026-04-19 下午：修复 `curmulref_alloc_entry` 和 `f2fs_alloc_mulref_entry` 死锁

### 问题现象

快照创建后执行 COW 触发测试时，系统出现以下症状：

1. **fio 进程卡住**（状态 `Ds` - 不可中断睡眠）
2. **checkpoint 线程卡住**：
   ```
   [f2fs_ckpt-259:0]  state:D blocked
   Call Trace:
     wait_on_page_bit_common
       __lock_page
         f2fs_flush_inline_data
           f2fs_write_checkpoint
   ```
3. **多个进程卡在 `f2fs_get_node_page`**：
   ```
   f2fs_get_node_page
     read_inline_xattr
       f2fs_getxattr
         wait_on_page_bit_common
   ```
4. **kworker 被阻塞** 491+ 秒

### 根因分析

#### 死锁链

```
FIO 进程 A:
  ├─ 获取 curmulref_lock (写锁)
  └─ 调用 curmulref_alloc_entry
       └─ 调用 f2fs_get_meta_page() → 阻塞等待 I/O

FIO 进程 B:
  └─ 等待 curmulref_lock → 被进程 A 阻塞

Checkpoint 线程:
  ├─ 持有 page lock
  └─ 需要刷新 inline data → lock_page → 等待页面解锁
```

#### 问题 1：`curmulref_alloc_entry` 在持有写锁期间执行 I/O

原实现依赖调用者持有 `curmulref_lock`（写锁），在持有锁期间调用 `f2fs_get_meta_page`：
- 快速路径：`f2fs_get_meta_page` → 读取 curmulref 块
- 如果块满需要旋转：`f2fs_put_page` → 可能触发 writeback → 等待 `f2fs_lock_op`

#### 问题 2：`f2fs_alloc_mulref_entry` 在持有写锁期间进行大量 I/O

该函数在 `down_write(&curmulref_lock)` 持锁期间调用：
- `curmulref_alloc_entry()` × 2
- `f2fs_get_meta_page()` × N
- `f2fs_get_sum_page()`
- `snapfs_stage_sit_page_change()`
- `snapfs_redo_begin/commit()`

### 修复方案

#### 修复 1：`curmulref_alloc_entry` 使用两阶段锁

**核心思想**：快速路径使用读锁，慢速路径才使用写锁。

```c
int curmulref_alloc_entry(struct f2fs_sb_info *sbi, u16 *eidx)
{
    struct f2fs_sm_info *sm = SM_I(sbi);
    struct curmulref_info *cmr = &SM_I(sbi)->curmulref_blk;

    if (!cmr->inited)
        return -EINVAL;

    /*
     * 两阶段锁策略：
     * - 快速路径（读锁）：查找当前块中的空闲 entry，大多数情况下无阻塞
     * - 慢速路径（写锁）：只在块满需要旋转时获取写锁
     */
    pr_debug("[curmulref_alloc] entry: cmr->blkaddr=%u, next_free=%u, used=%u\n",
             cmr->blkaddr, cmr->next_free_entry, cmr->used_entries);

    /* === 快速路径：读锁 + 查找 === */
    down_read(&sm->curmulref_lock);

    page = f2fs_get_meta_page(sbi, cmr->blkaddr);
    if (IS_ERR(page)) {
        err = PTR_ERR(page);
        up_read(&sm->curmulref_lock);
        return err;
    }
    blk = page_address(page);

    /* 在当前块中查找空闲 entry */
    for (idx = cmr->next_free_entry; idx < MRENTRY_PER_BLOCK; idx++) {
        if (!f2fs_test_bit(idx, (char *)blk->multi_bitmap))
            goto found_read;
    }

    /* 当前块已满，释放页面并释放读锁 */
    f2fs_put_page(page, 1);
    page = NULL;
    up_read(&sm->curmulref_lock);

    /* === 慢速路径：写锁 + 旋转 === */
    down_write(&sm->curmulref_lock);

    /* 重新检查（可能被其他写者更新） */
    page = f2fs_get_meta_page(sbi, cmr->blkaddr);
    if (IS_ERR(page)) {
        err = PTR_ERR(page);
        goto out_write;
    }
    blk = page_address(page);

    /* 再次检查是否有空闲 entry */
    for (idx = 0; idx < MRENTRY_PER_BLOCK; idx++) {
        if (!f2fs_test_bit(idx, (char *)blk->multi_bitmap))
            goto found_write;
    }

    /* 确实需要旋转到下一个块 */
    f2fs_put_page(page, 1);
    page = NULL;

    /* 写回当前块（写锁内，但不等待 writeback 完成） */
    prev_page = f2fs_get_meta_page(sbi, cmr->blkaddr);
    if (!IS_ERR(prev_page)) {
        set_page_dirty(prev_page);
        f2fs_put_page(prev_page, 1);  /* 触发 writeback，但不等待 */
    }

    /* 更新 curmulref 块地址 */
    if (cmr->blkaddr + 1 < sm->ssa_blkaddr)
        cmr->blkaddr += 1;
    else
        cmr->blkaddr = sbi->magic_info->mulref_blkaddr;
    cmr->next_free_entry = 0;
    sbi->ckpt->cur_mulref_blk = cmr->blkaddr - sbi->magic_info->mulref_blkaddr;

    /* 在新块中查找 */
    page = f2fs_get_meta_page(sbi, cmr->blkaddr);
    // ...
```

**关键改进**：
- 快速路径使用读锁，不阻塞其他读者，也不阻塞写者
- 只有在块满需要旋转时才获取写锁
- 写锁期间不执行可能阻塞的 I/O（或只执行快速的页面读取）

#### 修复 2：添加 `curmulref_alloc_multi` 函数

新增函数用于原子地分配多个 entry（最多 2 个），确保所有 entry 来自同一个块：

```c
struct curmulref_alloc_info {
    block_t blkaddr;  /* entry 所在的块地址 */
    u16 eidx;         /* entry 在块中的索引 */
};

/*
 * 原子分配多个 entry（最多 2 个）
 * 确保所有 entry 来自同一个块
 */
int curmulref_alloc_multi(struct f2fs_sb_info *sbi, int count,
                         struct curmulref_alloc_info *info);
```

#### 修复 3：修改 `f2fs_alloc_mulref_entry`

移除了外部的锁获取代码，因为 `curmulref_alloc_entry` 现在内部处理锁：

```c
// 之前：需要外部获取锁
down_write(&sm->curmulref_lock);
mutex_lock(&cmr->curmulref_mutex);
curmulref_alloc_entry(...);
// ...
up_write(&sm->curmulref_lock);

// 现在：curmulref_alloc_entry 内部处理锁
curmulref_alloc_entry(...);  // 内部使用两阶段锁
```

### 安全性保证

1. **`f2fs_set_bit` 是原子操作** → bitmap 更新安全
2. **写锁保护块旋转和 `cmr` 状态更新** → 状态一致性
3. **读锁允许并发** → 消除阻塞
4. **多进程分配不同 entry 时可并发执行** → 提高性能

### 修复效果

- **消除 `curmulref_alloc_entry` 重入死锁**：多个进程可以并发调用，不会互相阻塞
- **减少锁持有时间**：I/O 操作不在锁内执行
- **保持并发正确性**：两个进程分配不同 entry 时可以并发执行

### 相关文件变更

| 文件 | 变更 |
|------|------|
| `snapshot.c` | 修改 `curmulref_alloc_entry` 使用两阶段锁；新增 `curmulref_alloc_multi` 函数；修改 `f2fs_alloc_mulref_entry` 移除外部锁 |
| `snapshot.h` | 新增 `struct curmulref_alloc_info` 定义和 `curmulref_alloc_multi` 函数声明 |
