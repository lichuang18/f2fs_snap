# SnapFS Redo Journal 统一设计 v3

## 1. 目标与边界

本设计统一 COW 路径与 overwrite 路径的崩溃一致性机制，要求：

1. 明确区分两类 redo，避免状态、slot、恢复逻辑混用。
2. 保持 1 个 journal segment 的物理布局不变。
3. 支持多文件并发 COW。
4. overwrite 路径保持串行，提供独立一致性保障。
5. 提供可调的 redo 写入策略，默认强一致。

非目标：

- 不改变 snapshot create/delete 的高层语义。
- 不引入跨路径共享 slot 的调度策略。

---

## 2. 统一物理布局

沿用现有布局：

```text
[CP][SIT][NAT][REDO_JOURNAL_1SEG][MAGIC][MULREF_FLAG][MULREF_AREA][SSA][MAIN]
```

假设 block size = 4KB，1 segment = 512 blocks，则 journal 有 512 个 slot（每 slot 4KB）。

### 2.1 slot 分区（强约束）

- `slot[0..510]`：**COW redo 专用区**（511 slots）
- `slot[511]`：**overwrite redo 专用区**（1 slot）

禁止跨区分配：

- COW 分配器不可申请 `slot[511]`
- overwrite 固定只使用 `slot[511]`

这条约束用于消除歧义和恢复路径冲突。

---

## 3. 两类 redo 的职责划分

## 3.1 COW redo（多并发）

职责：

- 记录“文件 COW 进度 + 当前块事务”，支持中断后续跑。
- 覆盖多文件并发触发 COW 的场景。

粒度：

- 每个活跃 COW 上下文占用 1 个 slot。
- 上下文语义：`src_ino + snap_ino + node_nid + node_ofs + valid_bits + bitmap + pending block txn`。

## 3.2 overwrite redo（串行）

职责：

- 保障 `f2fs_mulref_overwrite` 过程中的 mulref/summary/SIT 崩溃一致性。
- 解决 SSA 与 mulref 可能出现的撕裂状态。

粒度：

- 全局串行路径，固定占用 1 个专用 slot（`slot[511]`）。
- 不承载 COW 进度位图语义。

---

## 4. 记录模型

## 4.1 COW slot 模型

采用“块组进度 + 当前块紧凑事务”模型：

- 身份头：`slot_id/slot_gen/tx_seq`
- owner 与范围：`src_ino/snap_ino/node_nid/node_ofs/valid_bits`
- 进度与挂起：`bitmap/pending_valid/pending_bit/state`
- 当前块事务：`mulref_ops[] + summary_op + sit_op + flags`
- 保护字段：`magic/version/crc`

其中：

- `slot_gen`：slot 每次释放后再分配必须递增，用于消除 slot 复用歧义。
- `tx_seq`：仅在当前 `(slot_id, slot_gen)` 内单调递增，用于判定先后顺序。
- `pending_bit`：必须显式记录，恢复时禁止通过 first-incomplete 推测当前挂起事务。

状态机：

- `EMPTY`
- `GROUP_IN_PROGRESS`
- `BLOCK_TXN_COMMITTED`

核心语义：

- bit=1 必须在“home apply + flush 完成”之后写入。
- `BLOCK_TXN_COMMITTED` 表示当前块最终值已落 journal，可重放。

## 4.2 overwrite slot 模型

overwrite 使用独立记录头，不复用 COW bitmap 语义：

- 标识：`magic/version/state/txid/crc`
- 操作身份：`op_type/data_blkaddr`
- 基线快照：`old_sum(nid/ofs/version)`
- 目标操作：`mulref_ops[]/summary_op/sit_op/flags`

状态机：

- `OW_EMPTY`
- `OW_TXN_COMMITTED`

核心语义：

- 先 durable overwrite redo，再改 home 元数据。
- replay 前校验 `old_sum` 基线，支持幂等重放与冲突判定。

---

## 5. 提交协议

## 5.1 COW 提交协议

单块事务必须遵循：

1. `begin`
2. `stage current block final ops`
3. 写 slot：`pending_valid=1, pending_bit=<bit>, state=BLOCK_TXN_COMMITTED, tx_seq++`
4. `apply mulref/summary/sit to home`
5. `flush homes`
6. 更新 slot：`bitmap[bit]=1, pending_valid=0, state=GROUP_IN_PROGRESS, tx_seq++`
7. 组完成后清 slot（`EMPTY`）
8. slot 释放回收时 `slot_gen++`

## 5.2 overwrite 提交协议

overwrite 单事务遵循：

1. 读取 `old_sum`，构造目标变更
2. `begin`
3. 记录 `data_blkaddr + old_sum + final ops`
4. `commit -> state=OW_TXN_COMMITTED`
5. `apply home`（mulref 链、summary、必要时 SIT）
6. `flush homes`
7. `complete -> state=OW_EMPTY`

overwrite 路径串行，因此不存在多事务并发 slot 竞争。

---

## 6. 恢复协议（挂载时）

## 6.1 COW 恢复

必须扫描 `slot[0..510]` 全区，不允许只读单个固定 slot：

- `EMPTY`：跳过
- `GROUP_IN_PROGRESS`：按 `node_nid/node_ofs` 定位当前组，从 bitmap 首个 0 bit 继续
- `BLOCK_TXN_COMMITTED` 且 `pending_valid=1`：按 `pending_bit` replay 当前块，再置 bit，继续组内后续 bit

恢复身份与先后关系以 `(slot_id, slot_gen, tx_seq)` 判定。

## 6.2 overwrite 恢复

仅检查 `slot[511]`：

- `OW_EMPTY`：跳过
- `OW_TXN_COMMITTED`：
  1. 读取当前 summary
  2. 与日志 `old_sum` 比较
  3. 分支处理：
     - 匹配：执行 replay
     - 已达目标态：按幂等完成
     - 非旧态且非目标态：标记冲突并保留日志供诊断

恢复流程必须与 COW 恢复互不干扰。

---

## 7. 动态控制策略（默认强一致）

## 7.1 COW 控制

- `cow_redo_interval_ops`（默认 `1`）
  - `1`：每块事务都 durable（强一致）
  - `>1`：允许窗口回退，用于性能调优

## 7.2 overwrite 控制

- `overwrite_redo_mode`（默认 `1`）
  - `0`：关闭 overwrite redo（仅调试）
  - `1`：强一致（每次 overwrite 都走 redo，默认）
  - `2`：保留 redo 语义，调节刷盘节奏/批次

- `overwrite_redo_interval_ops`（默认 `1`）
  - 当前 overwrite 路径串行，默认保持每事务 durable。

原则：性能调优优先调“刷盘节奏”，不取消 redo 语义。

---

## 8. 不歧义约束（必须满足）

1. 分区固定：`[0..510]` 仅 COW，`511` 仅 overwrite。
2. 分配器隔离：COW allocator 与 overwrite allocator 独立。
3. 状态机隔离：COW 状态枚举与 overwrite 状态枚举独立。
4. 恢复器隔离：COW 扫描 511 槽；overwrite 只看末槽。
5. 结构隔离：overwrite 记录不得使用 COW bitmap 语义字段。
6. 统计隔离：分别统计 COW redo 与 overwrite redo 次数、重放次数、冲突次数。
7. COW 语义：`1 slot = 1 活跃上下文`，slot 内串行、slot 间并行。
8. COW 约束：任意时刻一个 slot 最多 1 个 pending block txn。
9. COW 恢复：禁止猜测 pending bit，必须使用 `pending_bit` 显式字段。
10. slot 重分配：仅允许在 `slot_gen` 递增后发生。

---

## 9. 与 v2 的关键差异

1. 明确把 overwrite 从“通用 slot 复用”中剥离为专属末槽。
2. COW 与 overwrite 的状态机、恢复入口、配置项全部分离。
3. overwrite 增加 `old_sum` 基线校验，减少 SSA/mulref 不一致窗口。
4. 统一提出“默认强一致 + 可调节”策略，支持后续性能实验。

---

## 10. 实施顺序建议

1. 固化 slot 分区与分配器隔离。
2. 抽离 overwrite 专属日志结构与状态机。
3. 增加 overwrite `old_sum` 基线记录与 replay 校验。
4. 补齐配置项与统计项。
5. 最后收敛恢复入口，形成双恢复器（COW/overwrite）。

---

## 11. 最终结论

v3 方案的核心是“**同一物理 journal，双语义分区，双状态机恢复**”：

- COW redo 面向多文件并发进度恢复。
- overwrite redo 面向串行块级一致性。

两者共享 1 个 segment，但严格逻辑隔离，从而在不扩大物理保留区的前提下，同时满足可恢复性、可维护性和可调优性。

---

## 12. 基于当前代码的缺口审计（重点：overwrite）

以下结论来自 `snapshot.c` / `segment.c` 当前实现。

### 12.1 overwrite 已形成“固定末槽 + 事务入槽”链路

当前实现已具备：

- `redo->overwrite_slot = nr_slots - 1`（末槽专用）
- `snapfs_txn_bind_overwrite_slot()` 绑定 `txn.slot_idx/slot_valid`
- `snapfs_redo_commit()` 可将 overwrite 事务写入 journal slot

因此 overwrite 已不再是“未入槽”状态。

### 12.2 overwrite 状态机已独立为 `OW_EMPTY/OW_TXN_COMMITTED`

当前 overwrite replay 仅接受 `SNAPFS_OVERWRITE_TXN_COMMITTED`，并显式跳过 `SNAPFS_OVERWRITE_EMPTY`。

此外，overwrite complete/replay 清槽已切换为写入 `OW_EMPTY`，而非仅依赖 zero-slot。

### 12.3 overwrite 基线字段与三分判定已落地

`snap_redo_slot` 已包含 overwrite 基线：

- `old_sum_nid`
- `old_sum_ofs`
- `old_sum_ver`

`snapfs_replay_overwrite_slot()` 按三分逻辑处理：

- 当前 summary 匹配 old_sum：重放
- 当前 summary 已是目标 summary：幂等完成
- 两者都不匹配：判定冲突并返回错误

### 12.4 overwrite 控制面已与 COW 初步解耦

当前已增加 overwrite 独立控制字段：

- `overwrite_redo_mode`
- `overwrite_interval_ops`
- `overwrite_ops_since_sync`

并通过 overwrite 专用 begin 路径决定该类事务是否 bypass。默认 `overwrite_redo_mode=1`，保持 overwrite 强一致提交；关闭后才按 `overwrite_interval_ops` 生效。

---

## 13. 查漏补缺后的实施方案（v3 落地）

### 阶段 A：先做功能正确性（必须先完成）

1. 固化专用槽位
   - 约定 `OW_SLOT = redo->nr_slots - 1`。
   - COW 分配器禁止分配 `OW_SLOT`。
   - overwrite 路径不走通用 alloc，直接绑定 `OW_SLOT`。

2. overwrite 事务入槽
   - 在 `f2fs_mulref_overwrite()` 每条事务分支中，`snapfs_redo_begin()` 后立刻设置：
     - `txn.slot_idx = OW_SLOT`
     - `txn.slot_valid = true`
   - 使 `snapfs_redo_commit()`/`snapfs_redo_complete()` 实际生效。

3. overwrite 独立状态机
   - 增加 overwrite 状态枚举，避免复用 COW `SNAPFS_PROGRESS_*`。
   - overwrite commit 写 `OW_TXN_COMMITTED`，complete 写 `OW_EMPTY`。

### 阶段 B：补强恢复判定（避免语义歧义）

4. slot 结构补基线字段
   - 为 overwrite 记录增加：
     - `old_sum_nid`
     - `old_sum_ofs`
     - `old_sum_ver`

5. overwrite replay 三分判定
   - 读取当前 summary 与 `old_sum_*` 对比：
     - 匹配：按日志重放
     - 已到目标态：幂等完成
     - 既非旧态也非目标态：标记冲突并保留日志

6. 挂载恢复分离
   - `snapfs_recover_journal()` 对 `slot[0..510]` 执行 COW 恢复。
   - 对 `OW_SLOT` 执行 overwrite 专用恢复，不进入 COW 推进流程。

### 阶段 C：可调优控制（在正确性稳定后）

7. 拆分控制面
   - 保留 `cow_redo_interval_ops`。
   - 新增 `overwrite_redo_mode` + `overwrite_redo_interval_ops`。

8. 默认策略
   - 默认 `overwrite_redo_mode=1`（强一致，禁止 bypass）。
   - 性能实验仅调整 flush 节奏，不取消 overwrite redo 语义。

---

## 14. 验收标准（overwrite 一致性）

1. 代码路径覆盖
   - `f2fs_mulref_overwrite()` 所有事务分支都能落入 `OW_SLOT` 并成功 commit/complete。

2. 崩溃点验证
   - 在 commit 后、home apply 前崩溃：恢复后可重放到目标态。
   - 在部分 home flush 后崩溃：恢复后收敛到单一目标态。

3. 冲突可见性
   - old_sum 基线不匹配时不会静默覆盖，需可观测（计数或日志）。

4. 隔离性
   - COW 高并发压测下，overwrite 仍固定使用末槽，不与 COW slot 争用。