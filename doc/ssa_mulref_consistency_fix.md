# SSA / mulref 一致性修复记录

## 背景

当前 snapfs 在多引用块管理中，涉及三类元数据：

- SSA / curseg summary
- mulref 链表（`f2fs_mulref_block::mrentries`）
- SIT mulref 标记（`update_sit_mulref_entry()`）

原实现把这三者拆散在多个步骤里更新，导致中间态可能暴露给并发读者或后续路径使用。

典型问题：

1. 普通块首次转为 mulref 时，先改 SSA，后补第二个 mulref entry。
2. 已是 mulref 时追加 tail，`m_count` 先增加、`tail->next` 后更新。
3. overwrite 的 2->1 降级路径中，先清 mulref flag，后改 SSA。
4. `f2fs_update_summary_without_lock()` 允许无锁更新 curseg/SSA summary。

## 本次修改目标

在尽量小的改动范围内，统一关键提交顺序：

- **先完成 mulref 链更新**
- **再更新 SSA / curseg summary**
- **最后更新 SIT mulref 标记**（仅在首次转 mulref 或 2->1 降级时需要）

并且让关键路径不再使用无锁 summary 更新。

---

## 修改文件

- `snapshot.c`
- `doc/ssa_mulref_consistency_fix.md`

---

## 具体修改

### 1. 收敛 summary 更新入口

在 `snapshot.c` 中：

- 将原先的 `f2fs_update_summary_without_lock()` 删除出业务路径。
- 新增内部 helper：`__f2fs_update_summary_locked()`。
- `f2fs_update_summary()` 现在统一负责：
  - 查找目标块是否仍在某个 curseg 中；
  - 持有 `curseg_lock`；
  - 若命中 curseg，再持有 `curseg_mutex`；
  - 然后调用 `__f2fs_update_summary_locked()` 更新 curseg summary 或 SSA page。

这样业务路径不再绕开 summary 锁。

### 2. `f2fs_get_summary_by_addr()` 增加 curseg 读取保护

读取 curseg cache 时，增加：

- `down_read(&SM_I(sbi)->curseg_lock)`
- `mutex_lock(&curseg->curseg_mutex)`

避免读取到并发更新中的 curseg summary entry。

### 3. 普通块首次转 mulref：调整提交顺序

在 `f2fs_alloc_mulref_entry()` 的 `!is_mulref` 分支中：

#### 原顺序
1. 建 head
2. 改 SSA
3. 建第二个 entry
4. 单独补 `update_sit_mulref_entry(..., true)`

#### 新顺序
1. 建 head
2. 建第二个 entry
3. `f2fs_update_summary()` 更新 SSA / curseg summary
4. `update_sit_mulref_entry(..., true)`

同时 `set_mulref_entry()` 不再在函数外部补 `update_sit_mulref_entry()`，SIT 标记更新统一内聚到 `f2fs_alloc_mulref_entry()` 内部。

### 4. 已是 mulref 时追加 tail：先挂链，再增加计数

在 `f2fs_alloc_mulref_entry()` 的 `is_mulref` 分支中：

#### 原顺序
1. `head->m_count++`
2. 初始化 `new_entry`
3. 找 tail
4. `tail->next = new_entry`

#### 新顺序
1. 初始化 `new_entry`
2. 找到旧 tail
3. `tail->next = new_entry`
4. `head->m_count++`
5. 同步 `new_entry->m_count`

这样避免出现 `m_count` 已经增长但链表尚未挂接完成的中间态。

### 5. `f2fs_mulref_overwrite()`：不再无锁改 summary

#### 统一点
- 入口处先持有：
  - `down_write(&sm->curmulref_lock)`
  - `mutex_lock(&cmr->curmulref_mutex)`
- 函数末尾统一释放。
- 头删改、2->1 降级等路径不再中途反复重新加/解同一把 mulref 锁。

#### head 删除但仍保留多引用
顺序调整为：
1. 更新 mulref 链
2. 生成新的 `new_sum`
3. `f2fs_update_summary()` 改 SSA 指向新 head
4. 若是 2->1，不在这里清 flag；只有真正降成单引用时才清

#### 2->1 降级
顺序调整为：
1. 先失效旧 head / tail entry
2. 生成剩余唯一引用的 `new_sum`
3. `f2fs_update_summary()` 把 SSA 改回普通 summary
4. `update_sit_mulref_entry(..., false)` 清 mulref flag

这样避免出现“flag 已清但 SSA 还指向 mulref head”的窗口。

### 6. head 删除路径增加 `clear_mulref_flag`

在 `f2fs_mulref_overwrite()` 中增加 `clear_mulref_flag`：

- 仅当 head 删除后链从 2 降成 1 时置为 `true`
- SSA 更新成功后才执行 `update_sit_mulref_entry(..., false)`

---

## 修改后的关键顺序总结

### 普通块首次转 mulref
1. 完整写 mulref head + second entry
2. 更新 SSA / curseg summary 指向 head
3. 设置 SIT mulref flag

### 已是 mulref，再追加一个引用
1. 初始化新 entry
2. 找到 tail
3. `tail->next = new_entry`
4. `head->m_count++`

### mulref overwrite，删除 head 但仍是 mulref
1. 修改 mulref 链，确定新 head
2. 更新 SSA 指向新 head
3. 保持 mulref flag 不变

### mulref overwrite，2->1 降级
1. 失效旧 mulref entry
2. 更新 SSA 回普通 summary
3. 清 SIT mulref flag

---

## 当前设计如何解决 SSA 一致性问题

当前设计的核心原则是：

**把 SSA 作为块身份解释入口，并保证它只在目标状态已经准备好之后才切换。**

也就是：

- 普通块 → mulref：先把 mulref 链构造完整，再让 SSA 指向 mulref head，最后更新 SIT mulref 标记。
- mulref → 普通块：先让 SSA 改回普通 summary，再清理 SIT mulref 标记。
- mulref 内部扩展：如果 head 不变，则 SSA 不动，只调整 mulref 链内部顺序。

这样可以避免原先几类典型中间态：

| 场景 | 旧问题 | 当前设计如何避免 |
|---|---|---|
| 普通块首次转 mulref | SSA 先切到 head，但链还没建完 | 先建链，后改 SSA |
| 已是 mulref 追加引用 | `m_count` 先增，tail 还没挂上 | 先挂 tail，再增 `m_count` |
| 2→1 降级 | flag 已清，但 SSA 仍指向 mulref head | 先改 SSA，再清 flag |
| 删除 head 但仍多引用 | 新 head 已确定，但 SSA 仍指旧 head | 先更新链，再改 SSA |

---

## 结合实例说明

### 例 1：普通块第一次变成 mulref

假设旧块 `A` 原来是普通块：

```text
SSA[A] = { nid = inode_x, ofs = off_x, ver = v }
```

创建快照后，`A` 需要变成 mulref。

当前设计下的顺序是：

1. 先分配并写好两个 mulref entry：
   - `head` 保存旧引用
   - `tail` 保存新快照引用
2. 把链表连好：

```text
head(old inode) -> tail(snapshot inode)
```

3. 然后才更新：

```text
SSA[A] = { nid = mr_blk, ofs = head_idx, ver = v }
```

4. 最后再设置：

```text
SIT[A].mulref = 1
```

这意味着：只要任何读者看到 SSA 已经指向 mulref head，就可以认为 mulref 链已经存在且可遍历。

### 例 2：块已经是 mulref，再新增一个引用

假设当前状态：

```text
SSA[A] = head
head -> node2
m_count = 2
```

新增一个快照引用后，应变成：

```text
SSA[A] = head
head -> node2 -> node3
m_count = 3
```

这里 **SSA 不应该变化**，因为 head 没变。

当前设计的顺序是：

1. 初始化 `node3`
2. 找到旧 tail = `node2`
3. 先写：

```text
node2->next = node3
```

4. 最后才写：

```text
head->m_count = 3
node3->m_count = 3
```

因此不会再出现“`m_count` 已经是 3，但链上还只有两个节点”的不一致。

### 例 3：overwrite 删除 head，但仍然还有多个引用

假设原来：

```text
SSA[A] = head1
head1 -> node2 -> node3
```

覆盖写后，`head1` 对应的引用被删掉，新的正确状态应该是：

```text
SSA[A] = node2
node2 -> node3
```

当前设计的顺序是：

1. 先修改 mulref 链，确定 `node2` 成为新 head
2. 构造：

```text
new_sum = node2
```

3. 然后更新：

```text
SSA[A] = node2
```

4. 因为仍然是 mulref，所以 **不清 SIT mulref flag**

这样可以保证 SSA 始终指向当前真实 head。

### 例 4：overwrite 导致 2→1 降级

假设原来：

```text
SSA[A] = head
head -> tail
SIT[A].mulref = 1
```

覆盖写后只剩一个引用，应该退化为普通块：

```text
SSA[A] = { nid = inode_remain, ofs = off_remain, ver = v }
SIT[A].mulref = 0
```

当前设计的顺序是：

1. 先确定剩余唯一引用 `new_sum`
2. 先更新 SSA：

```text
SSA[A] = new_sum
```

3. SSA 成功后，再清：

```text
SIT[A].mulref = 0
```

所以不会再出现“flag 已清，但 SSA 还在指 mulref head”的窗口。

---

## 编译验证

已执行：

```bash
make
```

结果：
- 构建通过
- 仍有项目中原有 warning，但未引入新的构建错误

---

## 当前限制

本次是最小改动版，主要修复了最明显的一致性窗口，但还没有把整个 mulref/summary/SIT 更新抽象成完整事务框架。

仍建议后续继续收敛：

1. 把 overwrite 中间/尾节点删除路径也完全整理成统一提交 helper。
2. 进一步审视 `f2fs_mulref_replace_block()` 与 replace/GC 路径的交互。
3. 如需更强保证，可考虑显式引入单个事务型 helper，把“mulref 链改动 + summary 提交 + SIT 标记更新”收敛到一个接口。
