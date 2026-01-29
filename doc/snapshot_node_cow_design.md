# F2FS 快照系统 - 独立 Node Block 设计方案

## 文档信息

- **版本**: v1.0
- **日期**: 2026-01-26
- **作者**: lch
- **状态**: 设计阶段

---

## 一、背景与问题

### 1.1 当前 COW 实现概述

当前快照系统在触发 COW 时的处理流程：

```
f2fs_snapshot_cow(inode)
    └─► f2fs_cow(pra_inode, snap_inode, son_inode, &new_inode)
            ├─► snapfs_new_inode()          // 创建新 inode
            ├─► update_f2fs_inode()         // 复制 inode 元数据
            └─► f2fs_set_mulref_blocks()    // 标记数据块多引用
```

`update_f2fs_inode` 函数直接复制了源 inode 的所有字段，包括：

```c
// snapshot.c:57-60
for (idx = 0; idx < 5; idx++) {
    new_fi->i_nid[idx] = src_fi->i_nid[idx];  // 直接复制 nid
}
memcpy(new_fi->i_addr, src_fi->i_addr, sizeof(src_fi->i_addr));
```

### 1.2 F2FS inode 块映射结构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              f2fs_inode                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│  i_addr[0..922]  →  直接指向 923 个数据块 (level 0)                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  i_nid[0] → direct_node    → addr[0..1017] → 1018 个数据块 (level 1)        │
│  i_nid[1] → direct_node    → addr[0..1017] → 1018 个数据块 (level 2)        │
│  i_nid[2] → indirect_node  → nid[0..1017]  → 1018 个 direct_node            │
│  i_nid[3] → indirect_node  → nid[0..1017]  → 1018 个 direct_node            │
│  i_nid[4] → double_indirect → indirect[]   → direct[] → 数据块              │
└────────────────────────────────────────────────────────────────────────────┘

文件大小与寻址层级对应关系：
- Level 0 (i_addr[]):        0 ~ 3.6 MB     (923 * 4KB)
- Level 1 (i_nid[0]):        3.6 ~ 7.6 MB   (1018 * 4KB)
- Level 2 (i_nid[1]):        7.6 ~ 11.6 MB  (1018 * 4KB)
- Level 3 (i_nid[2]):        11.6 MB ~ 4 GB (1018 * 1018 * 4KB)
- Level 4 (i_nid[3]):        4 GB ~ 8 GB
- Level 5 (i_nid[4]):        8 GB ~ 4 TB
```

### 1.3 当前实现的问题

当前实现直接复制 `i_nid[0-4]`，导致两个 inode 共享同一组 node block：

```
当前 COW 后的结构（有问题）：

原始 inode (ino=100)                快照 inode (ino=200)
┌──────────────────┐               ┌──────────────────┐
│ i_nid[0] = 300   │───────┬───────│ i_nid[0] = 300   │  ← 共享同一个 nid!
│ i_nid[1] = 301   │───────┼───────│ i_nid[1] = 301   │
└──────────────────┘       │       └──────────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │   direct_node (nid=300) │
              │   footer.ino = 100      │  ← 只属于原始 inode
              │   addr[0] = 6000        │
              └─────────────────────────┘
```

#### 问题 1：NAT 设计冲突

F2FS 的 NAT (Node Address Table) 设计假设每个 nid 只属于一个 ino：

```c
struct f2fs_nat_entry {
    __u8 version;
    __le32 ino;        // 每个 nid 只记录一个 ino
    __le32 block_addr;
};
```

#### 问题 2：Node Footer 冲突

每个 node block 的 footer 记录了所属 inode：

```c
struct node_footer {
    __le32 nid;
    __le32 ino;        // 只记录一个 ino
    __le32 flag;
    __le64 cp_ver;
    __le32 next_blkaddr;
};
```

#### 问题 3：具体故障场景

| 场景 | 操作 | 后果 | 严重程度 |
|------|------|------|----------|
| 原始文件删除 | `truncate_node()` 释放 node | 快照无法访问数据 | **致命** |
| 原始文件覆盖写 | 修改 node 中的 addr[] | 快照数据映射被破坏 | **致命** |
| 原始文件 truncate | 释放部分 node | 快照部分数据丢失 | **致命** |
| fsync 快照文件 | `ino_of_node()` 检查失败 | node 被跳过 | **中等** |

---

## 二、设计目标

### 2.1 核心目标

**为快照文件构建独立的 node block 树，只在最底层共享数据块。**

### 2.2 设计原则

1. **隔离性**：原始文件的任何操作不影响快照
2. **兼容性**：符合 F2FS 原有设计（nid 与 ino 一对一）
3. **最小侵入**：不修改 F2FS 核心代码
4. **空间效率**：只复制 node block，数据块通过 mulref 共享

---

## 三、详细设计

### 3.1 目标结构

```
COW 后的正确结构：

原始 inode (ino=100)                快照 inode (ino=200)
┌──────────────────┐               ┌──────────────────┐
│ i_addr[0]=5000   │──────┬────────│ i_addr[0]=5000   │  ← 数据块地址相同
│ i_addr[1]=5001   │──────┼────────│ i_addr[1]=5001   │
│ ...              │      │        │ ...              │
│ i_nid[0]=300     │      │        │ i_nid[0]=400     │  ← 新分配的 nid
│ i_nid[1]=301     │      │        │ i_nid[1]=401     │  ← 新分配的 nid
└──────────────────┘      │        └──────────────────┘
        │                 │                 │
        ▼                 │                 ▼
┌───────────────────┐     │        ┌───────────────────┐
│ direct_node 300   │     │        │ direct_node 400   │  ← 新创建
│ footer.ino=100    │     │        │ footer.ino=200    │  ← 属于快照
│ addr[0]=6000 ─────┼─────┼────────│ addr[0]=6000      │  ← 地址相同
│ addr[1]=6001 ─────┼─────┼────────│ addr[1]=6001      │
└───────────────────┘     │        └───────────────────┘
                          │
                          ▼
              ┌─────────────────────────┐
              │      数据块 6000        │  ← mulref 保护
              │      数据块 6001        │
              └─────────────────────────┘
```

### 3.2 Node 复制层次

需要处理的 5 种 node 类型：

```
i_nid[0] → direct_node      (直接复制)
i_nid[1] → direct_node      (直接复制)
i_nid[2] → indirect_node    (递归复制)
           └─► direct_node[]
i_nid[3] → indirect_node    (递归复制)
           └─► direct_node[]
i_nid[4] → double_indirect  (二层递归复制)
           └─► indirect_node[]
               └─► direct_node[]
```

### 3.3 处理流程

```
f2fs_cow_copy_all_nodes(src_inode, snap_inode)
│
├─► 处理 i_nid[0]: direct_node
│   └─► f2fs_cow_copy_direct_node(src_nid=300) → new_nid=400
│       ├─► f2fs_alloc_nid() → 400
│       ├─► 创建新 node page
│       ├─► 复制 addr[] 数组（数据块地址不变）
│       ├─► 设置 footer (nid=400, ino=snap_ino)
│       └─► snap_inode->i_nid[0] = 400
│
├─► 处理 i_nid[1]: direct_node (同上)
│
├─► 处理 i_nid[2]: indirect_node
│   └─► f2fs_cow_copy_indirect_node(src_nid=302) → new_nid=402
│       ├─► f2fs_alloc_nid() → 402
│       ├─► 创建新 indirect node page
│       ├─► 遍历 nid[0..1017]，对每个非零 nid:
│       │   └─► f2fs_cow_copy_direct_node() → new_child_nid
│       │       └─► 更新 indirect_node.nid[i] = new_child_nid
│       ├─► 设置 footer
│       └─► snap_inode->i_nid[2] = 402
│
├─► 处理 i_nid[3]: indirect_node (同上)
│
└─► 处理 i_nid[4]: double_indirect_node
    └─► f2fs_cow_copy_double_indirect_node(src_nid=304) → new_nid=404
        ├─► f2fs_alloc_nid() → 404
        ├─► 创建新 double_indirect node page
        ├─► 遍历 nid[0..1017]，对每个非零 nid:
        │   └─► f2fs_cow_copy_indirect_node() → new_child_nid
        ├─► 设置 footer
        └─► snap_inode->i_nid[4] = 404
```

### 3.4 与现有 COW 流程的集成

#### 修改前的流程

```c
int f2fs_cow(...) {
    // 1. 创建新 inode
    tmp_inode = snapfs_new_inode(snap_inode, mode);

    // 2. 复制 inode 元数据（包括 i_nid，有问题）
    update_f2fs_inode(son_fi, new_fi);

    // 3. 标记数据块多引用
    ret = f2fs_set_mulref_blocks(*new_inode);
}
```

#### 修改后的流程

```c
int f2fs_cow(...) {
    // 1. 创建新 inode
    tmp_inode = snapfs_new_inode(snap_inode, mode);

    // 2. 复制 inode 元数据（不复制 i_nid）
    update_f2fs_inode_without_nid(son_fi, new_fi);

    // 3. 【新增】复制所有间接节点
    if (S_ISREG(son_inode->i_mode) && !f2fs_has_inline_data(son_inode)) {
        ret = f2fs_cow_copy_all_nodes(son_inode, tmp_inode);
        if (ret) {
            pr_err("f2fs_cow_copy_all_nodes failed\n");
            goto next_free;
        }
    }

    // 4. 标记数据块多引用
    ret = f2fs_set_mulref_blocks(*new_inode);
}
```

### 3.5 Node Offset 计算

F2FS 中每个 node 有一个 offset 值，用于标识其在 inode 树中的位置：

```
Node offset 定义：

Inode block (0)
  ├─ direct node (1)           ← i_nid[0]
  ├─ direct node (2)           ← i_nid[1]
  ├─ indirect node (3)         ← i_nid[2]
  │   └─ direct node (4 ~ 4 + N - 1)
  ├─ indirect node (4 + N)     ← i_nid[3]
  │   └─ direct node (5 + N ~ 5 + 2N - 1)
  └─ double indirect node (5 + 2N)  ← i_nid[4]
      └─ indirect node (6 + 2N ~ ...)
          └─ direct node (...)

其中 N = NIDS_PER_BLOCK = 1018
```

计算公式：

```c
// i_nid[0] 的 offset
#define NODE_OFS_DIRECT_0    1

// i_nid[1] 的 offset
#define NODE_OFS_DIRECT_1    2

// i_nid[2] 的 offset
#define NODE_OFS_INDIRECT_0  3

// i_nid[2] 下第 i 个 direct_node 的 offset
#define NODE_OFS_INDIRECT_0_CHILD(i)  (4 + (i))

// i_nid[3] 的 offset
#define NODE_OFS_INDIRECT_1  (4 + NIDS_PER_BLOCK)

// i_nid[4] 的 offset
#define NODE_OFS_DINDIRECT   (5 + 2 * NIDS_PER_BLOCK)
```

---

## 四、代价分析

### 4.1 空间代价

以 4GB 文件为例：

```
数据块数量: 4GB / 4KB = 1,048,576 个

块分布：
- i_addr[]:     923 个数据块
- i_nid[0]:     1,018 个数据块 (1 个 direct_node)
- i_nid[1]:     1,018 个数据块 (1 个 direct_node)
- i_nid[2]:     1,036,324 个数据块 (1 个 indirect + ~1018 个 direct)

需要复制的 node 数量：
- i_nid[0]: 1 个 direct_node
- i_nid[1]: 1 个 direct_node
- i_nid[2]: 1 个 indirect_node + ~1018 个 direct_node

总计: ~1021 个 node blocks = ~4 MB

空间代价比例: 4MB / 4GB = 0.1%
```

### 4.2 时间代价

```
COW 操作时间组成：
1. 创建新 inode:           O(1)
2. 复制 inode 元数据:       O(1)
3. 复制 node blocks:        O(n)，n = node 数量
4. 标记数据块 mulref:       O(m)，m = 数据块数量

对于 4GB 文件：
- 复制 ~1021 个 node: 需要 ~1021 次 page 分配和写入
- 标记 ~100万个数据块 mulref: 已有实现

相比原有的 mulref 标记操作，node 复制的代价较小。
```

### 4.3 代价总结

| 指标 | 数值 | 评估 |
|------|------|------|
| 额外空间 | ~0.1% | 可接受 |
| 额外时间 | O(node数量) | 可接受 |
| 代码复杂度 | 中等 | 可控 |

---

## 五、可行性分析

### 5.1 技术可行性

| 方面 | 分析 | 结论 |
|------|------|------|
| NID 分配 | 使用现有 `f2fs_alloc_nid()` | 可行 |
| Node 创建 | 使用现有 `f2fs_new_node_page()` | 可行 |
| 数据复制 | 简单的 `memcpy` | 可行 |
| Footer 设置 | 使用现有 `fill_node_footer()` | 可行 |
| 与 mulref 集成 | 复用现有 `f2fs_set_mulref_blocks()` | 可行 |

### 5.2 与现有系统的兼容性

| 组件 | 影响 | 兼容性 |
|------|------|--------|
| NAT | 每个 nid 独立，符合设计 | 完全兼容 |
| GC | 每个 node 有独立 owner | 完全兼容 |
| fsync | `ino_of_node()` 检查正确 | 完全兼容 |
| truncate | 只影响自己的 node | 完全兼容 |
| checkpoint | 标准 node 写入流程 | 完全兼容 |

### 5.3 风险评估

| 风险 | 可能性 | 影响 | 缓解措施 |
|------|--------|------|----------|
| NID 耗尽 | 低 | 高 | 监控 NID 使用率 |
| 内存不足 | 低 | 中 | 分批处理大文件 |
| 中途失败 | 中 | 中 | 实现回滚机制 |

---

## 六、优缺点分析

### 6.1 优点

1. **正确性保证**
   - 完全符合 F2FS 的设计假设
   - 每个 nid 只属于一个 ino
   - 不会出现 NAT/footer 冲突

2. **完全隔离**
   - 原始文件的删除、修改、truncate 不影响快照
   - 快照数据的完整性得到保证

3. **最小侵入**
   - 不需要修改 F2FS 核心代码
   - 只在 COW 流程中增加 node 复制步骤
   - 复用现有的 NID 分配和 node 管理机制

4. **实现简洁**
   - 逻辑清晰，易于理解和维护
   - 递归结构处理 indirect/double_indirect

5. **与 mulref 机制互补**
   - Node 层面：独立复制，完全隔离
   - Data 层面：mulref 共享，节省空间

### 6.2 缺点

1. **额外空间开销**
   - 每个快照需要独立的 node 树
   - 对于大文件，node 数量可观（但相对数据块仍很小）

2. **COW 时间增加**
   - 需要分配和写入额外的 node blocks
   - 对于大文件，可能有明显延迟

3. **实现复杂度**
   - 需要处理 5 种不同类型的 node
   - 需要正确计算 node offset
   - 需要处理错误和回滚

4. **NID 消耗增加**
   - 每个快照消耗额外的 NID
   - 频繁快照可能加速 NID 耗尽

### 6.3 与其他方案的对比

| 方案 | 空间效率 | 实现复杂度 | 正确性 | 兼容性 |
|------|----------|------------|--------|--------|
| **独立 Node（本方案）** | 中 | 中 | 高 | 高 |
| Node 多引用机制 | 高 | 高 | 中 | 低 |
| 完全深拷贝 | 低 | 低 | 高 | 高 |
| 当前实现（共享 nid） | 高 | 低 | **低** | **低** |

---

## 七、实现计划

### 7.1 阶段划分

```
Phase 1: 基础框架
├─► 实现 f2fs_cow_copy_direct_node()
├─► 实现 f2fs_cow_copy_indirect_node()
├─► 实现 f2fs_cow_copy_double_indirect_node()
└─► 实现 f2fs_cow_copy_all_nodes()

Phase 2: 集成与测试
├─► 修改 update_f2fs_inode()，不复制 i_nid
├─► 修改 f2fs_cow()，调用 node 复制函数
├─► 单元测试：小文件、中等文件、大文件
└─► 集成测试：删除、覆盖写、truncate 场景

Phase 3: 优化与完善
├─► 错误处理和回滚机制
├─► 性能优化（批量分配 NID）
└─► 边界条件处理
```

### 7.2 关键函数接口

```c
/**
 * f2fs_cow_copy_direct_node - 复制 direct_node
 * @sbi: 超级块信息
 * @src_nid: 源 node 的 nid
 * @snap_ino: 快照 inode 的 ino
 * @ofs: node offset
 *
 * 返回: 新分配的 nid，失败返回 0
 */
nid_t f2fs_cow_copy_direct_node(struct f2fs_sb_info *sbi,
                                 nid_t src_nid,
                                 nid_t snap_ino,
                                 unsigned int ofs);

/**
 * f2fs_cow_copy_indirect_node - 复制 indirect_node 及其子节点
 * @sbi: 超级块信息
 * @src_nid: 源 indirect_node 的 nid
 * @snap_ino: 快照 inode 的 ino
 * @ofs: node offset
 * @base_child_ofs: 子节点的起始 offset
 *
 * 返回: 新分配的 nid，失败返回 0
 */
nid_t f2fs_cow_copy_indirect_node(struct f2fs_sb_info *sbi,
                                   nid_t src_nid,
                                   nid_t snap_ino,
                                   unsigned int ofs,
                                   unsigned int base_child_ofs);

/**
 * f2fs_cow_copy_all_nodes - 复制 inode 的所有间接节点
 * @src_inode: 源 inode
 * @snap_inode: 快照 inode
 *
 * 返回: 0 成功，负数错误码
 */
int f2fs_cow_copy_all_nodes(struct inode *src_inode,
                            struct inode *snap_inode);
```

---

## 八、测试计划

### 8.1 功能测试

| 测试项 | 描述 | 预期结果 |
|--------|------|----------|
| 小文件 COW | 文件 < 3.6MB，只用 i_addr | 快照正确，无 node 复制 |
| 中等文件 COW | 文件 3.6MB ~ 11.6MB | i_nid[0,1] 正确复制 |
| 大文件 COW | 文件 > 11.6MB | i_nid[2] 及子节点正确复制 |
| 超大文件 COW | 文件 > 4GB | i_nid[3,4] 正确复制 |

### 8.2 隔离性测试

| 测试项 | 操作 | 预期结果 |
|--------|------|----------|
| 删除原始文件 | rm original | 快照数据完整可读 |
| 覆盖写原始文件 | echo "new" > original | 快照数据不变 |
| truncate 原始文件 | truncate -s 0 original | 快照数据完整 |
| 扩展原始文件 | dd >> original | 快照数据不变 |

### 8.3 压力测试

| 测试项 | 描述 |
|--------|------|
| 多快照 | 对同一文件创建多个快照 |
| 大量文件 | 对目录下大量文件创建快照 |
| 并发操作 | 同时进行 COW 和文件修改 |

---

## 九、总结

本设计方案通过为快照文件构建独立的 node block 树，解决了当前实现中 node 共享导致的数据一致性问题。

**核心思想**：
- Node 层面：完全独立，每个快照有自己的 node 树
- Data 层面：通过 mulref 机制共享，节省空间

**关键优势**：
- 符合 F2FS 原有设计
- 完全隔离，保证快照数据完整性
- 最小侵入，不修改核心代码

**代价**：
- 额外 ~0.1% 的空间开销
- COW 时需要复制 node blocks

综合评估，本方案是解决当前问题的最佳选择，建议尽快实施。

---

## 附录 A：相关代码位置

| 文件 | 函数 | 说明 |
|------|------|------|
| snapshot.c:29 | update_f2fs_inode() | 需要修改，不复制 i_nid |
| snapshot.c:2994 | f2fs_cow() | 需要修改，调用 node 复制 |
| snapshot.c:1949 | f2fs_set_mulref_blocks() | 保持不变 |
| node.c:1287 | f2fs_new_node_page() | 复用 |
| node.c:456 | set_node_addr() | 复用 |

## 附录 B：参考资料

- F2FS 源码: fs/f2fs/node.c, fs/f2fs/node.h
- F2FS 设计文档: Documentation/filesystems/f2fs.txt
- 本项目 mulref 实现: snapshot.c
