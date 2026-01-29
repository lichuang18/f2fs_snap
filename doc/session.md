# F2FS 快照系统 - Node Block COW 实现会话记录

## 会话信息

- **日期**: 2026-01-27
- **目标**: 实现快照系统的独立 Node Block 复制功能
- **状态**: 已完成实现，编译通过

---

## 一、背景问题

### 1.1 原有实现的缺陷

原有的 `update_f2fs_inode()` 函数直接复制 `i_nid[0-4]`，导致快照和原始文件共享同一组 node block：

```c
// 原有代码 (snapshot.c:57-60)
for (idx = 0; idx < 5; idx++) {
    new_fi->i_nid[idx] = src_fi->i_nid[idx];  // 问题：直接复制 nid
}
```

这违反了 F2FS 的 NAT 设计（每个 nid 只属于一个 ino），会导致：
- 原始文件删除时快照无法访问数据
- 原始文件覆盖写时快照数据映射被破坏
- 原始文件 truncate 时快照部分数据丢失

### 1.2 设计目标

为快照文件构建独立的 node block 树，只在最底层共享数据块（通过 mulref 机制）。

---

## 二、实现方案

### 2.1 修改的文件

| 文件 | 修改内容 |
|------|----------|
| `snapshot.c` | 修改 `update_f2fs_inode()`，新增 4 个 node 复制函数 |
| `snapshot.h` | 添加 `f2fs_cow_copy_all_nodes()` 函数声明 |
| `node.c` | 导出 `set_node_addr()` 函数（移除 static） |
| `f2fs.h` | 添加 `set_node_addr()` 函数声明 |

### 2.2 新增函数

#### 2.2.1 `f2fs_cow_copy_direct_node()`

复制单个 direct_node，用于处理 `i_nid[0]` 和 `i_nid[1]`。

```c
static nid_t f2fs_cow_copy_direct_node(struct f2fs_sb_info *sbi,
                                        nid_t src_nid,
                                        struct inode *snap_inode,
                                        unsigned int ofs);
```

#### 2.2.2 `f2fs_cow_copy_indirect_node()`

递归复制 indirect_node 及其所有子 direct_node，用于处理 `i_nid[2]` 和 `i_nid[3]`。

```c
static nid_t f2fs_cow_copy_indirect_node(struct f2fs_sb_info *sbi,
                                          nid_t src_nid,
                                          struct inode *snap_inode,
                                          unsigned int ofs,
                                          unsigned int base_child_ofs);
```

#### 2.2.3 `f2fs_cow_copy_double_indirect_node()`

递归复制 double_indirect_node 整棵树，用于处理 `i_nid[4]`。

```c
static nid_t f2fs_cow_copy_double_indirect_node(struct f2fs_sb_info *sbi,
                                                 nid_t src_nid,
                                                 struct inode *snap_inode);
```

#### 2.2.4 `f2fs_cow_copy_all_nodes()`

主入口函数，复制 inode 的所有间接节点树。

```c
int f2fs_cow_copy_all_nodes(struct inode *src_inode, struct inode *snap_inode);
```

### 2.3 Node Offset 定义

```c
#define NODE_OFS_DIRECT_0       1
#define NODE_OFS_DIRECT_1       2
#define NODE_OFS_INDIRECT_0     3
#define NODE_OFS_INDIRECT_1     (4 + NIDS_PER_BLOCK)
#define NODE_OFS_DINDIRECT      (5 + 2 * NIDS_PER_BLOCK)
```

---

## 三、Page 锁优化

### 3.1 原始实现的锁问题

原始实现存在严重的锁嵌套问题，最坏情况下可能同时持有 5 个 page 锁，有死锁风险。

### 3.2 优化后的锁策略

采用 **"先复制后释放"** 和 **"先递归后创建"** 策略：

#### `f2fs_cow_copy_direct_node()` 锁流程

```
获取 src_page 锁 → 复制到栈变量 → 释放 src_page 锁
→ 获取 new_page 锁 → 操作 → 释放 new_page 锁
(任意时刻最多持有 1 个锁)
```

#### `f2fs_cow_copy_indirect_node()` 锁流程

```
获取 src_page 锁 → 复制所有子 nid 到堆数组 → 释放 src_page 锁
→ 循环调用 f2fs_cow_copy_direct_node() (不持有任何锁)
→ 获取 new_page 锁 → 填充数据 → 释放 new_page 锁
(任意时刻最多持有 1 个锁)
```

#### `f2fs_cow_copy_all_nodes()` 三阶段处理

```
阶段1: 获取 src_ipage 锁 → 复制 i_nid[0-4] → 释放锁
阶段2: 调用所有 copy 函数 (不持有任何 inode page 锁)
阶段3: 获取 snap_ipage 锁 → 更新 i_nid[0-4] → 释放锁
```

### 3.3 锁深度对比

| 函数 | 修改前最大锁深度 | 修改后最大锁深度 |
|------|-----------------|-----------------|
| `f2fs_cow_copy_direct_node` | 2 | 1 |
| `f2fs_cow_copy_indirect_node` | 2 + 递归 | 1 |
| `f2fs_cow_copy_double_indirect_node` | 2 + 递归 | 1 |
| `f2fs_cow_copy_all_nodes` | 2 + 递归 | 1 |

### 3.4 上层调用锁分析

`f2fs_cow()` 在调用 `f2fs_cow_copy_all_nodes()` 之前已释放所有相关 page 锁：

```c
// snapshot.c 第 3798-3802 行
f2fs_put_page(son_ipage, 1);   // 已释放
f2fs_put_page(new_ipage, 1);   // 已释放

ret = f2fs_cow_copy_all_nodes(son_inode, tmp_inode);  // 安全调用
```

**结论：上层调用与底层函数之间没有 page lock 冲突。**

---

## 四、内存开销

| 函数 | 内存开销 |
|------|----------|
| `f2fs_cow_copy_direct_node` | 栈上 ~4KB (`struct direct_node`) |
| `f2fs_cow_copy_indirect_node` | 堆上 ~8KB (`2 * NIDS_PER_BLOCK * sizeof(nid_t)`) |
| `f2fs_cow_copy_double_indirect_node` | 堆上 ~8KB |

这些内存开销是可接受的，换取的是完全避免死锁风险。

---

## 五、调用点

`f2fs_cow_copy_all_nodes()` 在 `f2fs_cow()` 函数中被调用，有两个调用点：

1. **非 inline 目录** (snapshot.c:3738)
2. **非 inline 文件** (snapshot.c:3802)

---

## 六、COW 后的数据结构

```
COW 后的正确结构：

原始 inode (ino=100)                快照 inode (ino=200)
┌──────────────────┐               ┌──────────────────┐
│ i_addr[0]=5000   │──────┬────────│ i_addr[0]=5000   │  ← 数据块地址相同(mulref)
│ i_nid[0]=300     │      │        │ i_nid[0]=400     │  ← 新分配的独立 nid
└──────────────────┘      │        └──────────────────┘
        │                 │                 │
        ▼                 │                 ▼
┌───────────────────┐     │        ┌───────────────────┐
│ direct_node 300   │     │        │ direct_node 400   │  ← 新创建
│ footer.ino=100    │     │        │ footer.ino=200    │  ← 属于快照
│ addr[0]=6000 ─────┼─────┼────────│ addr[0]=6000      │  ← 地址相同(mulref)
└───────────────────┘     │        └───────────────────┘
                          ▼
              ┌─────────────────────────┐
              │      数据块 6000        │  ← mulref 保护
              └─────────────────────────┘
```

**核心思想**：
- Node 层面：完全独立，每个快照有自己的 node 树
- Data 层面：通过 mulref 机制共享，节省空间

---

## 七、编译状态

- **编译结果**: 成功
- **警告**: 无新增警告

---

## 八、待测试项

1. **功能测试**
   - 小文件 COW (< 3.6MB，只用 i_addr)
   - 中等文件 COW (3.6MB ~ 11.6MB，使用 i_nid[0,1])
   - 大文件 COW (> 11.6MB，使用 i_nid[2])
   - 超大文件 COW (> 4GB，使用 i_nid[3,4])

2. **隔离性测试**
   - 删除原始文件后快照数据完整性
   - 覆盖写原始文件后快照数据不变
   - truncate 原始文件后快照数据完整

3. **压力测试**
   - 多快照场景
   - 大量文件快照
   - 并发操作

---

## 九、相关代码位置

| 文件 | 行号 | 函数/内容 |
|------|------|----------|
| snapshot.c | 29-59 | `update_f2fs_inode()` - 已修改，不再复制 i_nid |
| snapshot.c | 88-106 | Node offset 宏定义 |
| snapshot.c | 108-202 | `f2fs_cow_copy_direct_node()` |
| snapshot.c | 204-354 | `f2fs_cow_copy_indirect_node()` |
| snapshot.c | 356-514 | `f2fs_cow_copy_double_indirect_node()` |
| snapshot.c | 516-630 | `f2fs_cow_copy_all_nodes()` |
| snapshot.c | 3738 | 调用点1：非 inline 目录 |
| snapshot.c | 3802 | 调用点2：非 inline 文件 |
| snapshot.h | 62 | 函数声明 |
| node.c | 456 | `set_node_addr()` - 已导出 |
| f2fs.h | 3564 | `set_node_addr()` 声明 |

---

## 十、参考文档

- `doc/snapshot_node_cow_design.md` - 详细设计文档
