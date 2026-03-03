# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

这是基于 F2FS (Flash-Friendly File System) 的快照文件系统实现，使用 Copy-on-Write (CoW) 机制提供文件级快照功能。核心思想是：元数据（node）复制 + 数据块通过引用计数共享。

## 编译命令

```bash
# 编译内核模块 snapfs
make

# 清理编译产物
make clean

# 编译测试工具
cd test_ioctl && make

# 加载模块
insmod snapfs.ko

# 卸载模块
rmmod snapfs
```

## 快照操作

通过 ioctl 接口操作快照：

```bash
# 创建快照: ./test <源目录> <挂载点> <快照名称>
./test_ioctl/test /mnt/test3 /mnt snap3

# 删除快照 (需要单独的实现)
```

## 核心架构

### 三大核心数据结构

1. **Magic Entry** (f2fs.h:1045-1051) - 快照映射表
   - 使用 hopscotch hashing 实现 O(1) 平均查找
   - 记录源 inode 到快照 inode 的映射关系

2. **Mulref Entry** (f2fs.h:1026-1033) - 多引用跟踪
   - 跟踪哪些数据块被多个快照共享
   - 维护引用计数（最大 255）

3. **Node Copy** (snapshot.c:88-630) - Node 树复制
   - 三阶段锁设计避免死锁
   - 递归复制 direct/indirect/double-indirect node

### 关键文件映射

| 文件 | 职责 |
|------|------|
| `snapshot.c` | CoW 核心实现，node 复制，mulref 管理 |
| `file.c` | ioctl 接口 (`f2fs_create_snapshot`, `f2fs_delete_snapshot`) |
| `f2fs.h` | 核心数据结构定义 |
| `snapshot.h` | 快照函数声明 |
| `gc.c` | GC 相关，包含 `update_f2fs_inode()` |

### 快照工作流程

```
创建快照:
  f2fs_create_snapshot() [file.c:3813]
    → 复制目录结构
    → 对每个文件调用 f2fs_cow()
        → f2fs_cow_update_inode()      // 复制 inode 元数据
        → f2fs_cow_copy_all_nodes()    // 复制 node 树
        → f2fs_set_mulref_blocks()     // 标记数据块为多引用

写时复制:
  f2fs_snapshot_cow() [snapshot.c:3963]
    → 检查文件是否在快照下
    → 遍历父目录链找到所有相关快照
    → 对每个快照调用 f2fs_cow()
```

### Node Offset 定义 (snapshot.c:102-106)

F2FS inode 的间接指针结构：
```
i_nid[0] → direct_node (offset=1)
i_nid[1] → direct_node (offset=2)
i_nid[2] → indirect_node (offset=3) → direct_nodes (4..4+1017)
i_nid[3] → indirect_node (offset=1022) → direct_nodes (1023..2040)
i_nid[4] → double_indirect (offset=2041)
```

## 已知问题

根据 `doc/summary.md` 的评估：

1. **错误处理**: `snapshot.c:3985,4017,4070` - CoW 失败时跳转到 `success` 而非错误路径
2. **锁重复获取**: `snapshot.c:1382` - 在已持有锁的情况下再次获取
3. **资源泄漏**: `snapshot.c:1311` - ERR_PTR 后调用 put_page

## 测试工具

位于 `test_ioctl/` 目录：
- `test` - 快照创建测试工具
- `run.sh` - 自动化测试脚本
- `fill_data.sh` - 填充测试数据

## 重要常量

- `MRENTRY_PER_BLOCK` = 336 - 每个 mulref 块的条目数
- `MGENTRY_PER_BLOCK` = 139 - 每个 magic 块的条目数
- `MAGIC_MAX` = 32678 - 最大快照映射数量
- `NIDS_PER_BLOCK` = 1018 - 每个 node 的子节点数