/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/f2fs/snapshot.h
 *
 * xmu lch
 * 
 */
#include "f2fs.h"

u16 alloc_magic_flag_from_reclaim(struct f2fs_sb_info *sbi);
u16 alloc_magic_flag_force(struct f2fs_sb_info *sbi);
void magic_mark_reclaim(struct f2fs_sb_info *sbi, u16 flag);

#define MAGIC_MAX		32678

struct magic_mgr {
	spinlock_t lock;
	/* 已分配 or 正在使用的 flag（快速路径） */
	DECLARE_BITMAP(used, MAGIC_MAX + 1);
	/* 已确认可回收、可再次分配的 flag */
	DECLARE_BITMAP(free, MAGIC_MAX + 1);
	atomic_t need_scan;
	wait_queue_head_t wq;
	struct task_struct *thread;
	/* 防止并发 force steal */
	struct mutex force_lock;
};



// f2fs_mgr_init.  参考GC
// magic_mgr_init(sbi)
// {
// 	/* 扫描 NAT / inode，标记 used s_flag */
// 	scan_all_nodes_for_s_flag(sbi);
// 	start_magic_reclaim_thread(sbi);
// }

// 触发条件 （2）
// 1.删除inode
// 在 inode 删除路径（如 f2fs_evict_inode()）：
// if (inode->i_s_flag)
	// magic_mark_reclaim(sbi, inode->i_s_flag);

// 周期扫描。兜底
// atomic_set(&mgr->need_scan, 1);
// wake_up(&mgr->wq);


// mulref

// struct mulref_mgr {
// 	spinlock_t lock;

// 	block_t cur_blk;      /* 当前分配 block */
// 	atomic_t need_scan;   /* 是否需要回收扫描 */

// 	wait_queue_head_t wq;
// 	struct task_struct *thread;
// };


// 放在 f2fs_sb_info 里：

// struct f2fs_sb_info {
// 	...
// 	struct mulref_mgr *mulref_mgr;
// };