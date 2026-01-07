/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/f2fs/snapshot.h
 *
 * xmu lch
 * 
 */

#include "f2fs.h"
#include <linux/types.h>
#define SNAPFS_DEBUG 1

int f2fs_magic_lookup_or_alloc(struct f2fs_sb_info *sbi,
                               u32 src_ino, u32 snap_ino);//,
                            //    u32 *ret_entry_id,
                            //    struct f2fs_magic_entry **ret_entry,
                            //    struct page **ret_page);


int f2fs_magic_lookup_or_alloc_hopscotch(struct f2fs_sb_info *sbi,
                               u32 src_ino,
                               u32 *ret_entry_id,
                               struct f2fs_magic_entry **ret_entry,
                               struct page **ret_page);
int f2fs_magic_lookup(struct f2fs_sb_info *sbi, u32 src_ino, 
			u32 *ret_entry_id, struct f2fs_magic_entry *ret_entry);

int f2fs_snapshot_cow(struct inode *inode);

struct inode *snapfs_new_inode(struct inode *dir, umode_t mode);
void snapfs_set_file_temperature(struct f2fs_sb_info *sbi, struct inode *inode,
		const unsigned char *name);
void snapfs_set_compress_inode(struct f2fs_sb_info *sbi, struct inode *inode,
						const unsigned char *name);

int snapfs_is_extension_exist(const unsigned char *s, const char *sub,
						bool tmp_ext);

bool f2fs_is_mulref_blkaddr(struct f2fs_sb_info *sbi,
					 block_t blkaddr);

int f2fs_mulref_overwrite(struct f2fs_sb_info *sbi,
                          block_t old_blkaddr,
                          nid_t new_nid);

void f2fs_mulref_replace_block(struct f2fs_sb_info *sbi, block_t old_addr, block_t new_addr, struct f2fs_summary *old_sum);

void update_f2fs_inode(struct f2fs_inode *src_fi,struct f2fs_inode *new_fi);
void update_f2fs_inode_inline(struct f2fs_inode *src_fi,struct f2fs_inode *new_fi);
void f2fs_cow_update_inode(struct inode *src_inode,struct inode *snap_inode);


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



// init
// if (!cur->inited) {
//     cur->blkaddr = ckpt->cur_mulref_blkaddr;
//     cur->page = f2fs_get_meta_page(sbi, cur->blkaddr);
//     cur->blk  = page_address(cur->page);
//     cur->inited = true;
// }

