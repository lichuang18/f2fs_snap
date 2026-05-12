/* SPDX-License-Identifier: GPL-2.0 */
/*
 * fs/f2fs/snapshot.h
 *
 * xmu lch
 * 
 */

#include "f2fs.h"
#include <linux/ktime.h>
#include <linux/types.h>
#define SNAPFS_DEBUG 0
#define SNAPFS_DEBUG1 0
#define SNAPFS_DEBUG_GC 0
#define SNAPFS_LOCK_DEBUG 1
int f2fs_magic_lookup_or_alloc(struct f2fs_sb_info *sbi,
                               u32 src_ino, u32 snap_ino, u32 *ret_entry_id);


int f2fs_magic_lookup_or_alloc_hopscotch(struct f2fs_sb_info *sbi,
                               u32 src_ino,
                               u32 *ret_entry_id,
                               struct f2fs_magic_entry **ret_entry,
                               struct page **ret_page);
int f2fs_magic_lookup(struct f2fs_sb_info *sbi, u32 src_ino, 
			u32 *ret_entry_id, struct f2fs_magic_entry *ret_entry);

int f2fs_snapshot_cow(struct inode *inode);
int f2fs_snapshot_cow_nolock(struct inode *inode);

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

int f2fs_mulref_overwrite_improved(struct f2fs_sb_info *sbi,
                                   block_t old_blkaddr,
                                   nid_t new_nid);

int f2fs_clear_mulref_blocks(struct inode *inode);

int f2fs_delete_snap_dir_recursive(struct inode *dir);

bool f2fs_dir_has_mulref_dentry(struct inode *dir);

bool f2fs_is_under_snapshot_dir(struct inode *inode);

void f2fs_mulref_replace_block(struct f2fs_sb_info *sbi, block_t old_addr, block_t new_addr, struct f2fs_summary *old_sum);

int f2fs_get_summary_by_addr(struct f2fs_sb_info *sbi,
                                    block_t blkaddr,
                                    struct f2fs_summary *sum);
void update_f2fs_inode(struct f2fs_inode *src_fi,struct f2fs_inode *new_fi);
void update_f2fs_inode_inline(struct f2fs_inode *src_fi,struct f2fs_inode *new_fi);
void f2fs_cow_update_inode(struct inode *src_inode,struct inode *snap_inode);
int f2fs_cow_copy_all_nodes(struct inode *src_inode, struct inode *snap_inode);
int f2fs_set_mulref_blocks(struct inode *inode, u32 src_ino);
bool check_sit_mulref_entry(struct f2fs_sb_info *sbi, block_t blkaddr);
void update_sit_mulref_entry(struct f2fs_sb_info *sbi, block_t blkaddr, bool set);
void f2fs_dump_nonzero_sit_mulref_entries_simple(struct f2fs_sb_info *sbi);
int snapfs_recover_journal(struct f2fs_sb_info *sbi);
int snapfs_resume_all_cow_slots(struct f2fs_sb_info *sbi);
int snapfs_resume_cow_from_slot(struct f2fs_sb_info *sbi, u32 snap_ino);

/* === Batch Redo Functions === */
int snapfs_batch_alloc_slot(struct f2fs_sb_info *sbi, u32 src_ino, u32 snap_ino,
                            u32 node_nid, u16 node_ofs, u16 valid_bits,
                            u32 *ret_slot_id, struct snapfs_batch_context **ret_ctx);
void snapfs_batch_free_slot(struct f2fs_sb_info *sbi, u32 slot_id);
int snapfs_batch_begin(struct f2fs_sb_info *sbi, u32 slot_id,
                       struct snapfs_batch_context *ctx);
int snapfs_batch_stage_redo(struct snapfs_batch_context *ctx,
                            block_t mr_blkaddr, u16 mr_idx,
                            bool valid, struct f2fs_mulref_entry *entry);
int snapfs_batch_commit(struct f2fs_sb_info *sbi, struct snapfs_batch_context *ctx);
int snapfs_batch_apply_one(struct f2fs_sb_info *sbi, struct snapfs_batch_context *ctx,
                           u16 bitno);
int snapfs_batch_flush_all(struct f2fs_sb_info *sbi, struct snapfs_batch_context *ctx);
int snapfs_batch_mark_applied(struct f2fs_sb_info *sbi, struct snapfs_batch_context *ctx);
int snapfs_batch_recover_slot(struct f2fs_sb_info *sbi, u32 slot_id);
int snapfs_batch_wait_for_slot(struct f2fs_sb_info *sbi);
void snapfs_batch_init_slot_info(struct snapfs_batch_slot_info *info, u32 slot_id);

/* mulref compact thread */
int f2fs_start_mulref_compact_thread(struct f2fs_sb_info *sbi);
void f2fs_stop_mulref_compact_thread(struct f2fs_sb_info *sbi);
void f2fs_wakeup_mulref_compact_thread(struct f2fs_sb_info *sbi, bool urgent);
int f2fs_mulref_get_stats(struct f2fs_sb_info *sbi, unsigned int *used,
			  unsigned int *total, unsigned int *usage_percent);

/* Hop range adjustment thread */
int f2fs_start_hop_range_thread(struct f2fs_sb_info *sbi);
void f2fs_stop_hop_range_thread(struct f2fs_sb_info *sbi);

static inline block_t magic_entry_to_blkaddr(u32 entry_id)
{
    return (entry_id / MGENTRY_PER_BLOCK);
}

static inline u32 magic_entry_to_offset(u32 entry_id)
{
    return entry_id % MGENTRY_PER_BLOCK;
}

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


/* mulref */

/* 用于 curmulref_alloc_multi 的输出结构 */
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

