// SPDX-License-Identifier: GPL-2.0
/*
 * fs/f2fs/gc.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 */
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/init.h>
#include <linux/f2fs_fs.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/sched/signal.h>
#include <linux/random.h>
#include <linux/namei.h>
#include <linux/sort.h>

#include "f2fs.h"
#include "node.h"
#include "segment.h"
#include "snapshot.h"
#include "iostat.h"
#include <trace/events/f2fs.h>

struct snapfs_txn {
	struct f2fs_sb_info *sbi;
	u64 txid;
	u32 slot_idx;
	u32 slot_gen;
	u32 tx_seq;
	bool slot_valid;
	bool bypass_redo;
	bool holds_overwrite_lock;     /* 标记是否持有 overwrite_slot_lock */
	__le16 state;
	__le32 src_ino;
	__le32 snap_ino;
	__le32 node_nid;
	__le16 node_ofs;
	__le16 valid_bits;
	__u8 bitmap[SNAPFS_PROGRESS_BITMAP_BYTES];
	__u8 pending_valid;
	u16 pending_bit;
	__le32 op_type;
	__le32 data_blkaddr;
	__le32 old_sum_nid;
	__le16 old_sum_ofs;
	__u8 old_sum_ver;
	__u8 flags;
	__u8 record_type;
	unsigned int mulref_count;
	struct snap_redo_mulref_op mulref_ops[SNAP_REDO_MAX_MULREF_OPS];
	struct snap_redo_summary_op summary_op;
	struct snap_redo_sit_op sit_op;
};

struct snapfs_cow_progress {
	__le32 src_ino;
	__le32 snap_ino;
	__le32 node_nid;
	__le16 node_ofs;
	__le16 valid_bits;
	__u8 bitmap[SNAPFS_PROGRESS_BITMAP_BYTES];
	u32 slot_idx;
	bool slot_valid;
	bool active;
};

static inline void mulref_mark_invalid(struct f2fs_mulref_block *blk, u16 idx);
int f2fs_update_summary(struct f2fs_sb_info *sbi, block_t blkaddr,
	                       struct f2fs_summary *new_sum, unsigned int old_segno,
	                       unsigned int offset);

static inline block_t snapfs_redo_slot_blkaddr(struct f2fs_sb_info *sbi,
					       u32 slot_idx)
{
	return sbi->magic_info->journal_blkaddr + slot_idx;
}

static bool snapfs_redo_slot_idx_valid(struct f2fs_sb_info *sbi, u32 slot_idx)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;

	return redo && slot_idx < redo->nr_slots;
}

static bool snapfs_redo_slot_valid(struct snap_redo_slot *slot);

static int snapfs_redo_find_slot_by_snap(struct f2fs_sb_info *sbi, u32 snap_ino,
					 u32 *slot_idx)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;
	struct page *page;
	struct snap_redo_slot *slot;
	u32 i;

	if (!redo)
		return -EINVAL;

	for (i = 0; i < redo->cow_nr_slots; i++) {
		if (!test_bit(i, redo->slot_inuse_bitmap))
			continue;
		page = f2fs_get_meta_page(sbi, snapfs_redo_slot_blkaddr(sbi, i));
		if (IS_ERR(page))
			continue;
		slot = (struct snap_redo_slot *)page_address(page);
		if (snapfs_redo_slot_valid(slot) &&
		    le16_to_cpu(slot->state) != SNAPFS_PROGRESS_EMPTY &&
		    le32_to_cpu(slot->snap_ino) == snap_ino) {
			*slot_idx = i;
			f2fs_put_page(page, 1);
			return 0;
		}
		f2fs_put_page(page, 1);
	}

	return -ENOENT;
}

static int __maybe_unused snapfs_redo_find_slot_by_group(struct f2fs_sb_info *sbi,
					  u32 src_ino, u32 snap_ino,
					  nid_t node_nid, u16 node_ofs,
					  u16 valid_bits, u32 *slot_idx)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;
	struct page *page;
	struct snap_redo_slot *slot;
	u32 i;

	if (!redo)
		return -EINVAL;

	for (i = 0; i < redo->cow_nr_slots; i++) {
		if (!test_bit(i, redo->slot_inuse_bitmap))
			continue;
		page = f2fs_get_meta_page(sbi, snapfs_redo_slot_blkaddr(sbi, i));
		if (IS_ERR(page))
			continue;
		slot = (struct snap_redo_slot *)page_address(page);
		if (snapfs_redo_slot_valid(slot) &&
		    le16_to_cpu(slot->state) != SNAPFS_PROGRESS_EMPTY &&
		    le32_to_cpu(slot->src_ino) == src_ino &&
		    le32_to_cpu(slot->snap_ino) == snap_ino &&
		    le32_to_cpu(slot->node_nid) == node_nid &&
		    le16_to_cpu(slot->node_ofs) == node_ofs &&
		    le16_to_cpu(slot->valid_bits) == valid_bits) {
			*slot_idx = i;
			f2fs_put_page(page, 1);
			return 0;
		}
		f2fs_put_page(page, 1);
	}

	return -ENOENT;
}

static int snapfs_redo_alloc_slot(struct f2fs_sb_info *sbi, u32 snap_ino,
				  u32 *slot_idx)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;
	unsigned long idx;
	int ret;

	if (!redo)
		return -EINVAL;

	mutex_lock(&redo->alloc_lock);
	ret = snapfs_redo_find_slot_by_snap(sbi, snap_ino, slot_idx);
	if (!ret) {
		mutex_unlock(&redo->alloc_lock);
		return 0;
	}

	idx = find_first_zero_bit(redo->slot_inuse_bitmap, redo->cow_nr_slots);
	if (idx >= redo->cow_nr_slots) {
		mutex_unlock(&redo->alloc_lock);
		return -ENOSPC;
	}
	__set_bit(idx, redo->slot_inuse_bitmap);
	redo->slot_tx_seq[idx] = 0;
	*slot_idx = idx;
	mutex_unlock(&redo->alloc_lock);
	return 0;
}

static void snapfs_redo_free_slot(struct f2fs_sb_info *sbi, u32 slot_idx)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;

	if (!redo || !snapfs_redo_slot_idx_valid(sbi, slot_idx))
		return;
	mutex_lock(&redo->alloc_lock);
	__clear_bit(slot_idx, redo->slot_inuse_bitmap);
	redo->slot_gens[slot_idx]++;
	redo->slot_tx_seq[slot_idx] = 0;
	mutex_unlock(&redo->alloc_lock);
}

static void snapfs_redo_slot_init(struct snap_redo_slot *slot,
				  struct snapfs_txn *txn)
{
	unsigned int i;
	u32 crc;

	memset(slot, 0, sizeof(*slot));
	slot->magic = cpu_to_le32(SNAP_REDO_MAGIC);
	slot->version = cpu_to_le16(SNAP_REDO_VERSION);
	slot->state = txn->state;
	slot->txid = cpu_to_le64(txn->txid);
	slot->slot_id = cpu_to_le32(txn->slot_idx);
	slot->slot_gen = cpu_to_le32(txn->slot_gen);
	slot->tx_seq = cpu_to_le32(txn->tx_seq);
	slot->src_ino = txn->src_ino;
	slot->snap_ino = txn->snap_ino;
	slot->node_nid = txn->node_nid;
	slot->node_ofs = txn->node_ofs;
	slot->valid_bits = txn->valid_bits;
	memcpy(slot->bitmap, txn->bitmap, sizeof(slot->bitmap));
	slot->pending_valid = txn->pending_valid;
	slot->pending_bit = cpu_to_le16(txn->pending_bit);
	slot->op_type = txn->op_type;
	slot->data_blkaddr = txn->data_blkaddr;
	slot->old_sum_nid = txn->old_sum_nid;
	slot->old_sum_ofs = txn->old_sum_ofs;
	slot->old_sum_ver = txn->old_sum_ver;
	slot->nr_mulref_ops = txn->mulref_count;
	slot->flags = txn->flags;
	slot->record_type = txn->record_type;
	for (i = 0; i < txn->mulref_count; i++)
		slot->mulref_ops[i] = txn->mulref_ops[i];
	if (txn->flags & SNAP_REDO_F_HAS_SUMMARY)
		slot->summary_op = txn->summary_op;
	if (txn->flags & SNAP_REDO_F_HAS_SIT)
		slot->sit_op = txn->sit_op;
	if (!slot->record_type)
		slot->record_type = SNAPFS_REDO_REC_COW;
	crc = crc32(~0, (unsigned char *)slot + offsetof(struct snap_redo_slot, version),
		    sizeof(*slot) - offsetof(struct snap_redo_slot, version) - sizeof(slot->crc));
	slot->crc = cpu_to_le32(crc);
}

static bool snapfs_redo_slot_valid(struct snap_redo_slot *slot)
{
	u32 old_crc, calc;

	if (le32_to_cpu(slot->magic) != SNAP_REDO_MAGIC)
		return false;
	if (le16_to_cpu(slot->version) != SNAP_REDO_VERSION)
		return false;
	old_crc = le32_to_cpu(slot->crc);
	slot->crc = 0;
	calc = crc32(~0, (unsigned char *)slot + offsetof(struct snap_redo_slot, version),
		     sizeof(*slot) - offsetof(struct snap_redo_slot, version) - sizeof(slot->crc));
	slot->crc = cpu_to_le32(old_crc);
	return old_crc == calc;
}

static bool snapfs_summary_equal(const struct f2fs_summary *a,
				 const struct f2fs_summary *b)
{
	return a->nid == b->nid &&
		a->ofs_in_node == b->ofs_in_node &&
		a->version == b->version;
}

/*
 * 检查 overwrite slot 的当前状态
 * 返回：SNAPFS_OVERWRITE_APPLIED 或其他状态值
 */
static u16 snapfs_get_overwrite_slot_state(struct f2fs_sb_info *sbi)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;
	struct snap_redo_slot *slot;
	struct page *page;
	u16 state;

	page = f2fs_get_meta_page(sbi,
		snapfs_redo_slot_blkaddr(sbi, redo->overwrite_slot));
	if (IS_ERR(page))
		return SNAPFS_OVERWRITE_EMPTY;  /* 出错时视为可覆盖 */

	slot = (struct snap_redo_slot *)page_address(page);
	if (!snapfs_redo_slot_valid(slot))
		state = SNAPFS_OVERWRITE_EMPTY;
	else
		state = le16_to_cpu(slot->state);
	f2fs_put_page(page, 1);

	return state;
}

/*
 * 等待 overwrite slot 变为 APPLIED 状态
 * 调用前必须已持有 overwrite_slot_lock
 */
static void snapfs_wait_overwrite_slot_applied(struct f2fs_sb_info *sbi)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;
	u16 state;

	/* 如果 slot 已经是 APPLIED，无需等待 */
	state = snapfs_get_overwrite_slot_state(sbi);
	if (state == SNAPFS_OVERWRITE_APPLIED)
		return;

	/* 等待直到状态变为 APPLIED 或被唤醒 */
	wait_event(redo->overwrite_slot_wq,
		(snapfs_get_overwrite_slot_state(sbi) == SNAPFS_OVERWRITE_APPLIED));
}

static void snapfs_txn_bind_overwrite_slot(struct snapfs_txn *txn,
				   struct f2fs_summary *old_sum)
{
	struct snap_redo_info *redo = txn->sbi->magic_info->redo_info;

	/* 1. 串行化：获取锁，确保同一时刻只有一个操作使用 overwrite slot */
	mutex_lock(&redo->overwrite_slot_lock);

	/* 2. 等待直到 slot 状态为 APPLIED */
	snapfs_wait_overwrite_slot_applied(txn->sbi);

	/* 3. 绑定到 overwrite slot */
	txn->slot_idx = redo->overwrite_slot;
	txn->slot_gen = redo->slot_gens[redo->overwrite_slot];
	txn->slot_valid = true;
	txn->bypass_redo = false;
	txn->record_type = SNAPFS_REDO_REC_OVERWRITE;
	txn->state = cpu_to_le16(SNAPFS_OVERWRITE_TXN_COMMITTED);
	txn->old_sum_nid = old_sum->nid;
	txn->old_sum_ofs = old_sum->ofs_in_node;
	txn->old_sum_ver = old_sum->version;
	txn->holds_overwrite_lock = true;  /* 标记：持有 overwrite_slot_lock */

	mutex_lock(&redo->alloc_lock);
	__set_bit(redo->overwrite_slot, redo->slot_inuse_bitmap);
	mutex_unlock(&redo->alloc_lock);
}

static int snapfs_redo_stage_summary_final(struct snapfs_txn *txn,
				     block_t data_blkaddr,
				     struct f2fs_summary *new_sum)
{
	txn->flags |= cpu_to_le16(SNAP_REDO_F_HAS_SUMMARY);
	txn->summary_op.data_blkaddr = cpu_to_le32(data_blkaddr);
	txn->summary_op.sum = *new_sum;
	return 0;
}

static int snapfs_redo_stage_sit_final(struct snapfs_txn *txn,
				 block_t data_blkaddr, bool set)
{
	txn->flags |= cpu_to_le16(SNAP_REDO_F_HAS_SIT);
	txn->sit_op.data_blkaddr = cpu_to_le32(data_blkaddr);
	txn->sit_op.set = set ? 1 : 0;
	return 0;
}

static int snapfs_redo_stage_mulref_op(struct snapfs_txn *txn,
				      block_t mr_blkaddr, u16 idx,
				      bool valid,
				      struct f2fs_mulref_entry *entry)
{
	struct snap_redo_mulref_op *op;

	if (txn->mulref_count >= SNAP_REDO_MAX_MULREF_OPS)
		return -ENOSPC;
	op = &txn->mulref_ops[txn->mulref_count++];
	op->mr_blkaddr = cpu_to_le32(mr_blkaddr);
	op->idx = cpu_to_le16(idx);
	op->valid = valid ? 1 : 0;
	memset(&op->entry, 0, sizeof(op->entry));
	if (entry)
		op->entry = *entry;
	return 0;
}

static void snapfs_redo_release_txn(struct snapfs_txn *txn)
{
	/* 如果持有 overwrite_slot_lock，释放它 */
	if (txn->holds_overwrite_lock) {
		struct snap_redo_info *redo = txn->sbi->magic_info->redo_info;
		mutex_unlock(&redo->overwrite_slot_lock);
		txn->holds_overwrite_lock = false;
	}
	txn->mulref_count = 0;
	txn->flags = 0;
}

static void snapfs_apply_sit_mulref_change(struct f2fs_sb_info *sbi,
				 block_t blkaddr, bool set)
{
	update_sit_mulref_entry(sbi, blkaddr, set);
}

static int snapfs_flush_locked_meta_page(struct f2fs_sb_info *sbi,
					 struct page *page)
{
	int ret;

	if (!page)
		return 0;
	ret = f2fs_sync_meta_page(sbi, page, FS_META_IO);
	/* f2fs_sync_meta_page always unlocks the page on return (both dirty
	 * and clean paths). The check below is idempotent and guarantees the
	 * caller always receives an unlocked page. */
	if (PageLocked(page))
		unlock_page(page);
	return ret;
}

static void snapfs_put_meta_page_auto(struct page *page)
{
	if (!page)
		return;
	f2fs_put_page(page, PageLocked(page) ? 1 : 0);
}

static void snapfs_mark_txn_pages_dirty(struct page **pages, unsigned int nr_pages)
{
	unsigned int i, j;

	for (i = 0; i < nr_pages; i++) {
		if (!pages[i])
			continue;
		for (j = 0; j < i; j++) {
			if (pages[i] == pages[j])
				break;
		}
		if (j != i)
			continue;
		set_page_dirty(pages[i]);
	}
}

static unsigned int snapfs_count_txn_pages(struct page **pages,
					   unsigned int nr_pages)
{
	unsigned int i, j, count = 0;

	for (i = 0; i < nr_pages; i++) {
		if (!pages[i])
			continue;
		for (j = 0; j < i; j++) {
			if (pages[i] == pages[j])
				break;
		}
		if (j != i)
			continue;
		count++;
	}
	return count;
}

static void snapfs_require_redo_for_pages(struct snapfs_txn *txn,
					  struct page **pages,
					  unsigned int nr_pages)
{
	if (snapfs_count_txn_pages(pages, nr_pages) > 1)
		txn->bypass_redo = false;
}

static int snapfs_stage_sit_page_change(struct f2fs_sb_info *sbi,
				       block_t data_blkaddr,
				       bool set,
				       struct page **sit_pagep)
{
	struct page *sit_page;
	struct f2fs_sit_mulref_block *sit_blk;
	block_t sit_blkaddr;
	unsigned int sit_off;
	unsigned int blkoff;
	bool old;

	sit_blkaddr = SIT_MR_I(sbi)->base_addr +
		(GET_SEGNO(sbi, data_blkaddr) / SIT_MR_I(sbi)->sments_per_block);
	sit_off = GET_SEGNO(sbi, data_blkaddr) % SIT_MR_I(sbi)->sments_per_block;
	blkoff = GET_BLKOFF_FROM_SEG0(sbi, data_blkaddr);
	sit_page = f2fs_get_meta_page(sbi, sit_blkaddr);
	if (IS_ERR(sit_page))
		return PTR_ERR(sit_page);

	sit_blk = (struct f2fs_sit_mulref_block *)page_address(sit_page);
	old = f2fs_test_bit(blkoff, (char *)sit_blk->entries[sit_off].mvalid_map);
	if (set) {
		if (!old) {
			sit_blk->entries[sit_off].mblocks = cpu_to_le16(
				le16_to_cpu(sit_blk->entries[sit_off].mblocks) + 1);
			f2fs_set_bit(blkoff,
				(char *)sit_blk->entries[sit_off].mvalid_map);
			set_page_dirty(sit_page);
		}
	} else {
		if (old) {
			if (le16_to_cpu(sit_blk->entries[sit_off].mblocks) > 0)
				sit_blk->entries[sit_off].mblocks = cpu_to_le16(
					le16_to_cpu(sit_blk->entries[sit_off].mblocks) - 1);
			f2fs_clear_bit(blkoff,
				(char *)sit_blk->entries[sit_off].mvalid_map);
			set_page_dirty(sit_page);
		}
	}

	*sit_pagep = sit_page;
	return 0;
}

/* 前向声明 */
static void mark_sum_page_dirty(struct f2fs_sb_info *sbi, unsigned int segno);

static int snapfs_stage_summary_page_change(struct f2fs_sb_info *sbi,
					   block_t data_blkaddr,
					   const struct f2fs_summary *sum,
					   struct page **sum_pagep)
{
	struct page *sum_page;
	struct f2fs_summary_block *sum_blk;
	unsigned int segno = GET_SEGNO(sbi, data_blkaddr);
	unsigned int blkoff = GET_BLKOFF_FROM_SEG0(sbi, data_blkaddr);

	sum_page = f2fs_get_sum_page(sbi, segno);
	if (IS_ERR(sum_page))
		return PTR_ERR(sum_page);

	sum_blk = (struct f2fs_summary_block *)page_address(sum_page);
	sum_blk->entries[blkoff] = *sum;
	set_page_dirty(sum_page);

	/* 标记该 summary page 为脏，确保后续读取从 SSA 而非 curseg cache */
	mark_sum_page_dirty(sbi, segno);

	*sum_pagep = sum_page;
	return 0;
}

static int snapfs_flush_txn_pages(struct f2fs_sb_info *sbi,
				 struct page **pages, unsigned int nr_pages)
{
	unsigned int i, j;
	int ret;

	snapfs_mark_txn_pages_dirty(pages, nr_pages);
	for (i = 0; i < nr_pages; i++) {
		if (!pages[i])
			continue;
		for (j = 0; j < i; j++) {
			if (pages[i] == pages[j])
				break;
		}
		if (j != i)
			continue;
		ret = snapfs_flush_locked_meta_page(sbi, pages[i]);
		if (ret)
			return ret;
	}
	return 0;
}

static int __maybe_unused snapfs_build_summary_block(struct f2fs_sb_info *sbi, block_t blkaddr,
				     struct f2fs_summary *new_sum,
				     struct f2fs_summary_block *out)
{
	unsigned int segno = GET_SEGNO(sbi, blkaddr);
	unsigned int blkoff = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);
	struct page *sum_page;

	if (!out)
		return -EINVAL;
	sum_page = f2fs_get_sum_page(sbi, segno);
	if (IS_ERR(sum_page))
		return PTR_ERR(sum_page);
	memcpy(out, page_address(sum_page), F2FS_BLKSIZE);
	out->entries[blkoff] = *new_sum;
	snapfs_put_meta_page_auto(sum_page);
	return 0;
}

static int snapfs_redo_write_slot(struct f2fs_sb_info *sbi, u32 slot_idx,
				  struct snap_redo_slot *slot)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;
	block_t blkaddr;
	int ret;

	if (!snapfs_redo_slot_idx_valid(sbi, slot_idx))
		return -EINVAL;
	blkaddr = snapfs_redo_slot_blkaddr(sbi, slot_idx);
	mutex_lock(&redo->slot_locks[slot_idx]);
	f2fs_update_meta_page(sbi, slot, blkaddr);
	ret = snapfs_flush_meta_blocks(sbi, blkaddr, 1, FS_META_IO);
	mutex_unlock(&redo->slot_locks[slot_idx]);
	return ret;
}

static int snapfs_redo_clear_slot(struct f2fs_sb_info *sbi, u32 slot_idx)
{
	struct snap_redo_slot *slot;
	int ret;

	slot = kzalloc(sizeof(*slot), GFP_NOFS);
	if (!slot)
		return -ENOMEM;

	ret = snapfs_redo_write_slot(sbi, slot_idx, slot);
	kfree(slot);
	return ret;
}

static int snapfs_redo_mark_overwrite_applied(struct f2fs_sb_info *sbi, u32 slot_idx)
{
	struct snap_redo_slot *slot;
	u32 crc;
	int ret;

	slot = kzalloc(sizeof(*slot), GFP_NOFS);
	if (!slot)
		return -ENOMEM;

	slot->magic = cpu_to_le32(SNAP_REDO_MAGIC);
	slot->version = cpu_to_le16(SNAP_REDO_VERSION);
	slot->state = cpu_to_le16(SNAPFS_OVERWRITE_APPLIED);
	slot->slot_id = cpu_to_le32(slot_idx);
	slot->slot_gen = cpu_to_le32(sbi->magic_info->redo_info->slot_gens[slot_idx]);
	slot->tx_seq = cpu_to_le32(sbi->magic_info->redo_info->slot_tx_seq[slot_idx]);
	slot->record_type = SNAPFS_REDO_REC_OVERWRITE;
	crc = crc32(~0, (unsigned char *)slot + offsetof(struct snap_redo_slot, version),
		    sizeof(*slot) - offsetof(struct snap_redo_slot, version) - sizeof(slot->crc));
	slot->crc = cpu_to_le32(crc);

	ret = snapfs_redo_write_slot(sbi, slot_idx, slot);

	/* 唤醒等待 overwrite slot 的线程 */
	if (!ret) {
		wake_up_all(&sbi->magic_info->redo_info->overwrite_slot_wq);
	}

	kfree(slot);
	return ret;
}

static int snapfs_redo_begin_with_policy(struct f2fs_sb_info *sbi,
					 struct snapfs_txn *txn,
					 bool overwrite)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;
	unsigned int interval;
	unsigned int *ops_since_sync;

	memset(txn, 0, sizeof(*txn));
	txn->sbi = sbi;
	txn->state = cpu_to_le16(SNAPFS_PROGRESS_BLOCK_TXN_COMMITTED);
	txn->record_type = SNAPFS_REDO_REC_COW;
	txn->valid_bits = cpu_to_le16(0);
	mutex_lock(&redo->lock);
	txn->txid = redo->next_txid++;
	if (overwrite) {
		interval = redo->overwrite_interval_ops;
		ops_since_sync = &redo->overwrite_ops_since_sync;
	} else {
		interval = redo->interval_ops;
		ops_since_sync = &redo->ops_since_sync;
	}
	(*ops_since_sync)++;
	if (overwrite && redo->overwrite_redo_mode)
		txn->bypass_redo = false;
	else if (interval <= 1 || *ops_since_sync >= interval) {
		txn->bypass_redo = false;
		*ops_since_sync = 0;
	} else {
		txn->bypass_redo = true;
	}
	mutex_unlock(&redo->lock);
	return 0;
}

static int snapfs_redo_begin(struct f2fs_sb_info *sbi, struct snapfs_txn *txn)
{
	return snapfs_redo_begin_with_policy(sbi, txn, false);
}

static int snapfs_redo_begin_overwrite(struct f2fs_sb_info *sbi,
				      struct snapfs_txn *txn)
{
	return snapfs_redo_begin_with_policy(sbi, txn, true);
}

static void snapfs_redo_end(struct snapfs_txn *txn)
{
	snapfs_redo_release_txn(txn);
}

/* === Batch Redo Slot Management === */

/*
 * 初始化 batch slot info 结构
 */
void snapfs_batch_init_slot_info(struct snapfs_batch_slot_info *info, u32 slot_id)
{
	if (!info)
		return;
	memset(info, 0, sizeof(*info));
}

/*
 * 检查槽位状态是否允许被覆盖
 * 只有 EMPTY 或 APPLIED 状态才允许
 */
static bool snapfs_batch_slot_overwritable(struct f2fs_sb_info *sbi, u32 slot_id)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;
	struct page *page;
	struct snapfs_batch_header *header;
	bool ret = false;
	u16 state;

	if (!redo || !redo->batch_mode)
		return false;

	page = f2fs_get_meta_page(sbi,
		redo->journal_blkaddr + slot_id * redo->batch_slot_blocks);
	if (IS_ERR(page)) {
		pr_info("[snapfs batch] slot %u: get_meta_page failed\n", slot_id);
		return false;
	}

	header = (struct snapfs_batch_header *)page_address(page);

	/* 检查 magic 和 version */
	if (le32_to_cpu(header->magic) != SNAP_REDO_MAGIC ||
	    le16_to_cpu(header->version) != SNAP_REDO_VERSION) {
		pr_info("[snapfs batch] slot %u: EMPTY (magic=%x or version=%x mismatch)\n",
			slot_id, le32_to_cpu(header->magic), le16_to_cpu(header->version));
		ret = true;  /* 未初始化，视为 EMPTY */
		goto out;
	}

	/* 检查状态 */
	state = le16_to_cpu(header->state);
	switch (state) {
	case SNAPFS_BATCH_EMPTY:
		pr_info("[snapfs batch] slot %u: EMPTY\n", slot_id);
		ret = true;
		break;
	case SNAPFS_BATCH_APPLIED:
		/*
		pr_info("[snapfs batch] slot %u: APPLIED\n", slot_id);
		*/
		ret = true;
		break;
	case SNAPFS_BATCH_PREPARING:
		pr_info("[snapfs batch] slot %u: PREPARING (in-use, skip)\n", slot_id);
		ret = false;
		break;
	case SNAPFS_BATCH_COMMITTED:
		pr_info("[snapfs batch] slot %u: COMMITTED (in-use, skip)\n", slot_id);
		ret = false;
		break;
	case SNAPFS_BATCH_APPLYING:
		pr_info("[snapfs batch] slot %u: APPLYING (in-use, skip)\n", slot_id);
		ret = false;
		break;
	default:
		pr_info("[snapfs batch] slot %u: UNKNOWN state=%u\n", slot_id, state);
		ret = false;
		break;
	}

out:
	f2fs_put_page(page, 1);
	return ret;
}

/*
 * 分配一个 batch 文件槽
 * 如果没有可用槽，调用方会等待
 *
 * 返回值:
 *   0: 成功分配
 *   -ENOSPC: 没有可用槽（不应该发生，调用方应该等待）
 *   -EINVAL: 参数无效或 batch 模式未启用
 */
/**
 * snapfs_batch_find_free_slot - 查找可覆盖的槽位
 * @sbi: 文件系统信息
 * 返回: 槽位索引或 -1 表示没有可用槽位
 */
static int snapfs_batch_find_free_slot(struct f2fs_sb_info *sbi)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;
	unsigned long idx;
	int checked = 0;

	/* 使用 find_first_zero_bit 查找未分配的槽位（bit=0）
	 * EMPTY 和 APPLIED 状态的槽位 bit 都是 0（未分配）
	 * IN-USE 状态的槽位 bit 是 1（已分配）
	 */
	idx = find_first_zero_bit(redo->batch_slot_inuse_bitmap, redo->batch_nr_slots);
	while (idx < redo->batch_nr_slots) {
		checked++;
		if (snapfs_batch_slot_overwritable(sbi, idx)) {
		/*
		pr_info("[snapfs batch] find_free_slot: found slot %lu (checked %d)\n",
			idx, checked);
		*/
		return idx;
		}
		idx = find_next_zero_bit(redo->batch_slot_inuse_bitmap,
		                   redo->batch_nr_slots, idx + 1);
	}
	pr_info("[snapfs batch] find_free_slot: no slot available (checked %d slots)\n", checked);
	return -1;
}

/**
 * snapfs_batch_slot_available - 检查是否有可用的槽位
 * @sbi: 文件系统信息
 * 返回: true 表示有可用槽位
 */
static bool snapfs_batch_slot_available(struct f2fs_sb_info *sbi)
{
	return snapfs_batch_find_free_slot(sbi) >= 0;
}

/**
 * snapfs_batch_alloc_slot - 分配一个 batch 文件槽
 *
 * 规则 3：如果拿不到完整的空闲日志块组，新的文件不能开始处理，必须等待
 *
 * 返回值:
 *   0: 成功分配槽位
 *   -EINVAL: 参数无效或 batch 模式未启用
 *   -ENOMEM: 内存分配失败
 *   -ERESTARTSYS: 等待被信号中断
 */
int snapfs_batch_alloc_slot(struct f2fs_sb_info *sbi, u32 src_ino, u32 snap_ino,
                            u32 node_nid, u16 node_ofs, u16 valid_bits,
                            u32 *ret_slot_id, struct snapfs_batch_context **ret_ctx)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;
	struct snapfs_batch_context *ctx;
	int ret = 0;
	int max_wait_loops = 100;  /* 最多等待 100 次，约 100 秒 */
	int wait_loops = 0;
	DEFINE_WAIT(wait);

	if (!redo || !redo->batch_mode) {
		pr_err("[snapfs batch] batch mode not enabled\n");
		return -EINVAL;
	}

	if (!ret_slot_id || !ret_ctx)
		return -EINVAL;

	ctx = kzalloc(sizeof(*ctx), GFP_NOFS);
	if (!ctx)
		return -ENOMEM;

	ctx->sbi = sbi;
	ctx->src_ino = src_ino;
	ctx->snap_ino = snap_ino;
	ctx->node_nid = node_nid;
	ctx->node_ofs = node_ofs;
	ctx->valid_bits = valid_bits;
	ctx->entry_count = 0;
	ctx->entry_capacity = SNAPFS_PROGRESS_BITMAP_BITS;
	ctx->current_bit = 0;
	ctx->state = SNAPFS_BATCH_EMPTY;

	/* 初始化 bitmap 为 0 */
	memset(ctx->bitmap, 0, sizeof(ctx->bitmap));

alloc_slot:
	mutex_lock(&redo->alloc_lock);

	/* 查找 EMPTY 或 APPLIED 的槽位 */
	ret = snapfs_batch_find_free_slot(sbi);
	if (ret >= 0) {
		/* 找到可用槽位，分配它 */
		u32 idx = (u32)ret;
		__set_bit(idx, redo->batch_slot_inuse_bitmap);
		redo->batch_slot_gens[idx]++;

		ctx->slot_id = idx;
		ctx->batch_id = redo->batch_slot_gens[idx];

		mutex_unlock(&redo->alloc_lock);

		*ret_slot_id = idx;
		*ret_ctx = ctx;

		/*
		pr_info("[snapfs batch] ALLOC SUCCESS: slot %u for src_ino=%u snap_ino=%u node_nid=%u\n",
		         idx, src_ino, snap_ino, node_nid);
		*/
		return 0;
	}

	mutex_unlock(&redo->alloc_lock);

	/* 没有可用槽位，必须等待 */
	pr_info("[snapfs batch] NO SLOT: waiting... (loop %d, waiting_count=%d)\n",
		wait_loops, atomic_read(&redo->batch_waiting_count));

	/* 增加等待计数 */
	atomic_inc(&redo->batch_waiting_count);

	/* 使用内核 wait_event 等待有可用槽 */
	ret = wait_event_interruptible(redo->batch_slot_wq,
		snapfs_batch_slot_available(sbi));

	atomic_dec(&redo->batch_waiting_count);

	if (ret) {
		/* 被信号打断，释放上下文并返回 */
		pr_info("[snapfs batch] INTERRUPTED: wait interrupted\n");
		kfree(ctx);
		return -ERESTARTSYS;
	}

	/* 增加等待循环计数，防止无限等待 */
	wait_loops++;
	if (wait_loops >= max_wait_loops) {
		pr_err("[snapfs batch] TIMEOUT: wait timeout after %d loops\n", wait_loops);
		kfree(ctx);
		return -EBUSY;
	}

	pr_info("[snapfs batch] WAKEUP: slot became available, retrying (loop %d)\n", wait_loops);
	goto alloc_slot;
}

/*
 * 释放一个 batch 文件槽
 */
void snapfs_batch_free_slot(struct f2fs_sb_info *sbi, u32 slot_id)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;

	if (!redo || !redo->batch_mode)
		return;

	if (slot_id >= redo->batch_nr_slots)
		return;

	mutex_lock(&redo->alloc_lock);
	__clear_bit(slot_id, redo->batch_slot_inuse_bitmap);
	redo->batch_slot_gens[slot_id]++;
	mutex_unlock(&redo->alloc_lock);

	/* 唤醒等待槽的进程 */
	wake_up_all(&redo->batch_slot_wq);

	/*
	pr_info("[snapfs batch] FREE SLOT: slot %u freed, wake up waiters\n", slot_id);
	*/
}

/*
 * 等待直到有可用槽
 */
/*
 * 等待有可用槽
 * 返回值:
 *   0: 成功（有可用槽）
 *   -EINVAL: batch 模式未启用
 *   -ERESTARTSYS: 等待被信号中断
 */
int snapfs_batch_wait_for_slot(struct f2fs_sb_info *sbi)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;

	if (!redo || !redo->batch_mode)
		return -EINVAL;

	/* 如果已经有可用槽，直接返回 */
	if (snapfs_batch_slot_available(sbi))
		return 0;

	atomic_inc(&redo->batch_waiting_count);

	/* 等待有可用槽 */
	wait_event_interruptible(redo->batch_slot_wq,
		snapfs_batch_slot_available(sbi));

	atomic_dec(&redo->batch_waiting_count);

	return 0;
}

/* === Batch Redo State Machine === */

/*
 * 初始化 batch，开始 PREPARING 阶段
 * 写入 batch header（prepared=0），然后开始收集 redo 项
 */
int snapfs_batch_begin(struct f2fs_sb_info *sbi, u32 slot_id,
                       struct snapfs_batch_context *ctx)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;
	struct page *page;
	struct snapfs_batch_header *header;
	block_t blkaddr;
	u32 crc;

	if (!redo || !redo->batch_mode)
		return -EINVAL;

	if (slot_id >= redo->batch_nr_slots)
		return -EINVAL;

	ctx->slot_id = slot_id;
	ctx->state = SNAPFS_BATCH_PREPARING;

	/* 写入 batch header（prepared=0 表示未完成） */
	blkaddr = redo->journal_blkaddr + slot_id * redo->batch_slot_blocks;
	page = f2fs_get_meta_page(sbi, blkaddr);
	if (IS_ERR(page))
		return PTR_ERR(page);

	header = (struct snapfs_batch_header *)page_address(page);
	memset(header, 0, sizeof(*header));

	header->magic = cpu_to_le32(SNAP_REDO_MAGIC);
	header->version = cpu_to_le16(SNAP_REDO_VERSION);
	header->state = cpu_to_le16(SNAPFS_BATCH_PREPARING);
	header->batch_id = cpu_to_le32(ctx->batch_id);
	header->src_ino = cpu_to_le32(ctx->src_ino);
	header->snap_ino = cpu_to_le32(ctx->snap_ino);
	header->node_nid = cpu_to_le32(ctx->node_nid);
	header->node_ofs = cpu_to_le16(ctx->node_ofs);
	header->valid_bits = cpu_to_le16(ctx->valid_bits);
	header->prepared = 0;  /* PREPARING 阶段，prepared=0 */

	/* 初始化 bitmap 为 0 */
	memset(header->bitmap, 0, sizeof(header->bitmap));

	/* 计算 CRC */
	crc = crc32(~0, (unsigned char *)header + offsetof(struct snapfs_batch_header, version),
	             sizeof(*header) - offsetof(struct snapfs_batch_header, version) -
	             sizeof(header->crc));
	header->crc = cpu_to_le32(crc);

	set_page_dirty(page);

	f2fs_put_page(page, 1);

	/* 清空 dirty_sum 相关数组，确保每次 batch 开始时状态干净 */
	ctx->dirty_sum_count = 0;
	memset(ctx->dirty_sum_pages, 0, sizeof(ctx->dirty_sum_pages));
	memset(ctx->dirty_sum_segno, 0, sizeof(ctx->dirty_sum_segno));

	/* 清空 SIT 相关数组 */
	ctx->dirty_sit_count = 0;
	memset(ctx->dirty_sit_pages, 0, sizeof(ctx->dirty_sit_pages));
	memset(ctx->dirty_sit_blkaddr, 0, sizeof(ctx->dirty_sit_blkaddr));

	/* 清空 dirty_mr_page */
	if (ctx->dirty_mr_page) {
		f2fs_put_page(ctx->dirty_mr_page, 1);
		ctx->dirty_mr_page = NULL;
	}
	ctx->cur_mr_blkaddr = 0;  /* 初始化当前 mulref block 地址 */

	pr_info("[snapfs batch] slot %u: PREPARING started, batch_id=%u, valid_bits=%u\n",
	         slot_id, ctx->batch_id, ctx->valid_bits);

	return 0;
}

/*
 * 向 batch 添加一个 redo 项
 * 不实际写入磁盘，只是收集到 ctx->entries 中
 */
int snapfs_batch_stage_redo(struct snapfs_batch_context *ctx,
                            block_t mr_blkaddr, u16 mr_idx,
                            bool valid, struct f2fs_mulref_entry *entry)
{
	struct snap_redo_mulref_op *op;

	if (!ctx)
		return -EINVAL;

	if (ctx->entry_count >= ctx->entry_capacity)
		return -ENOSPC;

	op = &ctx->entries[ctx->entry_count++].mulref;
	op->mr_blkaddr = cpu_to_le32(mr_blkaddr);
	op->idx = cpu_to_le16(mr_idx);
	op->valid = valid ? 1 : 0;
	if (entry)
		op->entry = *entry;
	else
		memset(&op->entry, 0, sizeof(op->entry));

	return 0;
}

/*
 * 暂存 summary 操作到 batch context
 *
 * 注意：batch entry 中的 sum 字段只存储新的 summary 值
 * replay 时会读取当前 summary 进行验证
 */
int snapfs_batch_stage_summary(struct snapfs_batch_context *ctx,
                              block_t data_blkaddr,
                              struct f2fs_summary *new_sum)
{
	struct snapfs_batch_entry *entry;

	if (!ctx || !new_sum)
		return -EINVAL;

	if (ctx->entry_count >= ctx->entry_capacity)
		return -ENOSPC;

	entry = &ctx->entries[ctx->entry_count];
	entry->flags |= SNAPFS_BATCH_ENTRY_HAS_SUMMARY;
	entry->data_blkaddr = cpu_to_le32(data_blkaddr);

	/* 使用 batch entry 中的 sum 字段存储新的 summary 值 */
	entry->sum.sum = *new_sum;

	return 0;
}

/*
 * 暂存 SIT 操作到 batch context
 */
int snapfs_batch_stage_sit(struct snapfs_batch_context *ctx,
                           block_t data_blkaddr,
                           block_t sit_blkaddr,
                           bool set_mulref)
{
	struct snapfs_batch_entry *entry;

	if (!ctx)
		return -EINVAL;

	if (ctx->entry_count >= ctx->entry_capacity)
		return -ENOSPC;

	entry = &ctx->entries[ctx->entry_count];
	entry->flags |= SNAPFS_BATCH_ENTRY_HAS_SIT;
	entry->data_blkaddr = cpu_to_le32(data_blkaddr);
	entry->sit_blkaddr = cpu_to_le32(sit_blkaddr);
	entry->sit_set = set_mulref ? 1 : 0;

	return 0;
}

/*
 * 将 batch 标记为 APPLIED
 * 写入状态为 APPLIED，允许未来覆盖
 */
int snapfs_batch_mark_applied(struct f2fs_sb_info *sbi, struct snapfs_batch_context *ctx)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;
	struct page *page;
	struct snapfs_batch_header *header;
	block_t blkaddr;
	u32 crc;
	int ret = 0;

	if (!redo || !redo->batch_mode)
		return -EINVAL;

	blkaddr = redo->journal_blkaddr + ctx->slot_id * redo->batch_slot_blocks;
	page = f2fs_get_meta_page(sbi, blkaddr);
	if (IS_ERR(page))
		return PTR_ERR(page);

	header = (struct snapfs_batch_header *)page_address(page);

	/* 更新状态为 APPLIED */
	header->state = cpu_to_le16(SNAPFS_BATCH_APPLIED);
	header->prepared = 1;

	/* 复制最终的 bitmap */
	memcpy(header->bitmap, ctx->bitmap, sizeof(header->bitmap));

	/* 计算 CRC */
	crc = crc32(~0, (unsigned char *)header + offsetof(struct snapfs_batch_header, version),
	             sizeof(*header) - offsetof(struct snapfs_batch_header, version) -
	             sizeof(header->crc));
	header->crc = cpu_to_le32(crc);

	set_page_dirty(page);
	ret = snapfs_flush_locked_meta_page(sbi, page);
	/* snapfs_flush_locked_meta_page unlocks the page but doesn't release it */
	f2fs_put_page(page, 0);

	if (!ret)
		ctx->state = SNAPFS_BATCH_APPLIED;

	pr_info("[snapfs batch] slot %u: marked APPLIED\n", ctx->slot_id);

	return ret;
}

/*
 * 清理可能阻塞的 overwrite slot
 *
 * 问题：Batch CoW 和 Overwrite 操作使用同一个 overwrite_slot_lock 和 overwrite_slot_wq。
 * 如果 Overwrite 操作失败或被中断，overwrite slot 可能处于 COMMITTED 状态，
 * 导致后续 Overwrite 操作在 snapfs_wait_overwrite_slot_applied() 中永远等待。
 *
 * 解决方案：Batch 完成后，清理可能阻塞的 Overwrite slot。
 *
 * 关键：使用 mutex_trylock 避免死锁。
 * 如果无法获取锁，说明有其他操作正在使用该 slot（可能正在等待），
 * 此时跳过清理，让等待操作有机会完成。
 */
static void snapfs_batch_clear_stale_overwrite(struct f2fs_sb_info *sbi)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;
	u16 state;

	if (!redo)
		return;

	/* 先检查状态（无锁快速路径） */
	state = snapfs_get_overwrite_slot_state(sbi);
	if (state != SNAPFS_OVERWRITE_TXN_COMMITTED)
		return;

	/* 使用 try_lock 避免死锁 */
	if (!mutex_trylock(&redo->slot_locks[redo->overwrite_slot])) {
		/* 锁被占用，说明有操作正在使用该 slot
		 * 跳过清理，让等待操作有机会完成
		 */
		pr_warn("[snapfs batch] skip clearing overwrite slot: lock held by another operation\n");
		return;
	}

	/* 双重检查状态（持有锁后） */
	state = snapfs_get_overwrite_slot_state(sbi);
	if (state == SNAPFS_OVERWRITE_TXN_COMMITTED) {
		pr_warn("[snapfs batch] clearing stale overwrite slot state=%d\n", state);

		/* 清理 slot */
		snapfs_redo_clear_slot(sbi, redo->overwrite_slot);

		/* 唤醒所有等待该 slot 的线程 */
		wake_up_all(&redo->overwrite_slot_wq);
	}

	mutex_unlock(&redo->slot_locks[redo->overwrite_slot]);
}

/*
 * durable 一个 batch slot 的所有 redo blocks
 * 确保所有 43 个块都持久化到磁盘
 *
 * 返回值:
 *   0: 成功
 *   <0: 错误
 */
static int snapfs_batch_durable_all_pages(struct f2fs_sb_info *sbi,
                                          struct snapfs_batch_context *ctx)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;
	struct page *page;
	block_t blkaddr;
	u16 seq_no;
	int ret = 0;
	int sync_ret;

	/* durable 所有 43 个块 */
	for (seq_no = 0; seq_no < SNAPFS_BATCH_SLOT_BLOCKS; seq_no++) {
		blkaddr = redo->journal_blkaddr +
		          ctx->slot_id * redo->batch_slot_blocks + seq_no;
		page = f2fs_get_meta_page(sbi, blkaddr);
		if (IS_ERR(page)) {
			ret = PTR_ERR(page);
			pr_err("[snapfs batch] slot %u: failed to get page %u for durable\n",
			       ctx->slot_id, seq_no);
			continue;
		}

		/* 跳过未使用的块（保持为 EMPTY） */
		if (!PageDirty(page)) {
			f2fs_put_page(page, 1);
			continue;
		}

		sync_ret = snapfs_flush_locked_meta_page(sbi, page);
		if (sync_ret) {
			pr_err("[snapfs batch] slot %u: failed to sync page %u, ret=%d\n",
			       ctx->slot_id, seq_no, sync_ret);
			ret = sync_ret;
			/* page already unlocked by snapfs_flush_locked_meta_page */
			f2fs_put_page(page, 0);
			continue;
		}
		/* snapfs_flush_locked_meta_page already unlocked the page */
		f2fs_put_page(page, 0);
	}

	return ret;
}

/*
 * 写入一个 batch 的所有 redo 项
 * 将收集的 redo 项写入 43 个 redo blocks，然后 durable
 *
 * 格式:
 * - block 0: batch header + 前 23 个 redo 项
 * - block 1-42: continuation blocks，每个 24 个 redo 项
 *
 * 关键：必须遵循以下顺序
 * 1. 先写所有块（header + continuation blocks）
 * 2. durable 所有块
 * 3. 然后设置 header 状态为 COMMITTED
 * 4. durable header（带 COMMITTED 状态）
 *
 * 这样确保：只有在所有 redo 数据块都 durable 之后，
 * 才把状态设为 COMMITTED，恢复时才认为 redo 完整可用。
 */
int snapfs_batch_commit(struct f2fs_sb_info *sbi, struct snapfs_batch_context *ctx)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;
	struct page *page;
	struct snapfs_batch_header *header;
	struct snapfs_batch_continuation *cont;
	block_t blkaddr;
	u16 seq_no;
	u16 entry_idx;
	u16 entries_per_block;
	u16 entries_first_block;
	u16 remaining;
	u16 blocks_written = 0;
	u32 crc;
	int ret = 0;
	int i;

	if (!redo || !redo->batch_mode)
		return -EINVAL;

	if (ctx->state != SNAPFS_BATCH_PREPARING)
		return -EINVAL;

	pr_info("[snapfs batch] slot %u: committing %u entries\n",
	         ctx->slot_id, ctx->entry_count);

	entries_first_block = SNAPFS_BATCH_ENTRIES_FIRST;
	entries_per_block = SNAPFS_BATCH_ENTRIES_REST;

	/* === 步骤 1: 写所有块（使用 PREPARING 状态）=== */

	/* 写入 batch header (block 0)，使用 PREPARING 状态 */
	blkaddr = redo->journal_blkaddr + ctx->slot_id * redo->batch_slot_blocks;
	page = f2fs_get_meta_page(sbi, blkaddr);
	if (IS_ERR(page))
		return PTR_ERR(page);

	header = (struct snapfs_batch_header *)page_address(page);
	memset(header, 0, sizeof(*header));

	header->magic = cpu_to_le32(SNAP_REDO_MAGIC);
	header->version = cpu_to_le16(SNAP_REDO_VERSION);
	header->state = cpu_to_le16(SNAPFS_BATCH_PREPARING);  /* 先用 PREPARING */
	header->batch_id = cpu_to_le32(ctx->batch_id);
	header->src_ino = cpu_to_le32(ctx->src_ino);
	header->snap_ino = cpu_to_le32(ctx->snap_ino);
	header->node_nid = cpu_to_le32(ctx->node_nid);
	header->node_ofs = cpu_to_le16(ctx->node_ofs);
	header->valid_bits = cpu_to_le16(ctx->valid_bits);
	header->prepared = 0;  /* 还未完整写入，prepared=0 */

	/* 复制 bitmap */
	memcpy(header->bitmap, ctx->bitmap, sizeof(header->bitmap));

	/* 复制 redo 项到 header */
	entry_idx = 0;
	for (i = 0; i < entries_first_block && entry_idx < ctx->entry_count; i++, entry_idx++)
		header->entries[i] = ctx->entries[entry_idx];

	/* 计算 CRC */
	crc = crc32(~0, (unsigned char *)header + offsetof(struct snapfs_batch_header, version),
	             sizeof(*header) - offsetof(struct snapfs_batch_header, version) -
	             sizeof(header->crc));
	header->crc = cpu_to_le32(crc);

	set_page_dirty(page);
	blocks_written++;
	f2fs_put_page(page, 1);  /* 写回但不等待 */

	/* 写入 continuation blocks (block 1-42) */
	remaining = ctx->entry_count - entry_idx;
	seq_no = 1;

	while (remaining > 0 && seq_no < SNAPFS_BATCH_SLOT_BLOCKS) {
		blkaddr = redo->journal_blkaddr + ctx->slot_id * redo->batch_slot_blocks + seq_no;
		page = f2fs_get_meta_page(sbi, blkaddr);
		if (IS_ERR(page)) {
			ret = PTR_ERR(page);
			break;
		}

		cont = (struct snapfs_batch_continuation *)page_address(page);
		memset(cont, 0, sizeof(*cont));

		cont->magic = cpu_to_le32(SNAP_REDO_MAGIC);
		cont->version = cpu_to_le16(SNAP_REDO_VERSION);
		cont->state = SNAPFS_BATCH_PREPARING;  /* 使用 PREPARING */
		cont->batch_id = cpu_to_le32(ctx->batch_id);
		cont->slot_id = cpu_to_le32(ctx->slot_id);
		cont->seq_no = cpu_to_le16(seq_no);
		cont->entry_count = cpu_to_le16(min(remaining, entries_per_block));

		/* 复制 redo 项 */
		for (i = 0; i < cont->entry_count && entry_idx < ctx->entry_count; i++, entry_idx++)
			cont->entries[i] = ctx->entries[entry_idx];

		/* 计算 CRC */
		crc = crc32(~0, (unsigned char *)cont + offsetof(struct snapfs_batch_continuation, version),
		             sizeof(*cont) - offsetof(struct snapfs_batch_continuation, version) -
		             sizeof(cont->crc));
		cont->crc = cpu_to_le32(crc);

		set_page_dirty(page);
		blocks_written++;
		f2fs_put_page(page, 1);  /* 写回但不等待 */

		remaining -= cont->entry_count;
		seq_no++;
	}

	if (ret) {
		pr_err("[snapfs batch] slot %u: failed to write blocks, ret=%d\n",
		       ctx->slot_id, ret);
		return ret;
	}

	/* === 步骤 2: durable 所有块 === */
	ret = snapfs_batch_durable_all_pages(sbi, ctx);
	if (ret) {
		pr_err("[snapfs batch] slot %u: failed to durable all pages, ret=%d\n",
		       ctx->slot_id, ret);
		return ret;
	}

	/* === 步骤 2.5: 从 entries 收集所有 segno 到 dirty_sum_segno[] ===
	 * 这是关键的修复：staging 阶段设置了 entry->sum，但没有填充 dirty_sum_segno[]
	 * 现在我们需要从 entries 中收集所有 segno，以便 apply 阶段能找到对应的 sum page
	 */
	{
		unsigned int segno;
		unsigned int j;
		bool found;
		u16 k;

		ctx->dirty_sum_count = 0;
		for (j = 0; j < ctx->entry_count; j++) {
			struct snapfs_batch_entry *e = &ctx->entries[j];
			block_t data_blkaddr = le32_to_cpu(e->data_blkaddr);

			if (data_blkaddr == 0)
				continue;

			segno = GET_SEGNO(sbi, data_blkaddr);

			/* 检查是否已存在（去重） */
			found = false;
			for (k = 0; k < ctx->dirty_sum_count; k++) {
				if (ctx->dirty_sum_segno[k] == segno) {
					found = true;
					break;
				}
			}

			if (!found && ctx->dirty_sum_count < 512) {
				ctx->dirty_sum_segno[ctx->dirty_sum_count] = segno;
				pr_info("[snapfs batch] commit: SET dirty_sum[%u]=%u from entry %u\n",
				         ctx->dirty_sum_count, segno, j);
				ctx->dirty_sum_count++;
			}
		}
		pr_info("[snapfs batch] commit: collected %u unique segnos from %u entries\n",
		        ctx->dirty_sum_count, ctx->entry_count);
	}

	/* === 步骤 3: 设置 header 状态为 COMMITTED === */
	blkaddr = redo->journal_blkaddr + ctx->slot_id * redo->batch_slot_blocks;
	page = f2fs_get_meta_page(sbi, blkaddr);
	if (IS_ERR(page))
		return PTR_ERR(page);

	header = (struct snapfs_batch_header *)page_address(page);
	header->state = cpu_to_le16(SNAPFS_BATCH_COMMITTED);
	header->prepared = 1;  /* 所有块已 durable，标记 prepared=1 */

	/* 重新计算 CRC */
	crc = crc32(~0, (unsigned char *)header + offsetof(struct snapfs_batch_header, version),
	             sizeof(*header) - offsetof(struct snapfs_batch_header, version) -
	             sizeof(header->crc));
	header->crc = cpu_to_le32(crc);

	set_page_dirty(page);

	/* === 步骤 4: durable header（带 COMMITTED 状态）=== */
	ret = snapfs_flush_locked_meta_page(sbi, page);
	if (ret) {
		pr_err("[snapfs batch] slot %u: failed to sync committed header, ret=%d\n",
		       ctx->slot_id, ret);
		/* 即使 sync 失败，也认为 commit 完成，因为 redo 数据已经在步骤 2 durable 了 */
	}
	/* snapfs_flush_locked_meta_page already unlocked the page */
	f2fs_put_page(page, 0);

	ctx->state = SNAPFS_BATCH_COMMITTED;
	pr_info("[snapfs batch] slot %u: COMMITTED, %u redo blocks durable\n",
	         ctx->slot_id, blocks_written);

	return ret;
}

/*
 * 从 batch slot 读取 redo 项
 * 用于恢复时重新加载 batch 内容
 * 同时验证所有块的 CRC 完整性
 */
static int snapfs_batch_read_redo(struct f2fs_sb_info *sbi, u32 slot_id,
                                  struct snapfs_batch_context *ctx)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;
	struct page *page;
	struct snapfs_batch_header *header;
	struct snapfs_batch_continuation *cont;
	block_t blkaddr;
	u16 seq_no;
	u16 entry_idx;
	u16 entries_first_block;
	u16 count;
	u32 stored_crc;
	u32 calc_crc;
	int ret = 0;
	int i;

	if (!redo || !redo->batch_mode)
		return -EINVAL;

	entries_first_block = SNAPFS_BATCH_ENTRIES_FIRST;

	/* 读取 batch header (block 0) */
	blkaddr = redo->journal_blkaddr + slot_id * redo->batch_slot_blocks;
	page = f2fs_get_meta_page(sbi, blkaddr);
	if (IS_ERR(page))
		return PTR_ERR(page);

	header = (struct snapfs_batch_header *)page_address(page);

	/* 验证 header */
	if (le32_to_cpu(header->magic) != SNAP_REDO_MAGIC ||
	    le16_to_cpu(header->version) != SNAP_REDO_VERSION) {
		ret = -EINVAL;
		goto out;
	}

	/* 验证 header CRC */
	stored_crc = le32_to_cpu(header->crc);
	calc_crc = crc32(~0,
		(unsigned char *)header + offsetof(struct snapfs_batch_header, version),
		sizeof(*header) - offsetof(struct snapfs_batch_header, version) -
		sizeof(header->crc));
	if (stored_crc != calc_crc) {
		pr_err("[snapfs batch] slot %u: header CRC mismatch (stored=%u, calc=%u)\n",
		       slot_id, stored_crc, calc_crc);
		ret = -EINVAL;
		goto out;
	}

	ctx->batch_id = le32_to_cpu(header->batch_id);
	ctx->src_ino = le32_to_cpu(header->src_ino);
	ctx->snap_ino = le32_to_cpu(header->snap_ino);
	ctx->node_nid = le32_to_cpu(header->node_nid);
	ctx->node_ofs = le16_to_cpu(header->node_ofs);
	ctx->valid_bits = le16_to_cpu(header->valid_bits);
	ctx->state = le16_to_cpu(header->state);

	/* 复制 bitmap */
	memcpy(ctx->bitmap, header->bitmap, sizeof(ctx->bitmap));

	/* 读取 header 中的 redo 项 */
	entry_idx = 0;
	for (i = 0; i < entries_first_block && entry_idx < SNAPFS_PROGRESS_BITMAP_BITS; i++) {
		if (header->entries[i].mulref.mr_blkaddr == 0 && header->entries[i].mulref.idx == 0)
			continue;
		ctx->entries[entry_idx++] = header->entries[i];
	}

out:
	f2fs_put_page(page, 1);

	if (ret)
		return ret;

	/* 读取 continuation blocks，验证每个块的 CRC */
	seq_no = 1;
	while (seq_no < SNAPFS_BATCH_SLOT_BLOCKS) {
		blkaddr = redo->journal_blkaddr + slot_id * redo->batch_slot_blocks + seq_no;
		page = f2fs_get_meta_page(sbi, blkaddr);
		if (IS_ERR(page))
			break;

		cont = (struct snapfs_batch_continuation *)page_address(page);

		if (le32_to_cpu(cont->magic) != SNAP_REDO_MAGIC)
			goto next_cont;

		/* 验证 continuation block CRC */
		stored_crc = le32_to_cpu(cont->crc);
		calc_crc = crc32(~0,
			(unsigned char *)cont + offsetof(struct snapfs_batch_continuation, version),
			sizeof(*cont) - offsetof(struct snapfs_batch_continuation, version) -
			sizeof(cont->crc));
		if (stored_crc != calc_crc) {
			pr_warn("[snapfs batch] slot %u: cont block %u CRC mismatch, skipping\n",
			        slot_id, seq_no);
			/* CRC 不匹配，跳过这个块但不标记为错误 */
			goto next_cont;
		}

		count = le16_to_cpu(cont->entry_count);
		for (i = 0; i < count && entry_idx < SNAPFS_PROGRESS_BITMAP_BITS; i++)
			ctx->entries[entry_idx++] = cont->entries[i];

next_cont:
		f2fs_put_page(page, 1);
		seq_no++;
	}

	ctx->entry_count = entry_idx;

	return 0;
}

/*
 * 恢复一个 batch slot
 * 根据状态机执行恢复操作
 *
 * 返回值:
 *   0: 恢复完成（可能完成也可能需要继续）
 *   >0: 需要继续处理
 *   <0: 错误
 */
int snapfs_batch_recover_slot(struct f2fs_sb_info *sbi, u32 slot_id)
{
	struct snap_redo_info *redo = sbi->magic_info->redo_info;
	struct page *page;
	struct snapfs_batch_header *header;
	block_t blkaddr;
	u16 state;
	u16 first_zero_bit;
	int ret = 0;

	if (!redo || !redo->batch_mode)
		return -EINVAL;

	if (slot_id >= redo->batch_nr_slots)
		return -EINVAL;

	pr_debug("[snapfs batch] recovering slot %u\n", slot_id);

	/* 读取 slot header */
	blkaddr = redo->journal_blkaddr + slot_id * redo->batch_slot_blocks;
	page = f2fs_get_meta_page(sbi, blkaddr);
	if (IS_ERR(page))
		return PTR_ERR(page);

	header = (struct snapfs_batch_header *)page_address(page);

	/* 验证 header */
	if (le32_to_cpu(header->magic) != SNAP_REDO_MAGIC ||
	    le16_to_cpu(header->version) != SNAP_REDO_VERSION) {
		/* 无效 slot，视为 EMPTY */
		f2fs_put_page(page, 1);
		pr_debug("[snapfs batch] slot %u: invalid magic/version, treating as EMPTY\n", slot_id);
		return 0;
	}

	state = le16_to_cpu(header->state);
	f2fs_put_page(page, 1);

	switch (state) {
	case SNAPFS_BATCH_EMPTY:
	case SNAPFS_BATCH_APPLIED:
		/* 槽已完整结束，无需恢复 */
		pr_debug("[snapfs batch] slot %u: state=%u, no recovery needed\n", slot_id, state);
		ret = 0;
		break;

	case SNAPFS_BATCH_PREPARING: {
		/*
		 * PREPARING 期间崩溃
		 * 检查 prepared 标志：
		 *   - prepared=0：批量写入未完成，丢弃
		 *   - prepared=1：批量写入已完成，视为 COMMITTED 继续恢复
		 * 设计文档 Section 8.2 要求检查 prepared 标志判断完整性
		 */
		struct page *header_page;
		struct snapfs_batch_header *header;
		block_t header_blkaddr;
		u8 prepared;

		header_blkaddr = redo->journal_blkaddr + slot_id * SNAPFS_BATCH_SLOT_BLOCKS;
		header_page = f2fs_get_meta_page(sbi, header_blkaddr);
		if (IS_ERR(header_page)) {
			pr_warn("[snapfs batch] slot %u: failed to get header page, treating as incomplete\n",
			         slot_id);
			/* header 无法读取，视为不完整，清理槽位 */
			goto preparing_discard;
		}

		header = (struct snapfs_batch_header *)page_address(header_page);
		prepared = header->prepared;
		f2fs_put_page(header_page, 1);

		if (prepared == 0) {
			/* prepared=0：批量写入未完成，需要清理槽位 */
			pr_debug("[snapfs batch] slot %u: PREPARING crash, prepared=0, discarding\n",
			         slot_id);
			goto preparing_discard;
		}

		/*
		 * prepared=1：批量写入已完成，redo 数据已 durable
		 * 视为 COMMITTED 状态，继续恢复
		 * 跳转到 COMMITTED/APPLYING 处理逻辑
		 */
		pr_info("[snapfs batch] slot %u: PREPARING crash but prepared=1, treating as COMMITTED\n",
		        slot_id);
		goto batch_resume_from_bitmap;
	}

preparing_discard:
		{
			u32 slot_start_blk;
			u32 i;
			block_t start_blkaddr = redo->journal_blkaddr;

			/* 计算当前槽位对应的起始块地址 */
			slot_start_blk = start_blkaddr + slot_id * SNAPFS_BATCH_SLOT_BLOCKS;

			/* 清理所有 SNAPFS_BATCH_SLOT_BLOCKS 个块 */
			for (i = 0; i < SNAPFS_BATCH_SLOT_BLOCKS; i++) {
				block_t blkaddr = slot_start_blk + i;
				struct page *p = f2fs_get_meta_page(sbi, blkaddr);
				if (IS_ERR(p)) {
					pr_warn("[snapfs batch] slot %u block %u: get page failed\n",
					        slot_id, i);
					continue;
				}

				/* 清空块内容并设置为 EMPTY 状态 */
				memset(page_address(p), 0, PAGE_SIZE);
				if (i == 0) {
					/* block 0 是 header block */
					struct snapfs_batch_header *h = page_address(p);
					h->magic = cpu_to_le32(SNAP_REDO_MAGIC);
					h->version = cpu_to_le16(SNAP_REDO_VERSION);
					h->state = cpu_to_le16(SNAPFS_BATCH_EMPTY);
				} else {
					/* 其他块是 continuation block */
					struct snapfs_batch_continuation *c = page_address(p);
					c->magic = cpu_to_le32(SNAP_REDO_MAGIC);
					c->version = cpu_to_le16(SNAP_REDO_VERSION);
				}
				set_page_dirty(p);
				snapfs_flush_locked_meta_page(sbi, p);
				/* snapfs_flush_locked_meta_page unlocks but doesn't release */
				f2fs_put_page(p, 0);
			}
			pr_debug("[snapfs batch] slot %u: cleaned all %d blocks\n",
			         slot_id, SNAPFS_BATCH_SLOT_BLOCKS);
		}
		ret = 0;
		break;

	case SNAPFS_BATCH_COMMITTED:
	case SNAPFS_BATCH_APPLYING:
batch_resume_from_bitmap: {
		/*
		 * 比对式恢复（基于 redo）：
		 * 1. 遍历所有 entries
		 * 2. 对每个 entry，读取当前状态并与 redo 比对
		 * 3. 如果不一致，按 redo 恢复
		 * 4. 收集 dirty pages 后统一 flush
		 * 5. 标记为 APPLIED
		 */
		u16 i;
		struct snapfs_batch_context *ctx_ptr;
		u16 restore_count = 0;

		pr_debug("[snapfs batch] slot %u: COMMITTED/APPLYING, comparison-based recovery\n", slot_id);

		/* 使用动态分配避免大帧栈 */
		ctx_ptr = kzalloc(sizeof(*ctx_ptr), GFP_KERNEL);
		if (!ctx_ptr) {
			pr_err("[snapfs batch] slot %u: failed to allocate context\n", slot_id);
			ret = -ENOMEM;
			break;
		}

		ctx_ptr->sbi = sbi;
		ctx_ptr->slot_id = slot_id;
		ctx_ptr->entry_capacity = SNAPFS_PROGRESS_BITMAP_BITS;
		ctx_ptr->current_bit = 0;

		/* 读取 batch 内容 */
		ret = snapfs_batch_read_redo(sbi, slot_id, ctx_ptr);
		if (ret) {
			pr_err("[snapfs batch] slot %u: failed to read redo\n", slot_id);
			/* BUG FIX: 需要释放 slot */
			__clear_bit(slot_id, redo->batch_slot_inuse_bitmap);
			snapfs_batch_free_slot(sbi, slot_id);
			kfree(ctx_ptr);
			break;
		}

		/*
		 * 比对式恢复：遍历所有 entries，逐个比对当前状态与 redo
		 * - 如果一致，跳过
		 * - 如果不一致，按 redo 恢复
		 */
		pr_info("[snapfs batch] slot %u: checking %u entries for comparison recovery\n",
		        slot_id, ctx_ptr->valid_bits);

		/* 设置 slot 为 in-use（防止其他操作覆盖） */
		__set_bit(slot_id, redo->batch_slot_inuse_bitmap);
		ctx_ptr->state = SNAPFS_BATCH_APPLYING;

		/* 清空 dirty 数组（ctx_ptr 是 kzalloc 分配的，理论上已是 0，但确保安全） */
		ctx_ptr->dirty_sum_count = 0;
		memset(ctx_ptr->dirty_sum_pages, 0, sizeof(ctx_ptr->dirty_sum_pages));
		memset(ctx_ptr->dirty_sum_segno, 0, sizeof(ctx_ptr->dirty_sum_segno));
		ctx_ptr->dirty_sit_count = 0;
		memset(ctx_ptr->dirty_sit_pages, 0, sizeof(ctx_ptr->dirty_sit_pages));
		memset(ctx_ptr->dirty_sit_blkaddr, 0, sizeof(ctx_ptr->dirty_sit_blkaddr));
		if (ctx_ptr->dirty_mr_page) {
			f2fs_put_page(ctx_ptr->dirty_mr_page, 1);
			ctx_ptr->dirty_mr_page = NULL;
		}

		/* 从 entries 收集所有 segno 到 dirty_sum_segno[]（与 commit 路径相同的修复） */
		{
			unsigned int segno;
			unsigned int j;
			bool found;
			u16 k;

			for (j = 0; j < ctx_ptr->entry_count; j++) {
				struct snapfs_batch_entry *e = &ctx_ptr->entries[j];
				block_t data_blkaddr = le32_to_cpu(e->data_blkaddr);

				if (data_blkaddr == 0)
					continue;

				segno = GET_SEGNO(sbi, data_blkaddr);

				/* 检查是否已存在（去重） */
				found = false;
				for (k = 0; k < ctx_ptr->dirty_sum_count; k++) {
					if (ctx_ptr->dirty_sum_segno[k] == segno) {
						found = true;
						break;
					}
				}

				if (!found && ctx_ptr->dirty_sum_count < 512) {
					ctx_ptr->dirty_sum_segno[ctx_ptr->dirty_sum_count] = segno;
					pr_info("[snapfs batch] recovery: SET dirty_sum[%u]=%u from entry %u\n",
					         ctx_ptr->dirty_sum_count, segno, j);
					ctx_ptr->dirty_sum_count++;
				}
			}
			pr_info("[snapfs batch] recovery: collected %u unique segnos from %u entries\n",
			        ctx_ptr->dirty_sum_count, ctx_ptr->entry_count);
		}

		/* 循环遍历所有 entries，进行比对和恢复 */
		for (i = 0; i < ctx_ptr->valid_bits; i++) {
			struct snapfs_batch_entry *entry = &ctx_ptr->entries[i];
			struct page *mr_page = NULL;
			struct f2fs_mulref_block *mr_blk;
			u16 mr_idx;
			bool need_restore = false;
			block_t data_blkaddr;
			unsigned int segno;
			unsigned int blkoff;
			block_t sit_blkaddr;
			struct page *sum_page = NULL;
			struct f2fs_summary_block *sum_blk;
			struct page *sit_page = NULL;
			struct f2fs_sit_mulref_block *sit_blk;
			unsigned int sit_off;
			bool sum_match = true;
			bool sit_match = true;

			/* 1. 检查 mulref 状态 */
			mr_page = f2fs_get_meta_page(sbi, le32_to_cpu(entry->mulref.mr_blkaddr));
			if (IS_ERR(mr_page)) {
				ret = PTR_ERR(mr_page);
				mr_page = NULL;
				goto recovery_error;
			}
			mr_blk = page_address(mr_page);
			mr_idx = le16_to_cpu(entry->mulref.idx);

			/* 比较 multi_bitmap */
			if (entry->mulref.valid) {
				if (!f2fs_test_bit(mr_idx, (char *)mr_blk->multi_bitmap))
					need_restore = true;
				/* 比较 mrentries 内容 */
				else if (memcmp(&mr_blk->mrentries[mr_idx], &entry->mulref.entry,
						sizeof(entry->mulref.entry)) != 0)
					need_restore = true;
			} else {
				if (f2fs_test_bit(mr_idx, (char *)mr_blk->multi_bitmap))
					need_restore = true;
			}

			/* 2. 检查 summary 状态 */
			if (entry->data_blkaddr != 0 && !need_restore) {
				data_blkaddr = le32_to_cpu(entry->data_blkaddr);
				segno = GET_SEGNO(sbi, data_blkaddr);
				blkoff = GET_BLKOFF_FROM_SEG0(sbi, data_blkaddr);

				/* 使用 f2fs_get_meta_page 避免阻塞等待 I/O */
				sum_page = f2fs_get_meta_page(sbi, GET_SUM_BLOCK(sbi, segno));
				if (IS_ERR(sum_page)) {
					ret = PTR_ERR(sum_page);
					sum_page = NULL;
					f2fs_put_page(mr_page, 1);
					goto recovery_error;
				}
				sum_blk = page_address(sum_page);

				/* 比较 summary entry */
				if (memcmp(&sum_blk->entries[blkoff], &entry->sum.sum,
					   sizeof(entry->sum.sum)) != 0)
					sum_match = false;
			}

			/* 3. 检查 SIT 状态 */
			if (entry->data_blkaddr != 0 && !need_restore && !sum_match) {
				data_blkaddr = le32_to_cpu(entry->data_blkaddr);
				sit_blkaddr = SIT_MR_I(sbi)->base_addr +
					(GET_SEGNO(sbi, data_blkaddr) / SIT_MR_I(sbi)->sments_per_block);

				sit_page = f2fs_get_meta_page(sbi, sit_blkaddr);
				if (IS_ERR(sit_page)) {
					ret = PTR_ERR(sit_page);
					sit_page = NULL;
					f2fs_put_page(sum_page, 1);
					f2fs_put_page(mr_page, 1);
					goto recovery_error;
				}
				sit_blk = page_address(sit_page);
				sit_off = GET_SEGNO(sbi, data_blkaddr) % SIT_MR_I(sbi)->sments_per_block;

				/* 比较 SIT mvalid_map */
				if (entry->sit_set) {
					if (!f2fs_test_bit(blkoff, (char *)sit_blk->entries[sit_off].mvalid_map))
						sit_match = false;
				} else {
					if (f2fs_test_bit(blkoff, (char *)sit_blk->entries[sit_off].mvalid_map))
						sit_match = false;
				}
			}

			/* 判断是否需要恢复 */
			need_restore = need_restore || !sum_match || !sit_match;

			/* 释放用于比对的 pages */
			if (sit_page) f2fs_put_page(sit_page, 1);
			if (sum_page) f2fs_put_page(sum_page, 1);
			f2fs_put_page(mr_page, 1);

			if (!need_restore) {
				pr_debug("[snapfs batch] slot %u: entry %u matches redo, skipping\n",
				         slot_id, i);
				continue;
			}

			/* 需要恢复，调用 apply_one 收集 dirty pages */
			pr_debug("[snapfs batch] slot %u: entry %u inconsistent, restoring\n",
			         slot_id, i);

			ret = snapfs_batch_apply_one(sbi, ctx_ptr, i);
			if (ret) {
				pr_err("[snapfs batch] slot %u: apply bit %u failed: %d\n",
				       slot_id, i, ret);
				goto recovery_error;
			}
			restore_count++;
			pr_debug("[snapfs batch] slot %u: applied entry %u/%u\n",
			         slot_id, i + 1, ctx_ptr->valid_bits);
		}

		if (restore_count == 0) {
			/* 所有 entries 都一致，无需恢复，标记为 APPLIED */
			pr_info("[snapfs batch] slot %u: all %u entries match redo, no restore needed\n",
			        slot_id, ctx_ptr->valid_bits);
			ret = snapfs_batch_mark_applied(sbi, ctx_ptr);
			/* 关键修复：清理可能阻塞的 overwrite slot */
			snapfs_batch_clear_stale_overwrite(sbi);
			__clear_bit(slot_id, redo->batch_slot_inuse_bitmap);
			snapfs_batch_free_slot(sbi, slot_id);
			kfree(ctx_ptr);
			break;
		}

		pr_info("[snapfs batch] slot %u: restored %u/%u entries\n",
		        slot_id, restore_count, ctx_ptr->valid_bits);

recovery_error:
		/* 清理收集的 dirty pages */
		if (ctx_ptr->dirty_mr_page) {
			/* 关键修复：先检查 page 是否已锁定，避免 double-unlock */
			if (PageLocked(ctx_ptr->dirty_mr_page))
				unlock_page(ctx_ptr->dirty_mr_page);
			put_page(ctx_ptr->dirty_mr_page);  /* 使用 put_page 而非 f2fs_put_page(..., 1) */
			ctx_ptr->dirty_mr_page = NULL;
			ctx_ptr->cur_mr_blkaddr = 0;  /* 重置当前 mulref block 地址 */
		}
		for (i = 0; i < ctx_ptr->dirty_sum_count; i++) {
			if (ctx_ptr->dirty_sum_pages[i]) {
				f2fs_put_page(ctx_ptr->dirty_sum_pages[i], 1);
				ctx_ptr->dirty_sum_pages[i] = NULL;
			}
		}
		ctx_ptr->dirty_sum_count = 0;
		for (i = 0; i < ctx_ptr->dirty_sit_count; i++) {
			if (ctx_ptr->dirty_sit_pages[i]) {
				f2fs_put_page(ctx_ptr->dirty_sit_pages[i], 1);
				ctx_ptr->dirty_sit_pages[i] = NULL;
			}
		}
		ctx_ptr->dirty_sit_count = 0;

		/* 批量 flush 所有收集的 dirty pages */
		ret = snapfs_batch_flush_all(sbi, ctx_ptr);
		if (ret) {
			pr_err("[snapfs batch] slot %u: flush all failed: %d\n",
			       slot_id, ret);
			snapfs_batch_mark_applied(sbi, ctx_ptr);
			/* 关键修复：清理可能阻塞的 overwrite slot */
			snapfs_batch_clear_stale_overwrite(sbi);
			__clear_bit(slot_id, redo->batch_slot_inuse_bitmap);
			snapfs_batch_free_slot(sbi, slot_id);
			kfree(ctx_ptr);
			return ret;
		}

		/* 更新 bitmap（标记所有 entry 已完成） */
		for (i = 0; i < ctx_ptr->valid_bits; i++)
			f2fs_set_bit(i, ctx_ptr->bitmap);

		/* 所有 bits 都已 apply，标记为 APPLIED */
		pr_info("[snapfs batch] slot %u: all %u bits applied and flushed, marking APPLIED\n",
		        slot_id, ctx_ptr->valid_bits);
		ret = snapfs_batch_mark_applied(sbi, ctx_ptr);
		/* 关键修复：清理可能阻塞的 overwrite slot */
		snapfs_batch_clear_stale_overwrite(sbi);

		/* 释放 slot */
		__clear_bit(slot_id, redo->batch_slot_inuse_bitmap);
		snapfs_batch_free_slot(sbi, slot_id);

		kfree(ctx_ptr);
		ret = 0;
		break;
	}

	default:
		pr_warn("[snapfs batch] slot %u: unknown state %u\n", slot_id, state);
		ret = -EINVAL;
		break;
	}

	return ret;
}

/*
 * 对 batch 中指定 bit 执行 apply（收集 dirty pages，不立即 flush）
 * 从 ctx->entries 中找到对应的 redo 项并执行
 *
 * 优化后不再逐块 flush，而是收集到 ctx 的 dirty page 列表中
 * 收集后立即释放 lock，避免阻塞其他线程
 * 统一的 flush 在 snapfs_batch_flush_all() 中进行
 *
 * 返回值：
 *   0: 成功
 *   <0: 错误
 */
int snapfs_batch_apply_one(struct f2fs_sb_info *sbi, struct snapfs_batch_context *ctx,
                           u16 bitno)
{
    struct snapfs_batch_entry *entry = NULL;
    struct page *sum_page = NULL;
    struct page *sit_page = NULL;
    struct f2fs_mulref_block *mulref_blk = NULL;
    struct f2fs_summary_block *sum_blk = NULL;
    struct f2fs_sit_mulref_block *sit_blk = NULL;
    u16 mulref_idx;
    block_t data_blkaddr = 0;  /* 初始化为0，用于一致性检查 */
    unsigned int segno;
    unsigned int blkoff;
    unsigned int sit_off;
    block_t sit_blkaddr;
    bool need_sum_page = false;
    bool need_sit_page = false;
    u16 i;
    int ret = 0;

    if (!sbi || !ctx)
        return -EINVAL;

    if (bitno >= ctx->valid_bits)
        return -EINVAL;

    /* 清空 dirty 数组，避免残留数据导致不一致 */
    /* 关键修复：即使 snapfs_batch_begin() 已经清空，
     * 在 recovery 路径中 ctx 可能是从磁盘读取的，需要确保干净状态 */
    if (bitno == 0) {
        ctx->dirty_sum_count = 0;
        memset(ctx->dirty_sum_pages, 0, sizeof(ctx->dirty_sum_pages));
        memset(ctx->dirty_sum_segno, 0, sizeof(ctx->dirty_sum_segno));

        ctx->dirty_sit_count = 0;
        memset(ctx->dirty_sit_pages, 0, sizeof(ctx->dirty_sit_pages));
        memset(ctx->dirty_sit_blkaddr, 0, sizeof(ctx->dirty_sit_blkaddr));

        if (ctx->dirty_mr_page) {
            set_page_dirty(ctx->dirty_mr_page);
            /* 关键修复：先检查 page 是否已锁定，避免 double-unlock */
            if (PageLocked(ctx->dirty_mr_page))
                unlock_page(ctx->dirty_mr_page);
            put_page(ctx->dirty_mr_page);  /* 使用 put_page 而非 f2fs_put_page(..., 1) */
            ctx->dirty_mr_page = NULL;
        }
        ctx->cur_mr_blkaddr = 0;

        pr_info("[snapfs batch] slot %u: cleared dirty arrays at bitno=0\n", ctx->slot_id);
    }

    /* 在 entries 中查找 bitno 对应的项 */
    for (i = 0; i < ctx->entry_count; i++) {
        if (i == bitno) {
            entry = &ctx->entries[i];
            break;
        }
    }

    if (!entry) {
        pr_warn("[snapfs batch] slot %u: no redo entry for bit %u\n",
                ctx->slot_id, bitno);
        return 0;  /* 没有 redo 项，跳过 */
    }

    pr_info("[snapfs batch] slot %u: applying bit %u, mr_blkaddr=%u\n",
             ctx->slot_id, bitno, le32_to_cpu(entry->mulref.mr_blkaddr));

    /* ================================================================ */
    /* 1. 执行 mulref 更新（需要处理跨页情况）                           */
    /* 参考 curmulref_alloc_entry() 的换页逻辑                            */
    /* ================================================================ */
    {
        block_t new_mr_blkaddr = le32_to_cpu(entry->mulref.mr_blkaddr);
        mulref_idx = le16_to_cpu(entry->mulref.idx);

        /* === 检查是否需要切换 mulref page === */
        if (!ctx->dirty_mr_page || ctx->cur_mr_blkaddr != new_mr_blkaddr) {
            /* 需要切换到新的 mulref block */
            if (ctx->dirty_mr_page) {
                /* 刷新并释放旧的 page */
                set_page_dirty(ctx->dirty_mr_page);
                /* 关键修复：先检查 page 是否已锁定，避免 double-unlock
                 * 在 out: 标签处可能已解锁 dirty_mr_page，所以这里需要检查 */
                if (PageLocked(ctx->dirty_mr_page))
                    unlock_page(ctx->dirty_mr_page);
                put_page(ctx->dirty_mr_page);  /* 使用 put_page 而非 f2fs_put_page(..., 1) */
                ctx->dirty_mr_page = NULL;
            }

            pr_info("[snapfs batch] slot %u: switching to new mr_blkaddr=%u (old=%u)\n",
                    ctx->slot_id, new_mr_blkaddr, ctx->cur_mr_blkaddr);
            ctx->dirty_mr_page = f2fs_get_meta_page(sbi, new_mr_blkaddr);
            if (IS_ERR(ctx->dirty_mr_page)) {
                ret = PTR_ERR(ctx->dirty_mr_page);
                ctx->dirty_mr_page = NULL;
                ctx->cur_mr_blkaddr = 0;
                return ret;
            }
            ctx->cur_mr_blkaddr = new_mr_blkaddr;
        }

        /* === 检查 mulref_idx 是否在有效范围内 === */
        /* 关键修复：如果 idx >= MRENTRY_PER_BLOCK，说明 entry 数据可能损坏，
         * 或者这是一个跨页的 entry，需要重新计算 block 地址 */
        if (mulref_idx >= MRENTRY_PER_BLOCK) {
            pr_err("[snapfs batch] slot %u: BUG mulref_idx=%u >= MRENTRY_PER_BLOCK=%u, "
                   "mr_blkaddr=%u, entry_idx=%u\n",
                   ctx->slot_id, mulref_idx, MRENTRY_PER_BLOCK,
                   new_mr_blkaddr, bitno);

            /* 尝试计算正确的 block 地址和索引 */
            /* idx 是相对于 mulref area 起始位置的全局索引，需要计算 block 偏移 */
            if (mulref_idx < MRENTRY_PER_BLOCK * 256) {  /* 合理范围内 */
                u16 block_offset = mulref_idx / MRENTRY_PER_BLOCK;
                u16 correct_idx = mulref_idx % MRENTRY_PER_BLOCK;

                /*
                 * 修复: 正确计算 mulref block 地址
                 * mulref blocks 在 mulref 区域内连续排列
                 * 地址 = mulref 区域起始地址 + block 偏移
                 */
                block_t mr_base = sbi->magic_info->mulref_blkaddr;
                block_t correct_blkaddr = mr_base + block_offset;

                pr_warn("[snapfs batch] slot %u: idx=%u exceeds block, "
                        "correcting to blkaddr=%u (mr_base=%u, offset=%u), idx=%u\n",
                        ctx->slot_id, mulref_idx,
                        correct_blkaddr, mr_base, block_offset, correct_idx);

                /* 切换到正确的 block */
                if (ctx->dirty_mr_page) {
                    set_page_dirty(ctx->dirty_mr_page);
                    /* 关键修复：先检查 page 是否已锁定，避免 double-unlock */
                    if (PageLocked(ctx->dirty_mr_page))
                        unlock_page(ctx->dirty_mr_page);
                    put_page(ctx->dirty_mr_page);  /* 使用 put_page 而非 f2fs_put_page(..., 1) */
                    ctx->dirty_mr_page = NULL;
                }

                ctx->dirty_mr_page = f2fs_get_meta_page(sbi, correct_blkaddr);
                if (IS_ERR(ctx->dirty_mr_page)) {
                    ret = PTR_ERR(ctx->dirty_mr_page);
                    ctx->dirty_mr_page = NULL;
                    ctx->cur_mr_blkaddr = 0;
                    return ret;
                }
                ctx->cur_mr_blkaddr = correct_blkaddr;
                mulref_idx = correct_idx;
            } else {
                /* idx 超出合理范围，数据损坏 */
                pr_err("[snapfs batch] slot %u: mulref_idx=%u out of reasonable range, "
                       "skipping entry\n", ctx->slot_id, mulref_idx);
                return -EINVAL;
            }
        }

        /* 检查 dirty_mr_page 是否有效（适用于所有情况） */
        if (IS_ERR(ctx->dirty_mr_page) || !ctx->dirty_mr_page) {
            pr_err("[snapfs batch] slot %u: FAILED to get mr_page for blkaddr=%u\n",
                   ctx->slot_id, new_mr_blkaddr);
            return -EIO;
        }

        mulref_blk = (struct f2fs_mulref_block *)page_address(ctx->dirty_mr_page);
        if (!mulref_blk) {
            pr_err("[snapfs batch] slot %u: page_address returned NULL for mr_page\n",
                   ctx->slot_id);
            return -EIO;
        }

        /* === 执行 mulref 更新 === */
        if (entry->mulref.valid) {
            bool was_valid = f2fs_test_bit(mulref_idx, (char *)mulref_blk->multi_bitmap);
            struct f2fs_mulref_entry old_entry = mulref_blk->mrentries[mulref_idx];

            if (!was_valid) {
                f2fs_set_bit(mulref_idx, (char *)mulref_blk->multi_bitmap);
                mulref_blk->v_mrentrys = cpu_to_le16(
                    le16_to_cpu(mulref_blk->v_mrentrys) + 1);
            }

            /* === 方案4修复: 添加 mulref entry 一致性检查 === */
            /* 在写入 mulref entry 之前验证 m_nid 是否有效 */
            {
                block_t entry_m_nid = le32_to_cpu(entry->mulref.entry.m_nid);
                block_t mr_base = sbi->magic_info->mulref_blkaddr;
                block_t mr_end = mr_base + MAGIC_MAX;

                /* 简单检查：m_nid 不应该是另一个 mulref block 的地址 */
                if (entry_m_nid >= mr_base && entry_m_nid < mr_end) {
                    f2fs_err(sbi, "[snapfs batch] FATAL: mulref entry m_nid=%u points to mulref block!",
                             entry_m_nid);
                    f2fs_err(sbi, "  mr_blkaddr=%u, idx=%u, bitno=%u, data_blkaddr=%u",
                             new_mr_blkaddr, mulref_idx, bitno,
                             entry->data_blkaddr ? le32_to_cpu(entry->data_blkaddr) : 0);
                    ret = -EINVAL;
                    goto out;
                }
            }

            /* 调试: 打印 mulref entry 写入信息 */
            pr_info("[snapfs batch] WRITE mulref: bitno=%u, mr_blkaddr=%u, idx=%u, "
                    "new.m_nid=%u, new.m_ofs=%u, new.m_count=%u, new.next=%u, "
                    "old.m_nid=%u, old.m_ofs=%u, old.m_count=%u, old.next=%u, "
                    "was_valid=%d\n",
                    bitno, new_mr_blkaddr, mulref_idx,
                    le32_to_cpu(entry->mulref.entry.m_nid),
                    le16_to_cpu(entry->mulref.entry.m_ofs),
                    entry->mulref.entry.m_count,
                    le32_to_cpu(entry->mulref.entry.next),
                    le32_to_cpu(old_entry.m_nid),
                    le16_to_cpu(old_entry.m_ofs),
                    old_entry.m_count,
                    le32_to_cpu(old_entry.next),
                    was_valid);

            mulref_blk->mrentries[mulref_idx] = entry->mulref.entry;
        } else {
            mulref_mark_invalid(mulref_blk, mulref_idx);
            memset(&mulref_blk->mrentries[mulref_idx], 0,
                   sizeof(struct f2fs_mulref_entry));
        }
        /* 注意：不在这里 set_page_dirty，延后到 flush 或切换 page 时 */
        /* set_page_dirty(ctx->dirty_mr_page); */
    }

    /* 2. 处理 summary 和 SIT（检查是否需要获取新 page） */
    pr_info("[snapfs batch] apply_one: entry->data_blkaddr=%u, entry->flags=0x%x\n",
            entry->data_blkaddr, entry->flags);

    if (entry->data_blkaddr != 0) {
        data_blkaddr = le32_to_cpu(entry->data_blkaddr);
        segno = GET_SEGNO(sbi, data_blkaddr);
        blkoff = GET_BLKOFF_FROM_SEG0(sbi, data_blkaddr);
        sit_blkaddr = SIT_MR_I(sbi)->base_addr +
            (GET_SEGNO(sbi, data_blkaddr) / SIT_MR_I(sbi)->sments_per_block);

        /* 检查 summary page 是否已在 dirty list 中（按 segno 去重） */
        /* 关键修复：直接遍历 dirty_sum_segno[] 数组检查，因为该数组在 apply_one 过程中
         * 会逐步填充正确的 segno 值。dirty_sum_pages_bitmap 是用于 lazy reload 的，
         * 不能作为去重的依据（因为它在 apply_one 开始时可能不包含当前 batch 的数据） */
        {
            bool already_have = false;

            /* 遍历 dirty_sum_segno[] 检查是否已有该 segno */
            for (i = 0; i < ctx->dirty_sum_count; i++) {
                if (ctx->dirty_sum_segno[i] == segno) {
                    already_have = true;
                    break;
                }
            }

            if (!already_have) {
                need_sum_page = true;
            }
        }

        /* 检查 SIT page 是否已在 dirty list 中（按 sit_blkaddr 去重） */
        for (i = 0; i < ctx->dirty_sit_count; i++) {
            if (ctx->dirty_sit_blkaddr[i] == sit_blkaddr) {
                /* 已存在，使用该 page */
                break;
            }
        }
        if (i >= ctx->dirty_sit_count) {
            /* 需要获取新的 sit page */
            need_sit_page = true;
        }

        /* 获取 sum page（如果需要） */
        if (need_sum_page && ctx->dirty_sum_count < 512) {
            sum_page = f2fs_get_meta_page(sbi, GET_SUM_BLOCK(sbi, segno));
            if (IS_ERR(sum_page)) {
                ret = PTR_ERR(sum_page);
                pr_err("[snapfs batch] slot %u: get sum page failed: %d\n",
                       ctx->slot_id, ret);
                /* 清理已获取的 pages */
                if (ctx->dirty_mr_page && PageLocked(ctx->dirty_mr_page))
                    unlock_page(ctx->dirty_mr_page);
                goto out;
            }
            /* 关键调试：打印 dirty_sum_segno[] 写入时的详细信息 */
            pr_info("[snapfs batch] SET dirty_sum[%u]=%u (bitno=%u, src=%u, snap=%u)\n",
                    ctx->dirty_sum_count, segno, bitno, ctx->src_ino, ctx->snap_ino);
            ctx->dirty_sum_pages[ctx->dirty_sum_count] = sum_page;
            ctx->dirty_sum_segno[ctx->dirty_sum_count] = segno;
            ctx->dirty_sum_count++;
        }

        /* 获取 SIT page（如果需要） */
        if (need_sit_page && ctx->dirty_sit_count < 256) {
            sit_page = f2fs_get_meta_page(sbi, sit_blkaddr);
            if (IS_ERR(sit_page)) {
                ret = PTR_ERR(sit_page);
                pr_err("[snapfs batch] slot %u: get sit page failed: %d\n",
                       ctx->slot_id, ret);
                /* 清理已获取的 pages */
                if (ctx->dirty_mr_page && PageLocked(ctx->dirty_mr_page))
                    unlock_page(ctx->dirty_mr_page);
                if (sum_page && PageLocked(sum_page))
                    unlock_page(sum_page);
                goto out;
            }
            ctx->dirty_sit_pages[ctx->dirty_sit_count] = sit_page;
            ctx->dirty_sit_blkaddr[ctx->dirty_sit_count] = sit_blkaddr;
            ctx->dirty_sit_count++;
        }
    }

out:
    /* 释放 pages 的 lock */
    if (ctx->dirty_mr_page && PageLocked(ctx->dirty_mr_page))
        unlock_page(ctx->dirty_mr_page);
    for (i = 0; i < ctx->dirty_sum_count; i++) {
        if (ctx->dirty_sum_pages[i] && PageLocked(ctx->dirty_sum_pages[i]))
            unlock_page(ctx->dirty_sum_pages[i]);
    }
    for (i = 0; i < ctx->dirty_sit_count; i++) {
        if (ctx->dirty_sit_pages[i] && PageLocked(ctx->dirty_sit_pages[i]))
            unlock_page(ctx->dirty_sit_pages[i]);
    }

    if (ret)
        return ret;

    /* 3. 执行 summary 和 SIT 的修改（对所有已收集的 dirty pages） */
    /* Summary 修改 - 找到对应的 sum page 并写入 */
    {
        struct sit_mulref_info *smi = SIT_MR_I(sbi);
        bool found = false;

        for (i = 0; i < ctx->dirty_sum_count; i++) {
            block_t page_segno = ctx->dirty_sum_segno[i];

            /* 安全检查：segno 必须在有效范围内 */
            if (page_segno >= MAIN_SEGS(sbi)) {
                pr_warn("[snapfs batch] WARN: dirty_sum[%u]=%u out of range (max=%u)\n",
                        i, page_segno, MAIN_SEGS(sbi) - 1);
                continue;
            }

            /* 匹配条件（双重检查） */
            bool segno_match = (page_segno == segno);
            /* 关键修复：检查 segno（正确值）是否在 bitmap 中，而不是 page_segno（垃圾值） */
            bool bitmap_match = (smi && smi->dirty_sum_pages_bitmap &&
                                 test_bit(segno, smi->dirty_sum_pages_bitmap));

            if (segno_match || bitmap_match) {
                struct f2fs_summary old_sum_in_ssa;
                sum_blk = (struct f2fs_summary_block *)
                    page_address(ctx->dirty_sum_pages[i]);

                /* 保存写入前的 SSA 值（用于调试） */
                old_sum_in_ssa = sum_blk->entries[blkoff];

                /* 调试: 打印即将写入的 summary 值 */
                pr_info("[snapfs batch] WRITE sum: bitno=%u, segno=%u, blkoff=%u, "
                        "entry->sum.sum.nid=%u, entry->sum.sum.ofs=%u, "
                        "entry->mulref.mr_blkaddr=%u, entry->mulref.idx=%u, "
                        "match=%s, old_ssa.nid=%u, old_ssa.ofs=%u\n",
                        bitno, segno, blkoff,
                        le32_to_cpu(entry->sum.sum.nid),
                        le16_to_cpu(entry->sum.sum.ofs_in_node),
                        le32_to_cpu(entry->mulref.mr_blkaddr),
                        le16_to_cpu(entry->mulref.idx),
                        segno_match ? "segno" : "bitmap",
                        le32_to_cpu(old_sum_in_ssa.nid),
                        le16_to_cpu(old_sum_in_ssa.ofs_in_node));

                sum_blk->entries[blkoff] = entry->sum.sum;
                set_page_dirty(ctx->dirty_sum_pages[i]);
                /* 标记该 summary page 为脏，确保后续读取从 SSA */
                mark_sum_page_dirty(sbi, segno);
                found = true;
                break;
            }
        }

        if (!found) {
            bool bitmap_set = smi && smi->dirty_sum_pages_bitmap &&
                             test_bit(segno, smi->dirty_sum_pages_bitmap);
            pr_err("[snapfs batch] FATAL: SSA write skipped for segno=%u, blkoff=%u, "
                   "data_blkaddr=%u, bitno=%u, dirty_sum_count=%u, bitmap_set=%d\n",
                   segno, blkoff, data_blkaddr, bitno, ctx->dirty_sum_count, bitmap_set);

            /* 调试：打印 dirty_sum_segno[] 的内容 */
            pr_err("[snapfs batch] dirty_sum_segno[] contents (%u entries):\n",
                   ctx->dirty_sum_count);
            for (i = 0; i < ctx->dirty_sum_count && i < 32; i++) {
                pr_err("  dirty_sum[%u] = %u\n", i, ctx->dirty_sum_segno[i]);
            }

            /* 返回错误，让调用者知道 SSA 写入失败 */
            ret = -EIO;
            /* 注意：这里不直接 goto out，因为 sum_page 可能需要清理
             * 调用者会处理错误 */
        }
    }

    /* SIT 修改 */
    for (i = 0; i < ctx->dirty_sit_count; i++) {
        if (ctx->dirty_sit_blkaddr[i] == sit_blkaddr) {
            sit_blk = (struct f2fs_sit_mulref_block *)
                page_address(ctx->dirty_sit_pages[i]);
            sit_off = GET_SEGNO(sbi, data_blkaddr) %
                SIT_MR_I(sbi)->sments_per_block;

            if (entry->sit_set) {
                f2fs_set_bit(blkoff,
                    (char *)sit_blk->entries[sit_off].mvalid_map);
                sit_blk->entries[sit_off].mblocks = cpu_to_le16(
                    le16_to_cpu(sit_blk->entries[sit_off].mblocks) + 1);
            } else {
                f2fs_clear_bit(blkoff,
                    (char *)sit_blk->entries[sit_off].mvalid_map);
                if (le16_to_cpu(sit_blk->entries[sit_off].mblocks) > 0)
                    sit_blk->entries[sit_off].mblocks = cpu_to_le16(
                        le16_to_cpu(sit_blk->entries[sit_off].mblocks) - 1);
            }
            set_page_dirty(ctx->dirty_sit_pages[i]);
            break;
        }
    }

    /* 关键调试：每次 apply 完成时打印 dirty_sum_count 和前几个值 */
    if (bitno == 0 || bitno == 100 || bitno == 200 || bitno == 400 ||
        bitno == 600 || bitno == 800 || bitno >= ctx->entry_count - 1) {
        pr_info("[snapfs batch] APPLY done: bitno=%u, dirty_sum_count=%u, "
                "dirty_sum[0]=%u, dirty_sum[1]=%u, dirty_sum[2]=%u\n",
                bitno, ctx->dirty_sum_count,
                ctx->dirty_sum_count > 0 ? ctx->dirty_sum_segno[0] : 0,
                ctx->dirty_sum_count > 1 ? ctx->dirty_sum_segno[1] : 0,
                ctx->dirty_sum_count > 2 ? ctx->dirty_sum_segno[2] : 0);
    }

    return ret;  /* 返回错误码（如果 SSA 写入被跳过）*/
}

/*
 * 标记 sit page 为脏（需要重新加载）
 * 调用点: snapfs_batch_flush_all() 成功后
 */
static void mark_sit_page_dirty(struct f2fs_sb_info *sbi, block_t sit_blkaddr)
{
    struct sit_mulref_info *smi = SIT_MR_I(sbi);
    unsigned int page_idx;

    if (!smi || !smi->dirty_sit_pages_bitmap)
        return;

    /* 安全检查: 防止下溢 */
    if (sit_blkaddr < smi->base_addr)
        return;
    page_idx = sit_blkaddr - smi->base_addr;
    if (page_idx >= smi->sit_mulref_blocks)
        return;

    down_write(&smi->smentry_lock);
    if (!test_bit(page_idx, smi->dirty_sit_pages_bitmap)) {
        set_bit(page_idx, smi->dirty_sit_pages_bitmap);
        smi->dirty_sit_pages_count++;
    }
    up_write(&smi->smentry_lock);
}

/*
 * 标记 summary page 为脏（需要重新加载）
 * 调用点: snapfs_batch_flush_all() 成功后
 */
static void mark_sum_page_dirty(struct f2fs_sb_info *sbi, unsigned int segno)
{
    struct sit_mulref_info *smi = SIT_MR_I(sbi);

    if (!smi || !smi->dirty_sum_pages_bitmap)
        return;

    /* 边界检查 */
    if (segno >= MAIN_SEGS(sbi))
        return;

    down_write(&smi->smentry_lock);
    if (!test_bit(segno, smi->dirty_sum_pages_bitmap)) {
        set_bit(segno, smi->dirty_sum_pages_bitmap);
        smi->dirty_sum_pages_count++;
    }
    up_write(&smi->smentry_lock);
}

/*
 * 从 sit page 重新加载多引用状态到 smentries
 * 调用点: check_sit_mulref_entry() 检测到脏标记时
 */
static void reload_smentries_from_sit_page(struct f2fs_sb_info *sbi,
    block_t sit_blkaddr)
{
    struct sit_mulref_info *smi = SIT_MR_I(sbi);
    struct f2fs_sit_mulref_block *sit_blk;
    struct page *page;
    unsigned int page_idx;
    unsigned int sments_per_block;
    unsigned int start_segno, end_segno;
    unsigned int i;

    if (!smi || !smi->dirty_sit_pages_bitmap)
        return;

    /* 安全检查 */
    if (sit_blkaddr < smi->base_addr)
        return;
    page_idx = sit_blkaddr - smi->base_addr;
    if (page_idx >= smi->sit_mulref_blocks)
        return;

    /* 检查是否确实需要重新加载 */
    if (!test_bit(page_idx, smi->dirty_sit_pages_bitmap))
        return;

    /* 获取 sit page (可能阻塞，但不持有 smentry_lock) */
    page = f2fs_get_meta_page(sbi, sit_blkaddr);
    if (IS_ERR(page))
        return;

    sit_blk = (struct f2fs_sit_mulref_block *)page_address(page);
    sments_per_block = smi->sments_per_block;

    /* 计算 segno 范围 */
    start_segno = page_idx * sments_per_block;
    end_segno = min(start_segno + sments_per_block, MAIN_SEGS(sbi));

    /* 获取写锁后再次检查 (double-checked locking) */
    down_write(&smi->smentry_lock);

    if (!test_bit(page_idx, smi->dirty_sit_pages_bitmap)) {
        up_write(&smi->smentry_lock);
        f2fs_put_page(page, 1);
        return;
    }

    /* 复制 smentries */
    for (i = 0; i < end_segno - start_segno; i++) {
        struct sit_mulref_entry *sme = &smi->smentries[start_segno + i];
        struct f2fs_sit_mulref_entry *disk_entry = &sit_blk->entries[i];

        memcpy(sme->mvalid_map, disk_entry->mvalid_map, SIT_VBLOCK_MAP_SIZE);
        sme->mblocks = disk_entry->mblocks;
        sme->m_mtime = disk_entry->m_mtime;
    }

    /* 清除脏标记 */
    clear_bit(page_idx, smi->dirty_sit_pages_bitmap);
    smi->dirty_sit_pages_count--;

    /* 先释放锁，再释放 page (避免在持锁时触发 page I/O) */
    up_write(&smi->smentry_lock);
    f2fs_put_page(page, 1);
}

/*
 * 批量 flush 所有 dirty pages
 * 在 snapfs_batch_apply_one 收集完所有 dirty pages 后调用
 *
 * 返回值：
 *   0: 成功
 *   <0: 错误
 */
int snapfs_batch_flush_all(struct f2fs_sb_info *sbi, struct snapfs_batch_context *ctx)
{
    int ret = 0;
    int i;

    if (!sbi || !ctx)
        return -EINVAL;

#if 0
    pr_info("[snapfs batch] slot %u: flushing (mr=%p, sum=%u, sit=%u)\n",
            ctx->slot_id,
            ctx->dirty_mr_page, ctx->dirty_sum_count, ctx->dirty_sit_count);
#endif

    /* 1. Flush mulref page */
    if (ctx->dirty_mr_page) {
        struct page *page = ctx->dirty_mr_page;

#if 0
        /* DEBUG: 打印 mr page 状态 */
        pr_info("[snapfs batch] flush mr: page=%p, refcount=%d, mapcount=%d, dirty=%d, locked=%d\n",
                page, page_ref_count(page), page_mapcount(page),
                PageDirty(page), PageLocked(page));
#endif

        /* 确保 page 被锁定（page_mkclean 要求 page 必须锁定） */
        if (!PageLocked(page)) {
            lock_page(page);
#if 0
            pr_info("[snapfs batch] slot %u: mr page was unlocked, re-locked\n",
                    ctx->slot_id);
#endif
        }

        ret = snapfs_flush_locked_meta_page(sbi, page);
        if (ret) {
            pr_err("[snapfs batch] slot %u: flush mr page failed: %d\n",
                   ctx->slot_id, ret);
            return ret;
        }
        f2fs_put_page(page, 0);
        ctx->dirty_mr_page = NULL;
        ctx->cur_mr_blkaddr = 0;  /* 重置当前 mulref block 地址 */
    }

    /* 2. Flush sum pages */
    for (i = 0; i < ctx->dirty_sum_count; i++) {
        if (ctx->dirty_sum_pages[i]) {
            struct page *page = ctx->dirty_sum_pages[i];

#if 0
            /* DEBUG: 打印每个 sum page 状态 */
            pr_info("[snapfs batch] flush sum[%d]: page=%p, refcount=%d, mapcount=%d, dirty=%d, locked=%d\n",
                    i, page, page_ref_count(page),
                    page_mapcount(page), PageDirty(page), PageLocked(page));
#endif

            /* 确保 page 被锁定 */
            if (!PageLocked(page)) {
                lock_page(page);
#if 0
                pr_info("[snapfs batch] slot %u: sum page[%d] was unlocked, re-locked\n",
                        ctx->slot_id, i);
#endif
            }

            ret = snapfs_flush_locked_meta_page(sbi, page);
            if (ret) {
                pr_err("[snapfs batch] slot %u: flush sum page %u failed: %d\n",
                       ctx->slot_id, i, ret);
                /* 继续 flush 其他 pages */
            }
            f2fs_put_page(page, 0);
            ctx->dirty_sum_pages[i] = NULL;

            /* === 新增: 标记该 summary page 为脏（需要重新加载）=== */
            mark_sum_page_dirty(sbi, ctx->dirty_sum_segno[i]);
        }
    }
    ctx->dirty_sum_count = 0;

    /* 3. Flush SIT pages */
    for (i = 0; i < ctx->dirty_sit_count; i++) {
        if (ctx->dirty_sit_pages[i]) {
            struct page *page = ctx->dirty_sit_pages[i];

#if 0
            /* DEBUG: 打印每个 SIT page 状态 */
            pr_info("[snapfs batch] flush sit[%d]: page=%p, refcount=%d, mapcount=%d, dirty=%d, locked=%d\n",
                    i, page, page_ref_count(page),
                    page_mapcount(page), PageDirty(page), PageLocked(page));
#endif

            /* 确保 page 被锁定 */
            if (!PageLocked(page)) {
                lock_page(page);
#if 0
                pr_info("[snapfs batch] slot %u: sit page[%d] was unlocked, re-locked\n",
                        ctx->slot_id, i);
#endif
            }

            ret = snapfs_flush_locked_meta_page(sbi, page);
            if (ret) {
                pr_err("[snapfs batch] slot %u: flush sit page %u failed: %d\n",
                       ctx->slot_id, i, ret);
                /* 继续 flush 其他 pages */
            }
            f2fs_put_page(page, 0);
            ctx->dirty_sit_pages[i] = NULL;

            /* === 新增: 标记该 sit page 为脏（需要重新加载）=== */
            mark_sit_page_dirty(sbi, ctx->dirty_sit_blkaddr[i]);
        }
    }
    ctx->dirty_sit_count = 0;

#if 0
    pr_info("[snapfs batch] slot %u: all dirty pages flushed\n", ctx->slot_id);
#endif

    return 0;
}

static int snapfs_apply_mulref_op(struct f2fs_sb_info *sbi,
				 struct snap_redo_mulref_op *op)
{
	struct page *page;
	struct f2fs_mulref_block *blk;
	u16 idx = le16_to_cpu(op->idx);

	page = f2fs_get_meta_page(sbi, le32_to_cpu(op->mr_blkaddr));
	if (IS_ERR(page))
		return PTR_ERR(page);
	blk = (struct f2fs_mulref_block *)page_address(page);
	if (op->valid) {
		bool was_valid = f2fs_test_bit(idx, (char *)blk->multi_bitmap);
		if (!was_valid) {
			f2fs_set_bit(idx, (char *)blk->multi_bitmap);
			blk->v_mrentrys = cpu_to_le16(le16_to_cpu(blk->v_mrentrys) + 1);
		}
		blk->mrentries[idx] = op->entry;
	} else {
		mulref_mark_invalid(blk, idx);
		memset(&blk->mrentries[idx], 0, sizeof(struct f2fs_mulref_entry));
	}
	set_page_dirty(page);
	f2fs_put_page(page, 1);
	return 0;
}

static int snapfs_apply_summary_op(struct f2fs_sb_info *sbi,
				 struct snap_redo_summary_op *op)
{
	return f2fs_update_summary(sbi, le32_to_cpu(op->data_blkaddr),
			   &op->sum,
			   GET_SEGNO(sbi, le32_to_cpu(op->data_blkaddr)),
			   GET_BLKOFF_FROM_SEG0(sbi, le32_to_cpu(op->data_blkaddr)));
}

static int snapfs_apply_sit_op(struct f2fs_sb_info *sbi,
				 struct snap_redo_sit_op *op)
{
	snapfs_apply_sit_mulref_change(sbi, le32_to_cpu(op->data_blkaddr), op->set);
	return 0;
}

static int snapfs_redo_commit(struct snapfs_txn *txn)
{
	struct snap_redo_slot *slot;
	struct snap_redo_info *redo = txn->sbi->magic_info->redo_info;
	int ret;

	if (txn->bypass_redo)
		return 0;
	if (!txn->slot_valid)
		return -EINVAL;

	slot = kzalloc(sizeof(*slot), GFP_NOFS);
	if (!slot)
		return -ENOMEM;

	mutex_lock(&redo->alloc_lock);
	txn->slot_gen = redo->slot_gens[txn->slot_idx];
	txn->tx_seq = ++redo->slot_tx_seq[txn->slot_idx];
	mutex_unlock(&redo->alloc_lock);
	snapfs_redo_slot_init(slot, txn);
	if (txn->record_type == SNAPFS_REDO_REC_OVERWRITE)
		redo->overwrite_redo_commits++;
	else
		redo->cow_redo_commits++;
	ret = snapfs_redo_write_slot(txn->sbi, txn->slot_idx, slot);
	kfree(slot);
	return ret;
}

static int snapfs_redo_complete(struct snapfs_txn *txn)
{
	int ret;

	if (txn->bypass_redo)
		return 0;
	if (!txn->slot_valid)
		return -EINVAL;
	if (txn->record_type == SNAPFS_REDO_REC_OVERWRITE)
		ret = snapfs_redo_mark_overwrite_applied(txn->sbi, txn->slot_idx);
	else
		ret = snapfs_redo_clear_slot(txn->sbi, txn->slot_idx);
	if (!ret)
		snapfs_redo_free_slot(txn->sbi, txn->slot_idx);
	return ret;
}

static void snapfs_progress_reset(struct snapfs_cow_progress *progress)
{
	memset(progress, 0, sizeof(*progress));
}

static void snapfs_progress_init(struct snapfs_cow_progress *progress,
				       u32 src_ino, u32 snap_ino,
				       nid_t node_nid, u16 node_ofs,
				       u16 valid_bits)
{
	snapfs_progress_reset(progress);
	progress->src_ino = cpu_to_le32(src_ino);
	progress->snap_ino = cpu_to_le32(snap_ino);
	progress->node_nid = cpu_to_le32(node_nid);
	progress->node_ofs = cpu_to_le16(node_ofs);
	progress->valid_bits = cpu_to_le16(valid_bits);
	progress->slot_idx = 0;
	progress->slot_valid = false;
	progress->active = true;
}

static void snapfs_progress_mark_done(struct snapfs_cow_progress *progress, u16 bit)
{
	if (!progress->active)
		return;
	if (bit >= le16_to_cpu(progress->valid_bits))
		return;
	progress->bitmap[bit >> 3] |= (1U << (bit & 7));
}

static bool snapfs_progress_matches_group(struct snapfs_cow_progress *progress,
					  u32 src_ino, u32 snap_ino,
					  nid_t node_nid, u16 node_ofs,
					  u16 valid_bits)
{
	if (!progress || !progress->active)
		return false;
	return le32_to_cpu(progress->src_ino) == src_ino &&
		le32_to_cpu(progress->snap_ino) == snap_ino &&
		le32_to_cpu(progress->node_nid) == node_nid &&
		le16_to_cpu(progress->node_ofs) == node_ofs &&
		le16_to_cpu(progress->valid_bits) == valid_bits;
}

static bool snapfs_progress_bit_done(struct snapfs_cow_progress *progress,
				     u32 src_ino, u32 snap_ino,
				     nid_t node_nid, u16 node_ofs,
				     u16 valid_bits, u16 bit)
{
	if (!snapfs_progress_matches_group(progress, src_ino, snap_ino,
					  node_nid, node_ofs, valid_bits))
		return false;
	if (bit >= valid_bits)
		return false;
	return !!(progress->bitmap[bit >> 3] & (1U << (bit & 7)));
}

static void snapfs_txn_attach_progress(struct snapfs_txn *txn,
				      struct snapfs_cow_progress *progress)
{
	if (!progress || !progress->active)
		return;
	txn->state = cpu_to_le16(SNAPFS_PROGRESS_GROUP_IN_PROGRESS);
	txn->src_ino = progress->src_ino;
	txn->snap_ino = progress->snap_ino;
	txn->node_nid = progress->node_nid;
	txn->node_ofs = progress->node_ofs;
	txn->valid_bits = progress->valid_bits;
	txn->slot_idx = progress->slot_idx;
	txn->slot_valid = progress->slot_valid;
	txn->pending_valid = 0;
	txn->pending_bit = 0;
	memcpy(txn->bitmap, progress->bitmap, sizeof(txn->bitmap));
}

static void snapfs_txn_attach_pending_progress(struct snapfs_txn *txn,
				      struct snapfs_cow_progress *progress,
				      u16 bit)
{
	snapfs_txn_attach_progress(txn, progress);
	txn->state = cpu_to_le16(SNAPFS_PROGRESS_BLOCK_TXN_COMMITTED);
	txn->pending_valid = 1;
	txn->pending_bit = bit;
	if (bit < le16_to_cpu(txn->valid_bits))
		txn->bitmap[bit >> 3] &= ~(1U << (bit & 7));
}

static int snapfs_progress_write_group(struct f2fs_sb_info *sbi,
				      struct snapfs_cow_progress *progress)
{
	struct snapfs_txn txn;
	int ret;

	if (!progress || !progress->active)
		return 0;
	if (!progress->slot_valid) {
		ret = snapfs_redo_alloc_slot(sbi, le32_to_cpu(progress->snap_ino),
					    &progress->slot_idx);
		if (ret)
			return ret;
		progress->slot_valid = true;
	}
	ret = snapfs_redo_begin(sbi, &txn);
	if (ret)
		return ret;
	txn.bypass_redo = false;
	snapfs_txn_attach_progress(&txn, progress);
	ret = snapfs_redo_commit(&txn);
	snapfs_redo_end(&txn);
	return ret;
}

static int snapfs_progress_switch_group(struct f2fs_sb_info *sbi,
				       struct snapfs_cow_progress *progress,
				       u32 src_ino, u32 snap_ino,
				       nid_t node_nid, u16 node_ofs,
				       u16 valid_bits)
{
	u32 slot_idx = 0;
	bool slot_valid = false;
	int ret;

	if (progress->active &&
		le32_to_cpu(progress->src_ino) == src_ino &&
		le32_to_cpu(progress->snap_ino) == snap_ino &&
		le32_to_cpu(progress->node_nid) == node_nid &&
		le16_to_cpu(progress->node_ofs) == node_ofs &&
		le16_to_cpu(progress->valid_bits) == valid_bits)
		return 0;

	if (progress->slot_valid) {
		slot_idx = progress->slot_idx;
		slot_valid = true;
	} else {
		ret = snapfs_redo_alloc_slot(sbi, snap_ino, &slot_idx);
		if (ret)
			return ret;
		slot_valid = true;
	}

	snapfs_progress_init(progress, src_ino, snap_ino, node_nid, node_ofs,
			     valid_bits);
	progress->slot_idx = slot_idx;
	progress->slot_valid = slot_valid;
	return snapfs_progress_write_group(sbi, progress);
}

static int snapfs_progress_commit_after_block(struct snapfs_txn *txn,
				      struct snapfs_cow_progress *progress,
				      u16 bit)
{
	if (!progress || !progress->active)
		return snapfs_redo_complete(txn);

	snapfs_progress_mark_done(progress, bit);
	snapfs_redo_release_txn(txn);
	txn->pending_valid = 0;
	txn->pending_bit = 0;
	snapfs_txn_attach_progress(txn, progress);
	return snapfs_redo_commit(txn);
}

static int snapfs_progress_finish(struct f2fs_sb_info *sbi,
				 struct snapfs_cow_progress *progress)
{
	int ret;
	u32 slot_idx;
	bool slot_valid;

	if (!progress)
		return 0;
	slot_idx = progress->slot_idx;
	slot_valid = progress->slot_valid;
	snapfs_progress_reset(progress);
	if (!slot_valid)
		return 0;
	ret = snapfs_redo_clear_slot(sbi, slot_idx);
	if (!ret)
		snapfs_redo_free_slot(sbi, slot_idx);
	return ret;
}

static void snapfs_progress_from_slot(struct snapfs_cow_progress *progress,
				      struct snap_redo_slot *slot,
				      u32 slot_idx)
{
	snapfs_progress_reset(progress);
	progress->src_ino = slot->src_ino;
	progress->snap_ino = slot->snap_ino;
	progress->node_nid = slot->node_nid;
	progress->node_ofs = slot->node_ofs;
	progress->valid_bits = slot->valid_bits;
	progress->slot_idx = slot_idx;
	progress->slot_valid = true;
	memcpy(progress->bitmap, slot->bitmap, sizeof(progress->bitmap));
	if (slot->pending_valid && le16_to_cpu(slot->pending_bit) < le16_to_cpu(slot->valid_bits))
		progress->bitmap[le16_to_cpu(slot->pending_bit) >> 3] &= ~(1U << (le16_to_cpu(slot->pending_bit) & 7));
	progress->active = true;
}

static int snapfs_progress_group_start_lblk(struct inode *inode,
					struct snapfs_cow_progress *progress,
					pgoff_t *start_lblk)
{
	const long direct_index = ADDRS_PER_INODE(inode);
	const long direct_blks = ADDRS_PER_BLOCK(inode);
	u16 node_ofs;

	if (!progress || !progress->active)
		return -EINVAL;

	node_ofs = le16_to_cpu(progress->node_ofs);

	if (node_ofs == 0) {
		*start_lblk = 0;
		return 0;
	}
	if (node_ofs == 1) {
		*start_lblk = direct_index;
		return 0;
	}
	if (node_ofs == 2) {
		*start_lblk = direct_index + direct_blks;
		return 0;
	}
	if (node_ofs >= 3 && node_ofs < 3 + direct_blks) {
		*start_lblk = direct_index + 2 * direct_blks +
			(node_ofs - 3) * direct_blks;
		return 0;
	}
	if (node_ofs >= 1022 && node_ofs < 1022 + direct_blks) {
		*start_lblk = direct_index + 2 * direct_blks +
			direct_blks * direct_blks +
			(node_ofs - 1022) * direct_blks;
		return 0;
	}
	if (node_ofs >= 2041) {
		u32 rel = node_ofs - 2041;
		u32 outer = rel / direct_blks;
		u32 inner = rel % direct_blks;

		*start_lblk = direct_index + 2 * direct_blks +
			2 * direct_blks * direct_blks +
			((pgoff_t)outer * direct_blks + inner) * direct_blks;
		return 0;
	}

	return -EINVAL;
}

static int snapfs_flush_replayed_homes(struct f2fs_sb_info *sbi,
				       struct snap_redo_slot *slot)
{
	block_t flushed[SNAP_REDO_MAX_MULREF_OPS];
	unsigned int flushed_nr = 0;
	unsigned int i;
	int ret;

	for (i = 0; i < slot->nr_mulref_ops; i++) {
		block_t blkaddr = le32_to_cpu(slot->mulref_ops[i].mr_blkaddr);
		unsigned int j;
		bool seen = false;

		for (j = 0; j < flushed_nr; j++) {
			if (flushed[j] == blkaddr) {
				seen = true;
				break;
			}
		}
		if (seen)
			continue;
		ret = snapfs_flush_meta_blocks(sbi, blkaddr, 1, FS_META_IO);
		if (ret)
			return ret;
		if (flushed_nr < ARRAY_SIZE(flushed))
			flushed[flushed_nr++] = blkaddr;
	}

	if (slot->flags & SNAP_REDO_F_HAS_SUMMARY) {
		block_t data_blkaddr = le32_to_cpu(slot->summary_op.data_blkaddr);

		ret = snapfs_flush_meta_blocks(sbi,
				GET_SUM_BLOCK(sbi, GET_SEGNO(sbi, data_blkaddr)),
				1, FS_META_IO);
		if (ret)
			return ret;
	}

	if (slot->flags & SNAP_REDO_F_HAS_SIT) {
		block_t data_blkaddr = le32_to_cpu(slot->sit_op.data_blkaddr);
		block_t sit_blkaddr = SIT_MR_I(sbi)->base_addr +
			(GET_SEGNO(sbi, data_blkaddr) / SIT_MR_I(sbi)->sments_per_block);

		ret = snapfs_flush_meta_blocks(sbi, sit_blkaddr, 1, FS_META_IO);
		if (ret)
			return ret;
	}

	return 0;
}

static int snapfs_write_group_progress_slot(struct f2fs_sb_info *sbi,
					    u32 slot_idx,
					    struct snap_redo_slot *slot,
					    struct snapfs_cow_progress *progress)
{
	struct snapfs_txn txn;

	memset(&txn, 0, sizeof(txn));
	txn.sbi = sbi;
	txn.state = cpu_to_le16(SNAPFS_PROGRESS_GROUP_IN_PROGRESS);
	txn.record_type = SNAPFS_REDO_REC_COW;
	txn.txid = le64_to_cpu(slot->txid);
	txn.slot_gen = le32_to_cpu(slot->slot_gen);
	txn.tx_seq = le32_to_cpu(slot->tx_seq);
	txn.src_ino = progress->src_ino;
	txn.snap_ino = progress->snap_ino;
	txn.node_nid = progress->node_nid;
	txn.node_ofs = progress->node_ofs;
	txn.valid_bits = progress->valid_bits;
	txn.slot_idx = slot_idx;
	txn.slot_valid = true;
	txn.pending_valid = 0;
	txn.pending_bit = 0;
	txn.record_type = SNAPFS_REDO_REC_COW;
	memcpy(txn.bitmap, progress->bitmap, sizeof(txn.bitmap));
	snapfs_redo_slot_init(slot, &txn);
	return snapfs_redo_write_slot(sbi, slot_idx, slot);
}

static int snapfs_replay_slot(struct f2fs_sb_info *sbi,
			      u32 slot_idx,
			      struct snap_redo_slot *slot,
			      bool keep_progress)
{
	struct snapfs_cow_progress progress;
	struct snap_redo_info *redo = sbi->magic_info->redo_info;
	u64 max_txid = 0;
	int ret = 0;
	int pending_bit = -ENOENT;
	unsigned int i, nr_ops;

	if (!snapfs_redo_slot_valid(slot))
		return -ENOENT;
	if (slot->record_type == SNAPFS_REDO_REC_OVERWRITE)
		return -ENOENT;
	if (slot->record_type != 0 && slot->record_type != SNAPFS_REDO_REC_COW)
		return -EINVAL;
	if (le16_to_cpu(slot->state) != SNAP_REDO_COMMITTED &&
	    le16_to_cpu(slot->state) != SNAPFS_PROGRESS_GROUP_IN_PROGRESS &&
	    le16_to_cpu(slot->state) != SNAPFS_PROGRESS_BLOCK_TXN_COMMITTED)
		return -ENOENT;

	nr_ops = slot->nr_mulref_ops;
	if (nr_ops > SNAP_REDO_MAX_MULREF_OPS)
		return -EINVAL;

	if (le32_to_cpu(slot->slot_id) != slot_idx)
		return -EINVAL;
	if (le32_to_cpu(slot->slot_gen) != redo->slot_gens[slot_idx])
		redo->slot_gens[slot_idx] = le32_to_cpu(slot->slot_gen);
	if (le32_to_cpu(slot->tx_seq) > redo->slot_tx_seq[slot_idx])
		redo->slot_tx_seq[slot_idx] = le32_to_cpu(slot->tx_seq);

	max_txid = le64_to_cpu(slot->txid);
	if (max_txid >= redo->next_txid)
		redo->next_txid = max_txid + 1;

	if (le16_to_cpu(slot->state) == SNAPFS_PROGRESS_GROUP_IN_PROGRESS)
		return 0;

	if (keep_progress && le16_to_cpu(slot->state) == SNAPFS_PROGRESS_BLOCK_TXN_COMMITTED) {
		if (!slot->pending_valid || le16_to_cpu(slot->pending_bit) >= le16_to_cpu(slot->valid_bits))
			return -EINVAL;
		snapfs_progress_from_slot(&progress, slot, slot_idx);
		pending_bit = le16_to_cpu(slot->pending_bit);
	}

	for (i = 0; i < nr_ops; i++) {
		ret = snapfs_apply_mulref_op(sbi, &slot->mulref_ops[i]);
		if (ret)
			return ret;
	}
	if (slot->flags & SNAP_REDO_F_HAS_SUMMARY) {
		ret = snapfs_apply_summary_op(sbi, &slot->summary_op);
		if (ret)
			return ret;
	}
	if (slot->flags & SNAP_REDO_F_HAS_SIT) {
		ret = snapfs_apply_sit_op(sbi, &slot->sit_op);
		if (ret)
			return ret;
	}
	ret = snapfs_flush_replayed_homes(sbi, slot);
	if (ret)
		return ret;

	if (keep_progress && le16_to_cpu(slot->state) == SNAPFS_PROGRESS_BLOCK_TXN_COMMITTED) {
		if (pending_bit >= 0)
			snapfs_progress_mark_done(&progress, pending_bit);
		redo->cow_redo_replays++;
		return snapfs_write_group_progress_slot(sbi, slot_idx, slot, &progress);
	}

	ret = snapfs_redo_clear_slot(sbi, slot_idx);
	if (!ret)
		snapfs_redo_free_slot(sbi, slot_idx);
	return ret;
}

static int snapfs_replay_overwrite_slot(struct f2fs_sb_info *sbi,
				      u32 slot_idx,
				      struct snap_redo_slot *slot)
{
	struct f2fs_summary cur_sum;
	struct f2fs_summary old_sum;
	int ret;
	unsigned int i;
	u16 state;

	if (!snapfs_redo_slot_valid(slot))
		return -ENOENT;
	if (slot->record_type != SNAPFS_REDO_REC_OVERWRITE)
		return -ENOENT;
	if (le32_to_cpu(slot->slot_id) != slot_idx)
		return -EINVAL;
	if (le32_to_cpu(slot->slot_gen) != sbi->magic_info->redo_info->slot_gens[slot_idx])
		sbi->magic_info->redo_info->slot_gens[slot_idx] = le32_to_cpu(slot->slot_gen);
	if (le32_to_cpu(slot->tx_seq) > sbi->magic_info->redo_info->slot_tx_seq[slot_idx])
		sbi->magic_info->redo_info->slot_tx_seq[slot_idx] = le32_to_cpu(slot->tx_seq);

	state = le16_to_cpu(slot->state);
	/* 已应用完成，无需 replay */
	if (state == SNAPFS_OVERWRITE_EMPTY || state == SNAPFS_OVERWRITE_APPLIED)
		return 0;
	if (state != SNAPFS_OVERWRITE_TXN_COMMITTED)
		return -ENOENT;

	ret = f2fs_get_summary_by_addr(sbi, le32_to_cpu(slot->data_blkaddr), &cur_sum);
	if (ret)
		return ret;

	old_sum.nid = slot->old_sum_nid;
	old_sum.ofs_in_node = slot->old_sum_ofs;
	old_sum.version = slot->old_sum_ver;

	if (snapfs_summary_equal(&cur_sum, &old_sum)) {
		f2fs_info(sbi, "overwrite redo replay from old baseline blk=%u", le32_to_cpu(slot->data_blkaddr));
	} else if ((slot->flags & SNAP_REDO_F_HAS_SUMMARY) &&
		   snapfs_summary_equal(&cur_sum, &slot->summary_op.sum)) {
		f2fs_info(sbi, "overwrite redo already at target blk=%u", le32_to_cpu(slot->data_blkaddr));
	} else {
		sbi->magic_info->redo_info->overwrite_redo_conflicts++;
		f2fs_err(sbi, "overwrite redo conflict blk=%u", le32_to_cpu(slot->data_blkaddr));
		return -EUCLEAN;
	}

	for (i = 0; i < slot->nr_mulref_ops; i++) {
		ret = snapfs_apply_mulref_op(sbi, &slot->mulref_ops[i]);
		if (ret)
			return ret;
	}
	if (slot->flags & SNAP_REDO_F_HAS_SUMMARY) {
		ret = snapfs_apply_summary_op(sbi, &slot->summary_op);
		if (ret)
			return ret;
	}
	if (slot->flags & SNAP_REDO_F_HAS_SIT) {
		ret = snapfs_apply_sit_op(sbi, &slot->sit_op);
		if (ret)
			return ret;
	}
	ret = snapfs_flush_replayed_homes(sbi, slot);
	if (ret)
		return ret;

	/* 恢复时标记为 APPLIED 并唤醒等待者 */
	ret = snapfs_redo_mark_overwrite_applied(sbi, slot_idx);
	if (!ret) {
		sbi->magic_info->redo_info->overwrite_redo_replays++;
		snapfs_redo_free_slot(sbi, slot_idx);
	}
	return ret;
}

int snapfs_recover_journal(struct f2fs_sb_info *sbi)
{
	struct snap_redo_info *redo;
	struct snap_redo_slot *slot;
	struct page *page;
	u64 max_txid = 0;
	int ret = 0;
	u32 i;

	if (!sbi->magic_info || !sbi->magic_info->redo_info)
		return 0;
	redo = sbi->magic_info->redo_info;

	/* === Batch Redo Recovery === */
	if (redo->batch_mode) {
		pr_info("[snapfs batch] starting batch redo recovery\n");

		/* 初始化 batch slot 位图 */
		bitmap_zero(redo->batch_slot_inuse_bitmap, redo->batch_nr_slots);

		/* 扫描所有 batch 文件槽并恢复 */
		for (i = 0; i < redo->batch_nr_slots; i++) {
			ret = snapfs_batch_recover_slot(sbi, i);
			if (ret > 0) {
				/* 有未完成的 batch，需要继续 apply */
				pr_info("[snapfs batch] slot %u: %d bits remaining\n", i, ret);
				__set_bit(i, redo->batch_slot_inuse_bitmap);
			} else if (ret < 0) {
				pr_err("[snapfs batch] slot %u: recovery error %d\n", i, ret);
				return ret;
			}
		}

		pr_info("[snapfs batch] batch redo recovery completed\n");
		/* 仍然处理 overwrite slot */
		goto recover_overwrite;
	}

	/* === Legacy Slot-based Recovery === */
	bitmap_zero(redo->slot_inuse_bitmap, redo->nr_slots);
	memset(redo->slot_tx_seq, 0, sizeof(*redo->slot_tx_seq) * redo->nr_slots);
	for (i = 0; i < redo->cow_nr_slots; i++) {
		page = f2fs_get_meta_page(sbi, snapfs_redo_slot_blkaddr(sbi, i));
		if (IS_ERR(page))
			return PTR_ERR(page);
		slot = (struct snap_redo_slot *)page_address(page);
		if (!snapfs_redo_slot_valid(slot)) {
			f2fs_put_page(page, 1);
			continue;
		}
		if (le16_to_cpu(slot->state) == SNAPFS_PROGRESS_EMPTY) {
			f2fs_put_page(page, 1);
			continue;
		}
		if (slot->record_type != 0 && slot->record_type != SNAPFS_REDO_REC_COW) {
			f2fs_put_page(page, 1);
			continue;
		}
		__set_bit(i, redo->slot_inuse_bitmap);
		if (le64_to_cpu(slot->txid) > max_txid)
			max_txid = le64_to_cpu(slot->txid);
		ret = snapfs_replay_slot(sbi, i, slot, true);
		f2fs_put_page(page, 1);
		if (ret && ret != -ENOENT)
			return ret;
	}

recover_overwrite:
	/* 处理 overwrite slot（batch 和 legacy 模式都使用） */
	page = f2fs_get_meta_page(sbi, snapfs_redo_slot_blkaddr(sbi, redo->overwrite_slot));
	if (IS_ERR(page))
		return PTR_ERR(page);
	slot = (struct snap_redo_slot *)page_address(page);
	if (snapfs_redo_slot_valid(slot) &&
	    slot->record_type == SNAPFS_REDO_REC_OVERWRITE &&
	    le16_to_cpu(slot->state) != SNAPFS_OVERWRITE_EMPTY) {
		__set_bit(redo->overwrite_slot, redo->slot_inuse_bitmap);
		if (le64_to_cpu(slot->txid) > max_txid)
			max_txid = le64_to_cpu(slot->txid);
		ret = snapfs_replay_overwrite_slot(sbi, redo->overwrite_slot, slot);
		f2fs_put_page(page, 1);
		if (ret && ret != -ENOENT)
			return ret;
	} else {
		f2fs_put_page(page, 1);
	}
	if (max_txid >= redo->next_txid)
		redo->next_txid = max_txid + 1;
	return 0;
}


void update_f2fs_inode(struct f2fs_inode *src_fi,struct f2fs_inode *new_fi){
	new_fi->i_mode = src_fi->i_mode;
	new_fi->i_advise = src_fi->i_advise;
	new_fi->i_inline = src_fi->i_inline;
	new_fi->i_uid = src_fi->i_uid;
	new_fi->i_gid = src_fi->i_gid;
	new_fi->i_size = src_fi->i_size;
	new_fi->i_blocks = src_fi->i_blocks;  // 这个很重要！
	new_fi->i_atime = src_fi->i_atime;
	new_fi->i_ctime = src_fi->i_ctime;
	new_fi->i_mtime = src_fi->i_mtime;
	new_fi->i_atime_nsec = src_fi->i_atime_nsec;
	new_fi->i_ctime_nsec = src_fi->i_ctime_nsec;
	new_fi->i_mtime_nsec = src_fi->i_mtime_nsec;
	new_fi->i_generation = src_fi->i_generation;
	new_fi->i_current_depth = src_fi->i_current_depth;
	new_fi->i_flags = src_fi->i_flags;
	new_fi->i_namelen = src_fi->i_namelen;
	// 复制文件名（如果存在）
	if (src_fi->i_namelen > 0 && src_fi->i_namelen <= F2FS_NAME_LEN) {
		memcpy(new_fi->i_name, src_fi->i_name, src_fi->i_namelen);
		new_fi->i_namelen = src_fi->i_namelen;
	}
	new_fi->i_dir_level = src_fi->i_dir_level;
	// 复制extent信息
	memcpy(&new_fi->i_ext, &src_fi->i_ext, sizeof(struct f2fs_extent));

	// 不再复制 i_nid[0-4]，由 f2fs cow copy_all_nodes() 单独处理
	// 只复制直接数据块地址
	memcpy(new_fi->i_addr, src_fi->i_addr, sizeof(src_fi->i_addr));
}
void update_f2fs_inode_inline(struct f2fs_inode *src_fi,struct f2fs_inode *new_fi){
	new_fi->i_mode = src_fi->i_mode;
	new_fi->i_advise = src_fi->i_advise;
	new_fi->i_inline = src_fi->i_inline;
	new_fi->i_uid = src_fi->i_uid;
	new_fi->i_gid = src_fi->i_gid;
	new_fi->i_size = src_fi->i_size;
	// new_fi->i_blocks = src_fi->i_blocks;  // 这个很重要！
	new_fi->i_atime = src_fi->i_atime;
	new_fi->i_ctime = src_fi->i_ctime;
	new_fi->i_mtime = src_fi->i_mtime;
	new_fi->i_atime_nsec = src_fi->i_atime_nsec;
	new_fi->i_ctime_nsec = src_fi->i_ctime_nsec;
	new_fi->i_mtime_nsec = src_fi->i_mtime_nsec;
	new_fi->i_generation = src_fi->i_generation;
	new_fi->i_current_depth = src_fi->i_current_depth;
	new_fi->i_flags = src_fi->i_flags;
	new_fi->i_namelen = src_fi->i_namelen;
	// 复制文件名（如果存在）
	if (src_fi->i_namelen > 0 && src_fi->i_namelen <= F2FS_NAME_LEN) {
		memcpy(new_fi->i_name, src_fi->i_name, src_fi->i_namelen);
		new_fi->i_namelen = src_fi->i_namelen;
	}
	new_fi->i_dir_level = src_fi->i_dir_level;
	// 复制extent信息
	memcpy(&new_fi->i_ext, &src_fi->i_ext, sizeof(struct f2fs_extent));
}

/*
 * Node offset 定义 (参考 node.h 注释):
 *   Inode block (0)
 *     |- direct node (1)           <- i_nid[0]
 *     |- direct node (2)           <- i_nid[1]
 *     |- indirect node (3)         <- i_nid[2]
 *     |            `- direct node (4 => 4 + N - 1)
 *     |- indirect node (4 + N)     <- i_nid[3]
 *     |            `- direct node (5 + N => 5 + 2N - 1)
 *     `- double indirect node (5 + 2N)  <- i_nid[4]
 *                  `- indirect node (6 + 2N)
 *                        `- direct node
 *   其中 N = NIDS_PER_BLOCK = 1018
 */
#define NODE_OFS_DIRECT_0       1
#define NODE_OFS_DIRECT_1       2
#define NODE_OFS_INDIRECT_0     3
#define NODE_OFS_INDIRECT_1     (4 + NIDS_PER_BLOCK)
#define NODE_OFS_DINDIRECT      (5 + 2 * NIDS_PER_BLOCK)

/**
 * f2fs_cow_copy_direct_node - 复制一个 direct_node
 * @sbi: 超级块信息
 * @src_nid: 源 node 的 nid
 * @snap_inode: 快照 inode
 * @ofs: node offset
 *
 * 为快照创建一个新的 direct_node，复制源 node 的 addr[] 数组。
 * 数据块地址保持不变（通过 mulref 机制共享）。
 *
 * 返回: 新分配的 nid，失败返回 0
 */
static nid_t f2fs_cow_copy_direct_node(struct f2fs_sb_info *sbi,
                                        nid_t src_nid,
                                        struct inode *snap_inode,
                                        unsigned int ofs)
{
	struct page *src_page = NULL;
	struct page *new_page = NULL;
	struct f2fs_node *src_rn, *new_rn;
	struct direct_node dn_copy;
	struct node_info new_ni;
	nid_t new_nid = 0;
	int err;

	if (src_nid == 0)
		return 0;

	/* 1. 分配新的 nid */
	if (!f2fs_alloc_nid(sbi, &new_nid)) {
		pr_err("[snapfs cow_node]: failed to alloc nid for direct_node\n");
		return 0;
	}

	/* 2. 读取源 node page，复制内容后立即释放 */
	src_page = f2fs_get_node_page(sbi, src_nid);
	if (IS_ERR(src_page)) {
		pr_err("[snapfs cow_node]: failed to get src direct_node page, nid=%u\n", src_nid);
		f2fs_alloc_nid_failed(sbi, new_nid);
		return 0;
	}
	src_rn = F2FS_NODE(src_page);
	/* 复制到栈上，然后立即释放源页面锁 */
	memcpy(&dn_copy, &src_rn->dn, sizeof(struct direct_node));
	f2fs_put_page(src_page, 1);
	src_page = NULL;

	/* 3. 创建新的 node page */
	new_page = f2fs_grab_cache_page(NODE_MAPPING(sbi), new_nid, false);
	if (!new_page) {
		pr_err("[snapfs cow_node]: failed to grab cache page for new direct_node\n");
		f2fs_alloc_nid_failed(sbi, new_nid);
		return 0;
	}

	/* 4. 增加有效 node 计数 */
	err = inc_valid_node_count(sbi, snap_inode, false);
	if (err) {
		pr_err("[snapfs cow_node]: failed to inc_valid_node_count\n");
		f2fs_put_page(new_page, 1);
		f2fs_alloc_nid_failed(sbi, new_nid);
		return 0;
	}

	/* 5. 复制 direct_node 内容（从栈上的副本） */
	new_rn = F2FS_NODE(new_page);
	memcpy(&new_rn->dn, &dn_copy, sizeof(struct direct_node));

	/* 6. 设置新的 node footer */
	fill_node_footer(new_page, new_nid, snap_inode->i_ino, ofs, false);
	set_cold_node(new_page, S_ISDIR(snap_inode->i_mode));

	/* 7. 设置 NAT 映射 */
	new_ni.nid = new_nid;
	new_ni.ino = snap_inode->i_ino;
	new_ni.blk_addr = NULL_ADDR;
	new_ni.flag = 0;
	new_ni.version = 0;
	set_node_addr(sbi, &new_ni, NEW_ADDR, false);

	/* 8. 标记页面为最新并设置脏 */
	if (!PageUptodate(new_page))
		SetPageUptodate(new_page);
	set_page_dirty(new_page);

	/* 9. 完成 nid 分配 */
	f2fs_alloc_nid_done(sbi, new_nid);

	/* 10. 释放页面 */
	f2fs_put_page(new_page, 1);

	if (SNAPFS_DEBUG)
		pr_info("[snapfs cow_node]: copied direct_node src_nid=%u -> new_nid=%u, ofs=%u\n",
			src_nid, new_nid, ofs);

	return new_nid;
}

/**
 * f2fs_cow_copy_indirect_node - 复制一个 indirect_node 及其所有子 direct_node
 * @sbi: 超级块信息
 * @src_nid: 源 indirect_node 的 nid
 * @snap_inode: 快照 inode
 * @ofs: indirect_node 的 offset
 * @base_child_ofs: 子 direct_node 的起始 offset
 *
 * 递归复制 indirect_node 及其下属的所有 direct_node。
 * 注意：为避免死锁，先收集所有子 nid，释放锁后再递归处理。
 *
 * 返回: 新分配的 nid，失败返回 0
 */
static nid_t f2fs_cow_copy_indirect_node(struct f2fs_sb_info *sbi,
                                          nid_t src_nid,
                                          struct inode *snap_inode,
                                          unsigned int ofs,
                                          unsigned int base_child_ofs)
{
	struct page *src_page = NULL;
	struct page *new_page = NULL;
	struct f2fs_node *src_rn, *new_rn;
	struct node_info new_ni;
	nid_t new_nid = 0;
	nid_t child_nid, new_child_nid;
	nid_t *child_nids = NULL;  /* 临时数组存储子 nid */
	nid_t *new_child_nids = NULL;  /* 临时数组存储新子 nid */
	int i, err;

	if (src_nid == 0)
		return 0;

	/* 分配临时数组 */
	child_nids = kvmalloc(NIDS_PER_BLOCK * sizeof(nid_t), GFP_KERNEL);
	if (!child_nids) {
		pr_err("[snapfs cow_node]: failed to alloc child_nids array\n");
		return 0;
	}
	new_child_nids = kvmalloc(NIDS_PER_BLOCK * sizeof(nid_t), GFP_KERNEL);
	if (!new_child_nids) {
		pr_err("[snapfs cow_node]: failed to alloc new_child_nids array\n");
		kvfree(child_nids);
		return 0;
	}
	memset(new_child_nids, 0, NIDS_PER_BLOCK * sizeof(nid_t));

	/* 1. 分配新的 nid */
	if (!f2fs_alloc_nid(sbi, &new_nid)) {
		pr_err("[snapfs cow_node]: failed to alloc nid for indirect_node\n");
		kvfree(child_nids);
		kvfree(new_child_nids);
		return 0;
	}

	/* 2. 读取源 indirect_node page，复制子 nid 数组后立即释放 */
	src_page = f2fs_get_node_page(sbi, src_nid);
	if (IS_ERR(src_page)) {
		pr_err("[snapfs cow_node]: failed to get src indirect_node page, nid=%u\n", src_nid);
		f2fs_alloc_nid_failed(sbi, new_nid);
		kvfree(child_nids);
		kvfree(new_child_nids);
		return 0;
	}
	src_rn = F2FS_NODE(src_page);
	/* 复制所有子 nid 到临时数组，同时检查有效性 */
	for (i = 0; i < NIDS_PER_BLOCK; i++) {
		nid_t nid_to_check = le32_to_cpu(src_rn->in.nid[i]);
		/* 检查 nid 是否在有效范围内（防止损坏的源数据） */
		if (nid_to_check != 0 && nid_to_check >= NM_I(sbi)->max_nid) {
			pr_err("[snapfs cow_node] COPY WARNING: indirect_node %u, invalid child nid %u at index %d (max_nid=%u), skipping\n",
			       src_nid, nid_to_check, i, NM_I(sbi)->max_nid);
			child_nids[i] = 0;  /* 将无效 nid 视为 0（空节点） */
		} else {
			child_nids[i] = nid_to_check;
		}
	}
	/* 调试日志：打印所有复制的 child nids（前几个和后几个） */
#if 0
	if (SNAPFS_DEBUG || child_nids[0] != 0) {
		pr_info("[snapfs cow_node] COPY: indirect_node src_nid=%u, new_nid=%u, copying %d child nids:\n",
			src_nid, new_nid, NIDS_PER_BLOCK);
		for (i = 0; i < 5 && i < NIDS_PER_BLOCK; i++) {
			pr_info("  [%d] = %u\n", i, child_nids[i]);
		}
		if (NIDS_PER_BLOCK > 10) {
			pr_info("  ... (%d total, last 5):\n", NIDS_PER_BLOCK);
			for (i = NIDS_PER_BLOCK - 5; i < NIDS_PER_BLOCK; i++) {
				pr_info("  [%d] = %u\n", i, child_nids[i]);
			}
		}
	}
#endif
	f2fs_put_page(src_page, 1);
	src_page = NULL;

	/* 3. 递归复制所有子 direct_node（此时不持有任何 page 锁） */
	for (i = 0; i < NIDS_PER_BLOCK; i++) {
		child_nid = child_nids[i];
		if (child_nid == 0) {
			new_child_nids[i] = 0;
			continue;
		}

		new_child_nid = f2fs_cow_copy_direct_node(sbi, child_nid, snap_inode,
		                                           base_child_ofs + i);
		if (new_child_nid == 0) {
			pr_err("[snapfs cow_node]: failed to copy child direct_node[%d]\n", i);
			/* 继续处理其他节点，不中断 */
		}
		new_child_nids[i] = new_child_nid;
	}

	/* 4. 创建新的 indirect node page */
	new_page = f2fs_grab_cache_page(NODE_MAPPING(sbi), new_nid, false);
	if (!new_page) {
		pr_err("[snapfs cow_node]: failed to grab cache page for new indirect_node\n");
		f2fs_alloc_nid_failed(sbi, new_nid);
		kvfree(child_nids);
		kvfree(new_child_nids);
		return 0;
	}

	/* 5. 增加有效 node 计数 */
	err = inc_valid_node_count(sbi, snap_inode, false);
	if (err) {
		pr_err("[snapfs cow_node]: failed to inc_valid_node_count for indirect\n");
		f2fs_put_page(new_page, 1);
		f2fs_alloc_nid_failed(sbi, new_nid);
		kvfree(child_nids);
		kvfree(new_child_nids);
		return 0;
	}

	new_rn = F2FS_NODE(new_page);

	/* 6. 填充新 indirect_node 的子 nid 数组 */
	for (i = 0; i < NIDS_PER_BLOCK; i++) {
		new_rn->in.nid[i] = cpu_to_le32(new_child_nids[i]);
	}

	/* 7. 设置新的 node footer */
	fill_node_footer(new_page, new_nid, snap_inode->i_ino, ofs, false);
	set_cold_node(new_page, S_ISDIR(snap_inode->i_mode));

	/* 8. 设置 NAT 映射 */
	new_ni.nid = new_nid;
	new_ni.ino = snap_inode->i_ino;
	new_ni.blk_addr = NULL_ADDR;
	new_ni.flag = 0;
	new_ni.version = 0;
	set_node_addr(sbi, &new_ni, NEW_ADDR, false);

	/* 9. 标记页面为最新并设置脏 */
	if (!PageUptodate(new_page))
		SetPageUptodate(new_page);
	set_page_dirty(new_page);

	/* 10. 完成 nid 分配 */
	f2fs_alloc_nid_done(sbi, new_nid);

	/* 11. 释放新页面 */
	f2fs_put_page(new_page, 1);

	/* 释放临时数组 */
	kvfree(child_nids);
	kvfree(new_child_nids);

	if (SNAPFS_DEBUG)
		pr_info("[snapfs cow_node]: copied indirect_node src_nid=%u -> new_nid=%u, ofs=%u\n",
			src_nid, new_nid, ofs);

	return new_nid;
}

/**
 * f2fs_cow_copy_double_indirect_node - 复制 double_indirect_node 及其所有子节点
 * @sbi: 超级块信息
 * @src_nid: 源 double_indirect_node 的 nid
 * @snap_inode: 快照 inode
 *
 * 递归复制 double_indirect_node -> indirect_node -> direct_node 整棵树。
 * 注意：为避免死锁，先收集所有子 nid，释放锁后再递归处理。
 *
 * 返回: 新分配的 nid，失败返回 0
 */
static nid_t f2fs_cow_copy_double_indirect_node(struct f2fs_sb_info *sbi,
                                                 nid_t src_nid,
                                                 struct inode *snap_inode)
{
	struct page *src_page = NULL;
	struct page *new_page = NULL;
	struct f2fs_node *src_rn, *new_rn;
	struct node_info new_ni;
	nid_t new_nid = 0;
	nid_t child_nid, new_child_nid;
	nid_t *child_nids = NULL;  /* 临时数组存储子 nid */
	nid_t *new_child_nids = NULL;  /* 临时数组存储新子 nid */
	unsigned int dindirect_ofs = NODE_OFS_DINDIRECT;
	unsigned int child_indirect_ofs;
	unsigned int child_direct_base_ofs;
	int i, err;

	if (src_nid == 0)
		return 0;

	/* 分配临时数组 */
	child_nids = kvmalloc(NIDS_PER_BLOCK * sizeof(nid_t), GFP_KERNEL);
	if (!child_nids) {
		pr_err("[snapfs cow_node]: failed to alloc child_nids array for dindirect\n");
		return 0;
	}
	new_child_nids = kvmalloc(NIDS_PER_BLOCK * sizeof(nid_t), GFP_KERNEL);
	if (!new_child_nids) {
		pr_err("[snapfs cow_node]: failed to alloc new_child_nids array for dindirect\n");
		kvfree(child_nids);
		return 0;
	}
	memset(new_child_nids, 0, NIDS_PER_BLOCK * sizeof(nid_t));

	/* 1. 分配新的 nid */
	if (!f2fs_alloc_nid(sbi, &new_nid)) {
		pr_err("[snapfs cow_node]: failed to alloc nid for double_indirect_node\n");
		kvfree(child_nids);
		kvfree(new_child_nids);
		return 0;
	}

	/* 2. 读取源 double_indirect_node page，复制子 nid 数组后立即释放 */
	src_page = f2fs_get_node_page(sbi, src_nid);
	if (IS_ERR(src_page)) {
		pr_err("[snapfs cow_node]: failed to get src double_indirect_node page, nid=%u\n", src_nid);
		f2fs_alloc_nid_failed(sbi, new_nid);
		kvfree(child_nids);
		kvfree(new_child_nids);
		return 0;
	}
	src_rn = F2FS_NODE(src_page);
	/* 复制所有子 nid 到临时数组，同时检查有效性 */
	for (i = 0; i < NIDS_PER_BLOCK; i++) {
		nid_t nid_to_check = le32_to_cpu(src_rn->in.nid[i]);
		/* 检查 nid 是否在有效范围内（防止损坏的源数据） */
		if (nid_to_check != 0 && nid_to_check >= NM_I(sbi)->max_nid) {
			pr_err("[snapfs cow_node]: WARNING: invalid child nid %u at index %d (max_nid=%u), skipping\n",
			       nid_to_check, i, NM_I(sbi)->max_nid);
			child_nids[i] = 0;  /* 将无效 nid 视为 0（空节点） */
		} else {
			child_nids[i] = nid_to_check;
		}
	}
	f2fs_put_page(src_page, 1);
	src_page = NULL;

	/* 3. 递归复制所有子 indirect_node（此时不持有任何 page 锁） */
	for (i = 0; i < NIDS_PER_BLOCK; i++) {
		child_nid = child_nids[i];
		if (child_nid == 0) {
			new_child_nids[i] = 0;
			continue;
		}

		/*
		 * 计算子 indirect_node 的 offset:
		 * double_indirect 的 offset = 5 + 2N
		 * 第 i 个子 indirect_node 的 offset = (6 + 2N) + i * (N + 1)
		 * 其下 direct_node 的起始 offset = (6 + 2N) + i * (N + 1) + 1
		 */
		child_indirect_ofs = (dindirect_ofs + 1) + i * (NIDS_PER_BLOCK + 1);
		child_direct_base_ofs = child_indirect_ofs + 1;

		/* 递归复制子 indirect_node */
		new_child_nid = f2fs_cow_copy_indirect_node(sbi, child_nid, snap_inode,
		                                             child_indirect_ofs,
		                                             child_direct_base_ofs);
		if (new_child_nid == 0) {
			pr_err("[snapfs cow_node]: failed to copy child indirect_node[%d]\n", i);
			/* 继续处理其他节点 */
		}
		new_child_nids[i] = new_child_nid;
	}

	/* 4. 创建新的 double_indirect node page */
	new_page = f2fs_grab_cache_page(NODE_MAPPING(sbi), new_nid, false);
	if (!new_page) {
		pr_err("[snapfs cow_node]: failed to grab cache page for new double_indirect_node\n");
		f2fs_alloc_nid_failed(sbi, new_nid);
		kvfree(child_nids);
		kvfree(new_child_nids);
		return 0;
	}

	/* 5. 增加有效 node 计数 */
	err = inc_valid_node_count(sbi, snap_inode, false);
	if (err) {
		pr_err("[snapfs cow_node]: failed to inc_valid_node_count for double_indirect\n");
		f2fs_put_page(new_page, 1);
		f2fs_alloc_nid_failed(sbi, new_nid);
		kvfree(child_nids);
		kvfree(new_child_nids);
		return 0;
	}

	new_rn = F2FS_NODE(new_page);

	/* 6. 填充新 double_indirect_node 的子 nid 数组 */
	for (i = 0; i < NIDS_PER_BLOCK; i++) {
		new_rn->in.nid[i] = cpu_to_le32(new_child_nids[i]);
	}

	/* 7. 设置新的 node footer */
	fill_node_footer(new_page, new_nid, snap_inode->i_ino, dindirect_ofs, false);
	set_cold_node(new_page, S_ISDIR(snap_inode->i_mode));

	/* 8. 设置 NAT 映射 */
	new_ni.nid = new_nid;
	new_ni.ino = snap_inode->i_ino;
	new_ni.blk_addr = NULL_ADDR;
	new_ni.flag = 0;
	new_ni.version = 0;
	set_node_addr(sbi, &new_ni, NEW_ADDR, false);

	/* 9. 标记页面为最新并设置脏 */
	if (!PageUptodate(new_page))
		SetPageUptodate(new_page);
	set_page_dirty(new_page);

	/* 10. 完成 nid 分配 */
	f2fs_alloc_nid_done(sbi, new_nid);

	/* 11. 释放新页面 */
	f2fs_put_page(new_page, 1);

	/* 释放临时数组 */
	kvfree(child_nids);
	kvfree(new_child_nids);

	if (SNAPFS_DEBUG)
		pr_info("[snapfs cow_node]: copied double_indirect_node src_nid=%u -> new_nid=%u\n",
			src_nid, new_nid);

	return new_nid;
}

/**
 * f2fs cow copy_all_nodes - 复制 inode 的所有间接节点树
 * @src_inode: 源 inode
 * @snap_inode: 快照 inode
 *
 * 为快照 inode 创建独立的 node block 树。
 * 只复制 node block，数据块通过 mulref 机制共享。
 * 注意：为避免死锁，采用三阶段处理：
 *   1. 读取源 inode 的所有 i_nid，释放锁
 *   2. 递归复制所有 node（不持有任何 inode page 锁）
 *   3. 获取快照 inode page 锁，更新 i_nid
 *
 * 返回: 0 成功，负数错误码
 */
int f2fs_cow_copy_all_nodes(struct inode *src_inode, struct inode *snap_inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(src_inode);
	struct page *src_ipage = NULL;
	struct page *snap_ipage = NULL;
	struct f2fs_inode *src_fi, *snap_fi;
	nid_t src_nids[5];  /* 源 inode 的 i_nid[0-4] */
	nid_t new_nids[5];  /* 新分配的 nid */
	int i, ret = 0;

	if (SNAPFS_DEBUG)
		pr_info("[snapfs cow_node]: start copying nodes for inode %lu -> %lu\n",
			src_inode->i_ino, snap_inode->i_ino);

	memset(new_nids, 0, sizeof(new_nids));

	/* 阶段1：读取源 inode 的所有 i_nid，然后释放锁 */
	src_ipage = f2fs_get_node_page(sbi, src_inode->i_ino);
	if (IS_ERR(src_ipage)) {
		pr_err("[snapfs cow_node]: failed to get src inode page\n");
		return PTR_ERR(src_ipage);
	}
	src_fi = F2FS_INODE(src_ipage);
	for (i = 0; i < 5; i++) {
		src_nids[i] = le32_to_cpu(src_fi->i_nid[i]);
	}
	f2fs_put_page(src_ipage, 1);
	src_ipage = NULL;

	/* 阶段2：递归复制所有 node（此时不持有任何 inode page 锁） */

	/* 处理 i_nid[0]: direct_node, offset = 1 */
	if (src_nids[0] != 0) {
		new_nids[0] = f2fs_cow_copy_direct_node(sbi, src_nids[0], snap_inode, NODE_OFS_DIRECT_0);
		if (new_nids[0] == 0) {
			pr_err("[snapfs cow_node]: failed to copy direct_node i_nid[0]\n");
			ret = -ENOMEM;
			goto out_copy_failed;
		}
		if (SNAPFS_DEBUG)
			pr_info("[snapfs cow_node]: i_nid[0]: %u -> %u\n", src_nids[0], new_nids[0]);
	}

	/* 处理 i_nid[1]: direct_node, offset = 2 */
	if (src_nids[1] != 0) {
		new_nids[1] = f2fs_cow_copy_direct_node(sbi, src_nids[1], snap_inode, NODE_OFS_DIRECT_1);
		if (new_nids[1] == 0) {
			pr_err("[snapfs cow_node]: failed to copy direct_node i_nid[1]\n");
			ret = -ENOMEM;
			goto out_copy_failed;
		}
		if (SNAPFS_DEBUG)
			pr_info("[snapfs cow_node]: i_nid[1]: %u -> %u\n", src_nids[1], new_nids[1]);
	}

	/* 处理 i_nid[2]: indirect_node, offset = 3, 子 direct_node 起始 offset = 4 */
	if (src_nids[2] != 0) {
		new_nids[2] = f2fs_cow_copy_indirect_node(sbi, src_nids[2], snap_inode,
		                                           NODE_OFS_INDIRECT_0, 4);
		if (new_nids[2] == 0) {
			pr_err("[snapfs cow_node]: failed to copy indirect_node i_nid[2]\n");
			ret = -ENOMEM;
			goto out_copy_failed;
		}
		if (SNAPFS_DEBUG)
			pr_info("[snapfs cow_node]: i_nid[2]: %u -> %u\n", src_nids[2], new_nids[2]);
	}

	/* 处理 i_nid[3]: indirect_node, offset = 4+N, 子 direct_node 起始 offset = 5+N */
	if (src_nids[3] != 0) {
		new_nids[3] = f2fs_cow_copy_indirect_node(sbi, src_nids[3], snap_inode,
		                                           NODE_OFS_INDIRECT_1,
		                                           5 + NIDS_PER_BLOCK);
		if (new_nids[3] == 0) {
			pr_err("[snapfs cow_node]: failed to copy indirect_node i_nid[3]\n");
			ret = -ENOMEM;
			goto out_copy_failed;
		}
		if (SNAPFS_DEBUG)
			pr_info("[snapfs cow_node]: i_nid[3]: %u -> %u\n", src_nids[3], new_nids[3]);
	}

	/* 处理 i_nid[4]: double_indirect_node, offset = 5+2N */
	if (src_nids[4] != 0) {
		new_nids[4] = f2fs_cow_copy_double_indirect_node(sbi, src_nids[4], snap_inode);
		if (new_nids[4] == 0) {
			pr_err("[snapfs cow_node]: failed to copy double_indirect_node i_nid[4]\n");
			ret = -ENOMEM;
			goto out_copy_failed;
		}
		if (SNAPFS_DEBUG)
			pr_info("[snapfs cow_node]: i_nid[4]: %u -> %u\n", src_nids[4], new_nids[4]);
	}

out_copy_failed:
	/* 阶段3：获取快照 inode page 锁，更新 i_nid */
	snap_ipage = f2fs_get_node_page(sbi, snap_inode->i_ino);
	if (IS_ERR(snap_ipage)) {
		pr_err("[snapfs cow_node]: failed to get snap inode page\n");
		return PTR_ERR(snap_ipage);
	}
	snap_fi = F2FS_INODE(snap_ipage);

	for (i = 0; i < 5; i++) {
		snap_fi->i_nid[i] = cpu_to_le32(new_nids[i]);
	}

	/* 标记快照 inode page 为脏 */
	set_page_dirty(snap_ipage);
	f2fs_put_page(snap_ipage, 1);

	if (SNAPFS_DEBUG)
		pr_info("[snapfs cow_node]: finished copying all nodes, ret=%d\n", ret);

	return ret;
}

void f2fs_cow_update_inode(struct inode *src_inode,struct inode *snap_inode){
	snap_inode->i_mode = src_inode->i_mode;
	snap_inode->i_opflags = src_inode->i_opflags;
	snap_inode->i_uid = src_inode->i_uid;
	snap_inode->i_gid = src_inode->i_gid;
	snap_inode->i_flags = src_inode->i_flags;
	if (S_ISCHR(src_inode->i_mode) || S_ISBLK(src_inode->i_mode)) {
		snap_inode->i_rdev = src_inode->i_rdev;
	}
	snap_inode->i_atime = src_inode->i_atime;
	snap_inode->i_mtime = src_inode->i_mtime;
	snap_inode->i_ctime = src_inode->i_ctime;
	snap_inode->i_blkbits = src_inode->i_blkbits;
	snap_inode->i_write_hint = src_inode->i_write_hint;
	snap_inode->i_bytes = src_inode->i_bytes;
	snap_inode->i_version = src_inode->i_version;
	snap_inode->i_sequence = src_inode->i_sequence;
	snap_inode->i_generation = src_inode->i_generation;
	snap_inode->dirtied_when = src_inode->dirtied_when;
	snap_inode->dirtied_time_when = src_inode->dirtied_time_when;
    snap_inode->i_count = src_inode->i_count;

	/* 复制 inode 扩展属性 */
	F2FS_I(snap_inode)->i_projid = F2FS_I(src_inode)->i_projid;
	F2FS_I(snap_inode)->i_pino = F2FS_I(src_inode)->i_pino;
}

static void __maybe_unused __add_sum_entry(struct f2fs_sb_info *sbi, int type,
					struct f2fs_summary *sum)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	void *addr = curseg->sum_blk;

	addr += curseg->next_blkoff * sizeof(struct f2fs_summary);
	memcpy(addr, sum, sizeof(struct f2fs_summary));
}


void __update_sum_entry(struct f2fs_sb_info *sbi, int type,
                        unsigned int offset, struct f2fs_summary *sum)
{
    struct curseg_info *curseg = CURSEG_I(sbi, type);
    // pr_info("__update_sum_entry: nid[%u],ofs[%u],ver[%u]\n",
    //         le32_to_cpu(sum->nid),sum->ofs_in_node,sum->version);
    // 安全检查
    if (WARN_ON(offset >= sbi->blocks_per_seg))
        return;
    
    // 直接内存拷贝（和__add_sum_entry一样的逻辑）
    // memcpy(curseg->sum_blk + offset * sizeof(struct f2fs_summary),
    //        sum, sizeof(struct f2fs_summary));
    curseg->sum_blk->entries[offset].nid = sum->nid;
    curseg->sum_blk->entries[offset].ofs_in_node = sum->ofs_in_node;
    curseg->sum_blk->entries[offset].version = sum->version;
    // struct f2fs_summary old_sum2;
    // old_sum2 = curseg->sum_blk->entries[offset];
    // pr_info("add sum2: nid[%u],ofs[%u],ver[%u]\n",
    //     le32_to_cpu(old_sum2.nid),old_sum2.ofs_in_node,old_sum2.version);   
}


static int __f2fs_update_summary_locked(struct f2fs_sb_info *sbi, block_t blkaddr,
                       struct f2fs_summary *new_sum, unsigned int old_segno,
                       unsigned int offset)
{
    struct curseg_info *curseg = NULL;
    int type = DATA;
    unsigned int old_type;
    struct page *sum_page;
    struct f2fs_summary_block *sum_blk;

    for (old_type = CURSEG_HOT_DATA; old_type <= CURSEG_COLD_DATA; old_type++) {
        struct curseg_info *ci = CURSEG_I(sbi, old_type);
        if (ci->segno == old_segno) {
            curseg = ci;
            break;
        }
    }

    if (curseg) {
        __update_sum_entry(sbi, type, offset, new_sum);
    } else {
        unsigned int segno = GET_SEGNO(sbi, blkaddr);
        unsigned int blkoff = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);

        sum_page = f2fs_get_sum_page(sbi, segno);
        if (IS_ERR(sum_page))
            return PTR_ERR(sum_page);

        sum_blk = (struct f2fs_summary_block *)page_address(sum_page);
        sum_blk->entries[blkoff].nid = new_sum->nid;
        sum_blk->entries[blkoff].ofs_in_node = new_sum->ofs_in_node;
        sum_blk->entries[blkoff].version = new_sum->version;
        set_page_dirty(sum_page);
        /* 新增: 标记该 summary page 为脏，确保后续读取从 SSA */
        mark_sum_page_dirty(sbi, old_segno);
        snapfs_put_meta_page_auto(sum_page);
    }

    return 0;
}

static int snapfs_overwrite_summary_cache(struct f2fs_sb_info *sbi, block_t blkaddr,
				      struct f2fs_summary *new_sum)
{
	unsigned int segno = GET_SEGNO(sbi, blkaddr);
	unsigned int blkoff = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);
	unsigned int type;

	down_read(&SM_I(sbi)->curseg_lock);
	for (type = CURSEG_HOT_DATA; type <= CURSEG_COLD_DATA; type++) {
		struct curseg_info *curseg = CURSEG_I(sbi, type);

		if (curseg->segno != segno || !curseg->sum_blk)
			continue;
		mutex_lock(&curseg->curseg_mutex);
		curseg->sum_blk->entries[blkoff] = *new_sum;
		mutex_unlock(&curseg->curseg_mutex);
		up_read(&SM_I(sbi)->curseg_lock);
		return 0;
	}
	up_read(&SM_I(sbi)->curseg_lock);
	return 0;
}

int f2fs_update_summary(struct f2fs_sb_info *sbi, block_t blkaddr,
                       struct f2fs_summary *new_sum, unsigned int old_segno,
                       unsigned int offset)
{
    struct curseg_info *curseg = NULL;
    unsigned int old_type;
    int ret;

    pr_info("update sum: nid[%u],ofs[%u](<336),ver[%u]\n",
            le32_to_cpu(new_sum->nid), new_sum->ofs_in_node, new_sum->version);

    for (old_type = CURSEG_HOT_DATA; old_type <= CURSEG_COLD_DATA; old_type++) {
        struct curseg_info *ci = CURSEG_I(sbi, old_type);
        if (ci->segno == old_segno) {
            curseg = ci;
            break;
        }
    }

    down_read(&SM_I(sbi)->curseg_lock);
    if (curseg)
        mutex_lock(&curseg->curseg_mutex);

    ret = __f2fs_update_summary_locked(sbi, blkaddr, new_sum, old_segno, offset);

    if (curseg)
        mutex_unlock(&curseg->curseg_mutex);
    up_read(&SM_I(sbi)->curseg_lock);

    return ret;
}



typedef struct StacksnapNode {
    nid_t	i_ino;  // 存储字符
    struct StacksnapNode* next;  // 指向下一个节点
} StacksnapNode;

// 栈结构体
typedef struct Stack_snap {
    StacksnapNode* top;  // 栈顶指针
} Stack_snap;

typedef struct {
    StacksnapNode *cur;
} snap_iter_t;

static inline void snap_iter_init(snap_iter_t *it,
                                  const Stack_snap *stack)
{
    it->cur = stack->top;
}

// 初始化栈
void snap_initStack(Stack_snap* stack) {
    stack->top = NULL;
}

// 判断栈是否为空
int snap_isEmpty(Stack_snap* stack) {
    return stack->top == NULL;
}

// 将字符压入栈
int snap_push(Stack_snap* stack, unsigned long ino) {
    StacksnapNode* newNode = (StacksnapNode*)kmalloc(sizeof(StacksnapNode), GFP_KERNEL);
    if (newNode == NULL) {
        pr_info("内存分配失败！\n");
        return 1;
    }
    newNode->i_ino = ino;
    newNode->next = stack->top;
    stack->top = newNode;
	return 0;
}

// 弹出栈顶元素
unsigned long snap_pop(Stack_snap* stack) {
    StacksnapNode* temp; //= stack->top;
	unsigned long top_ino;// = temp->i_ino;
	if (snap_isEmpty(stack)) {
        pr_info("stack is NULL\n");
		// kfree(temp);
        return 1;  // 栈空时直接退出
    }
	temp = stack->top;
	top_ino = temp->i_ino;
    stack->top = temp->next;
    kfree(temp);
	// return 0;
    return top_ino;
}
// pop 不清除
int snap_pop2(Stack_snap* stack, nid_t *ino, nid_t *ino2) {
    StacksnapNode* temp;
	temp = stack->top;
    if (temp->next == NULL) {
        return 1;
    }
	*ino = temp->i_ino;
	*ino2 = temp->next->i_ino;  // 移动到下一个节点
	return 0;	
}

// 释放栈的内存
void freeStacksnap(Stack_snap* stack) {
    while (!snap_isEmpty(stack)) {
        snap_pop(stack);
    }
}

// 在 f2fs_fill_super() 成功后：
// sbi->magic_mgr = kzalloc(sizeof(struct magic_mgr), GFP_KERNEL);
// spin_lock_init(&sbi->magic_mgr->lock);
// init_waitqueue_head(&sbi->magic_mgr->wq);
// atomic_set(&sbi->magic_mgr->need_scan, 1);

// sbi->magic_mgr->thread =
// 	kthread_run(magic_reclaim_thread, sbi, "f2fs_magic");

static int __maybe_unused curmulref_rotate_block(struct f2fs_sb_info *sbi,struct page *page)
{
    struct curmulref_info *cmr = &SM_I(sbi)->curmulref_blk;
    block_t new_blkaddr;
    // struct page *old_page;
    struct f2fs_mulref_block *blk;
    block_t old_blkaddr;
    old_blkaddr = cmr->blkaddr;
    
	if(old_blkaddr + 1 < sbi->sm_info->ssa_blkaddr){ // 分配下一个
		new_blkaddr = old_blkaddr + 1;
	}else { // 循环从0开始
		new_blkaddr = sbi->magic_info->mulref_blkaddr;
	}
    cmr->blkaddr = new_blkaddr;
    cmr->next_free_entry = 0;
    if(old_blkaddr == 48766){
        pr_info("oldaddr:[%u] new_addr:[%u] next [%u]\n",old_blkaddr,new_blkaddr,cmr->next_free_entry);
    }
    sbi->ckpt->cur_mulref_blk = new_blkaddr - (sbi->magic_info->mulref_blkaddr);
    return 0;
}


/*
 * 两阶段锁策略：
 * - 快速路径（读锁）：查找当前块中的空闲 entry，大多数情况下无阻塞
 * - 慢速路径（写锁）：只在块满需要旋转时获取写锁
 *
 * 注意：此函数内部获取锁，不需要调用者持有锁
 */
int curmulref_alloc_entry(struct f2fs_sb_info *sbi, u16 *eidx)
{
    struct f2fs_sm_info *sm = SM_I(sbi);
    struct curmulref_info *cmr = &SM_I(sbi)->curmulref_blk;
    struct f2fs_mulref_block *blk;
    u16 idx = 0;
    int err = 0;
    struct page *page = NULL;
    struct page *prev_page = NULL;

    if (!cmr->inited) {
        pr_err("curmulref not initialized!\n");
        return -EINVAL;
    }

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

    /* 再次检查是否有空闲 entry（可能已被其他写者分配） */
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
        f2fs_put_page(prev_page, 1);
    }
    prev_page = NULL;

    /* 更新 curmulref 块地址 */
    if (cmr->blkaddr + 1 < sm->ssa_blkaddr) {
        cmr->blkaddr += 1;
    } else {
        cmr->blkaddr = sbi->magic_info->mulref_blkaddr;
    }
    cmr->next_free_entry = 0;
    sbi->ckpt->cur_mulref_blk =
        cmr->blkaddr - sbi->magic_info->mulref_blkaddr;
    pr_debug("[curmulref_alloc] rotated to blkaddr=%u\n", cmr->blkaddr);

    /* 在新块中查找 */
    page = f2fs_get_meta_page(sbi, cmr->blkaddr);
    if (IS_ERR(page)) {
        err = PTR_ERR(page);
        page = NULL;
        goto out_write;
    }
    blk = page_address(page);

    for (idx = 0; idx < MRENTRY_PER_BLOCK; idx++) {
        if (!f2fs_test_bit(idx, (char *)blk->multi_bitmap))
            goto found_write;
    }

    /* 新块也满了 */
    err = -ENOSPC;
    goto out_write;

found_write:
    /* claim entry（在写锁内） */
    f2fs_set_bit(idx, (char *)blk->multi_bitmap);
    cmr->used_entries++;
    cmr->next_free_entry = idx + 1;
    blk->v_mrentrys = cpu_to_le16(le16_to_cpu(blk->v_mrentrys) + 1);
    blk->next_free_mrentry = cpu_to_le16(cmr->next_free_entry);
    memset(&blk->mrentries[idx], 0, sizeof(struct f2fs_mulref_entry));
    set_page_dirty(page);
    f2fs_put_page(page, 1);
    page = NULL;
    *eidx = idx;

out_write:
    if (page)
        f2fs_put_page(page, 1);
    if (prev_page)
        f2fs_put_page(prev_page, 1);
    up_write(&sm->curmulref_lock);
    return err;

found_read:
    /* claim entry（在读锁内，快速路径） */
    f2fs_set_bit(idx, (char *)blk->multi_bitmap);
    cmr->used_entries++;
    cmr->next_free_entry = idx + 1;
    blk->v_mrentrys = cpu_to_le16(le16_to_cpu(blk->v_mrentrys) + 1);
    blk->next_free_mrentry = cpu_to_le16(cmr->next_free_entry);
    memset(&blk->mrentries[idx], 0, sizeof(struct f2fs_mulref_entry));
    set_page_dirty(page);
    f2fs_put_page(page, 1);
    page = NULL;
    *eidx = idx;

    up_read(&sm->curmulref_lock);
    pr_debug("[curmulref_alloc] allocated (fast path): blkaddr=%u, eidx=%u\n", cmr->blkaddr, idx);
    return 0;
}

/*
 * curmulref_alloc_multi - 原子分配多个 entry
 * @sbi: 文件系统信息
 * @count: 需要分配的 entry 数量（1 或 2）
 * @info: 输出数组，存储每个 entry 的 (blkaddr, eidx)
 *
 * 确保所有分配的 entry 来自同一个块，避免跨块问题
 * 使用两阶段锁：快速路径读锁，慢速路径写锁
 */
int curmulref_alloc_multi(struct f2fs_sb_info *sbi, int count,
                         struct curmulref_alloc_info *info)
{
    struct f2fs_sm_info *sm = SM_I(sbi);
    struct curmulref_info *cmr = &SM_I(sbi)->curmulref_blk;
    int ret = 0;
    int i;
    struct page *prev_page = NULL;

    if (count < 1 || count > 2) {
        pr_err("[curmulref] invalid count %d\n", count);
        return -EINVAL;
    }

    if (!cmr->inited) {
        pr_err("curmulref not initialized!\n");
        return -EINVAL;
    }

    /* 初始化输出 */
    for (i = 0; i < count; i++) {
        info[i].blkaddr = 0;
        info[i].eidx = 0;
    }

    pr_debug("[curmulref_alloc_multi] count=%d, cmr->blkaddr=%u\n",
             count, cmr->blkaddr);

    /* === 快速路径：读锁 + 批量分配 === */
    down_read(&sm->curmulref_lock);

    for (i = 0; i < count; i++) {
        struct f2fs_mulref_block *blk;
        struct page *page;
        u16 idx;
        block_t blkaddr;

        page = f2fs_get_meta_page(sbi, cmr->blkaddr);
        if (IS_ERR(page)) {
            ret = PTR_ERR(page);
            up_read(&sm->curmulref_lock);
            goto out;
        }

        blk = page_address(page);
        blkaddr = cmr->blkaddr;

        /* 查找空闲 entry */
        for (idx = cmr->next_free_entry; idx < MRENTRY_PER_BLOCK; idx++) {
            if (!f2fs_test_bit(idx, (char *)blk->multi_bitmap)) {
                /* 找到空闲 entry */
                f2fs_set_bit(idx, (char *)blk->multi_bitmap);
                cmr->used_entries++;
                cmr->next_free_entry = idx + 1;
                blk->v_mrentrys = cpu_to_le16(le16_to_cpu(blk->v_mrentrys) + 1);
                blk->next_free_mrentry = cpu_to_le16(cmr->next_free_entry);
                memset(&blk->mrentries[idx], 0, sizeof(struct f2fs_mulref_entry));
                set_page_dirty(page);
                f2fs_put_page(page, 1);

                info[i].blkaddr = blkaddr;
                info[i].eidx = idx;
                break;
            }
        }

        if (info[i].blkaddr == 0) {
            /* 当前块已满，需要旋转 */
            f2fs_put_page(page, 1);
            up_read(&sm->curmulref_lock);
            goto slow_path;
        }
    }

    up_read(&sm->curmulref_lock);
    pr_debug("[curmulref_alloc_multi] fast path success\n");
    return 0;

slow_path:
    /* === 慢速路径：写锁 + 旋转 === */
    down_write(&sm->curmulref_lock);

    /* 旋转当前块（如果需要） */
    prev_page = f2fs_get_meta_page(sbi, cmr->blkaddr);
    if (!IS_ERR(prev_page)) {
        set_page_dirty(prev_page);
        f2fs_put_page(prev_page, 1);
    }

    /* 更新块地址 */
    if (cmr->blkaddr + 1 < sm->ssa_blkaddr)
        cmr->blkaddr += 1;
    else
        cmr->blkaddr = sbi->magic_info->mulref_blkaddr;
    cmr->next_free_entry = 0;
    sbi->ckpt->cur_mulref_blk = cmr->blkaddr - sbi->magic_info->mulref_blkaddr;

    /* 在新块中分配所有 entry */
    for (i = 0; i < count; i++) {
        struct f2fs_mulref_block *blk;
        struct page *page;
        u16 idx;

        page = f2fs_get_meta_page(sbi, cmr->blkaddr);
        if (IS_ERR(page)) {
            ret = PTR_ERR(page);
            up_write(&sm->curmulref_lock);
            goto out;
        }

        blk = page_address(page);

        for (idx = 0; idx < MRENTRY_PER_BLOCK; idx++) {
            if (!f2fs_test_bit(idx, (char *)blk->multi_bitmap)) {
                f2fs_set_bit(idx, (char *)blk->multi_bitmap);
                cmr->used_entries++;
                cmr->next_free_entry = idx + 1;
                blk->v_mrentrys = cpu_to_le16(1);
                blk->next_free_mrentry = cpu_to_le16(1);
                memset(&blk->mrentries[idx], 0, sizeof(struct f2fs_mulref_entry));
                set_page_dirty(page);
                f2fs_put_page(page, 1);

                info[i].blkaddr = cmr->blkaddr;
                info[i].eidx = idx;
                break;
            }
        }

        if (info[i].blkaddr == 0) {
            /* 新块也满了 */
            ret = -ENOSPC;
            up_write(&sm->curmulref_lock);
            goto out;
        }
    }

    up_write(&sm->curmulref_lock);
    pr_debug("[curmulref_alloc_multi] slow path success\n");
    return 0;

out:
    /* 回滚已分配的 entry（简化处理：只记录错误，不回滚 bitmap） */
    for (i = 0; i < count; i++) {
        if (info[i].blkaddr != 0) {
            pr_warn("[curmulref_alloc_multi] rollback entry: blkaddr=%u, eidx=%u\n",
                    info[i].blkaddr, info[i].eidx);
            info[i].blkaddr = 0;
            info[i].eidx = 0;
        }
    }
    return ret;
}

bool check_sit_mulref_entry(struct f2fs_sb_info *sbi, block_t blkaddr)
{
    struct sit_mulref_info *smi = SIT_MR_I(sbi);
    struct sit_mulref_entry *me;
    unsigned int segno;
    unsigned int blkoff;
    unsigned int sit_page_idx;
    bool result = false;

    /* 1. 安全检查 */
    if (!smi || !smi->smentries) {
        f2fs_info(sbi, "check sit mulref entry: smi is NULL or smentries is NULL");
        return false;
    }

    /* 2. 计算段号和块偏移 */
    segno = GET_SEGNO(sbi, blkaddr);
    blkoff = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);

    /* 3. 验证边界 */
    if (segno >= MAIN_SEGS(sbi) || blkoff >= sbi->blocks_per_seg) {
        f2fs_err(sbi, "ERROR: invalid segno=%u or blkoff=%u, blkaddr=%u",
                 segno, blkoff, blkaddr);
        return false;
    }

    /* 4. 计算对应的 sit page index */
    sit_page_idx = segno / smi->sments_per_block;

    /* 5. 检查脏标记 (无锁快速路径) */
    if (smi->dirty_sit_pages_bitmap &&
        test_bit(sit_page_idx, smi->dirty_sit_pages_bitmap)) {
        block_t sit_blkaddr = smi->base_addr + sit_page_idx;
        reload_smentries_from_sit_page(sbi, sit_blkaddr);
    }

    /* 6. 加读锁保护并发访问 */
    down_read(&smi->smentry_lock);

    /* 7. 再次检查smentries是否仍然有效 */
    if (unlikely(!smi->smentries)) {
        up_read(&smi->smentry_lock);
        f2fs_err(sbi, "smentries became NULL after lock");
        return false;
    }

    /* 8. 获取对应的段多引用条目 */
    me = &smi->smentries[segno];

    /* 9. 检查bitmap指针是否有效 */
    if (unlikely(!me->mvalid_map)) {
        up_read(&smi->smentry_lock);
        f2fs_err(sbi, "mvalid_map is NULL for segno=%u", segno);
        return false;
    }

    /* 使用f2fs_test_bit与update函数保持一致 */
    result = f2fs_test_bit(blkoff, (char *)me->mvalid_map);

    // pr_info("[DEBUG CHECK] blkaddr=%u segno=%u blkoff=%u, byte[%u]=0x%02x result=%d\n",
    //       blkaddr, segno, blkoff, blkoff/8, me->mvalid_map[blkoff/8], result);

    /* 释放读锁 */
    up_read(&smi->smentry_lock);
    
    return result;
}

/**
 * check sit_mulref entry - 检查指定块地址是否被标记为多引用
 * @sbi: F2FS超级块信息
 * @blkaddr: 要检查的块地址
 * 
 * 返回: true - 该块被标记为多引用
 *       false - 该块未被标记为多引用，或发生错误
 */

void update_sit_mulref_entry(struct f2fs_sb_info *sbi,
                 block_t blkaddr,
                 bool set)
{
    struct sit_mulref_info *smi = SIT_MR_I(sbi);
    struct sit_mulref_entry *me;
    unsigned int segno;
    unsigned int blkoff;
    bool old;
    
    if (!smi) {
        pr_info("smi is null, update mulref flag failed\n");
        return;
    }

    segno = GET_SEGNO(sbi, blkaddr);
    blkoff = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);
    
    // 添加边界检查
    if (segno >= MAIN_SEGS(sbi)) {
        pr_err("segno %u out of range (max %u)\n", segno, MAIN_SEGS(sbi));
        return;
    }

    // 检查 blkoff 是否有效
    unsigned int blocks_per_seg = sbi->blocks_per_seg;
    if (blkoff >= blocks_per_seg) {
        pr_err("blkoff %u out of range (max %u)\n", blkoff, blocks_per_seg);
        return;
    }

    down_write(&smi->smentry_lock);
    
    me = &smi->smentries[segno];

    // 修复：使用 f2fs_test_bit 而不是 test_bit
    old = f2fs_test_bit(blkoff, (char *)me->mvalid_map);
    
    if (set) { // 设置多引用
        if (!old) { // 如果原来是0，就设置为1
            // 修复：使用 f2fs_set_bit
            f2fs_set_bit(blkoff, (char *)me->mvalid_map);
            // pr_info("[DEBUG SET] blkaddr=%u segno=%u blkoff=%u, byte[%u]=0x%02x\n",
            //   blkaddr, segno, blkoff, blkoff/8, me->mvalid_map[blkoff/8]);
            
            // 修复：正确处理 __le16 的递增
            
            __le16 old_mblocks = me->mblocks;
            __u16 new_value = le16_to_cpu(old_mblocks) + 1;
            me->mblocks = cpu_to_le16(new_value);
            me->dirty = true;
            
            if (SNAPFS_DEBUG) {
                pr_info("Set mulref: segno=%u, blkoff=%u, mblocks %u->%u\n",
                        segno, blkoff, 
                        le16_to_cpu(me->mblocks),le16_to_cpu(me->mblocks) + 1);
            }
        } else {
            // 如果原来是1，不应该增加计数！
            if (SNAPFS_DEBUG) {
                pr_info("Mulref already set: segno=%u, blkoff=%u\n",
                        segno, blkoff);
            }
            // 注意：原来的代码会错误地增加 me->mblocks++，修复后不增加
        }
    } else { // 取消多引用设置
        if (old) { // 如果原来是1，就设置为0
            // 修复：使用 f2fs_clear_bit
            f2fs_clear_bit(blkoff, (char *)me->mvalid_map);
            
            
            if (le16_to_cpu(me->mblocks) > 0) {
                me->mblocks = cpu_to_le16(le16_to_cpu(me->mblocks) - 1);
                me->dirty = true;
                
                if (SNAPFS_DEBUG) {
                    pr_info("Clear mulref: segno=%u, blkoff=%u, mblocks %u->%u\n",
                            segno, blkoff, le16_to_cpu(me->mblocks), le16_to_cpu(me->mblocks) - 1);
                }
            } else {
                // 计数已经是0，但位图显示为1，数据不一致
                pr_warn("Inconsistent: mblocks=0 but bitmap=1 at segno=%u, blkoff=%u\n",
                        segno, blkoff);
                me->dirty = true; // 位图改变了
            }
        } else {
            // 如果已经是0，不需要操作
            if (SNAPFS_DEBUG) {
                pr_info("Mulref already cleared: segno=%u, blkoff=%u\n",
                        segno, blkoff);
            }
        }
    }

    // 更新时间戳
    if (me->dirty) {
        me->m_mtime = cpu_to_le64(get_mtime(sbi, false));
        // me->m_mtime = cpu_to_le64(ktime_get_real_seconds());
    }
    
    up_write(&smi->smentry_lock);
}

static inline void mulref_mark_invalid(struct f2fs_mulref_block *blk, u16 idx)
{
	/* already invalid */
    if (!f2fs_test_bit(idx, (char *)blk->multi_bitmap)){ 
	// if (!test_bit(idx, (unsigned long *)blk->multi_bitmap))
		return;
    }
    f2fs_clear_bit(idx, (char *)blk->multi_bitmap);
	// clear_bit(idx, (unsigned long *)blk->multi_bitmap);

	if (blk->v_mrentrys > 0)
		blk->v_mrentrys--;
}

// mulref batch - 按 node block 处理批量 redo
// 用于 SnapFS Batch Redo 设计

/*
 * 处理一个 node block 中所有数据块的 mulref 设置
 * 使用 batch redo 机制：先暂存所有 redo，再统一 commit，最后 apply
 *
 * 简化实现：每个数据块对应一个 batch entry
 * entry_count == nr_data_blks == valid_bits
 *
 * 注意：对于"普通块首次转 mulref"场景，暂存第一个 mulref entry 的 redo
 * 第二个 mulref entry 在 apply 阶段分配
 *
 * @inode: 源文件 inode
 * @src_ino: 源文件 inode 号
 * @node_nid: 当前 node block 的 nid
 * @node_ofs: node block 的 offset
 * @data_blks: 数据块地址数组
 * @nr_data_blks: 数据块数量
 * @lblks: 对应的逻辑块号数组
 *
 * 返回值：0 成功，非 0 失败
 */
static int f2fs_cow_node_block_batch(struct inode *inode, u32 src_ino,
				     nid_t node_nid, u16 node_ofs,
				     block_t *data_blks, int nr_data_blks,
				     u16 *lblks)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_sm_info *sm = SM_I(sbi);
	struct snapfs_batch_context *batch_ctx = NULL;
	pr_info("[snapfs batch] f2fs_cow_node_block_batch ENTER: inode=%u, src_ino=%u, node_nid=%u, node_ofs=%u, nr_data_blks=%d\n",
	        inode->i_ino, src_ino, node_nid, node_ofs, nr_data_blks);
	struct snap_redo_info *redo = sbi->magic_info->redo_info;
	struct curmulref_info *cmr = &sm->curmulref_blk;
	u32 slot_id;
	int ret = 0;
	int i;
	block_t old_blkaddr;
	bool is_mulref;
	u16 eidx;
	block_t blkaddr;
	struct f2fs_summary old_sum, new_sum;
	struct f2fs_mulref_entry *entry;
	unsigned int segno;
	block_t sit_blkaddr;
	int entry_idx;

	if (!data_blks || nr_data_blks <= 0) {
		pr_debug("[snapfs batch] no data blocks to process\n");
		return 0;
	}

	/* 检查 batch mode 是否启用 */
	if (!redo || !redo->batch_mode) {
		pr_err("[snapfs batch] batch mode not enabled\n");
		return -EINVAL;
	}

	/* 分配 batch slot（规则 3：必须等待） */
	ret = snapfs_batch_alloc_slot(sbi, src_ino, inode->i_ino,
				     node_nid, node_ofs, nr_data_blks,
				     &slot_id, &batch_ctx);
	if (ret) {
		pr_err("[snapfs batch] failed to allocate slot: %d\n", ret);
		return ret;
	}

	/* 检查 curmulref 是否初始化 */
	if (!cmr->inited) {
		pr_err("[snapfs batch] curmulref not initialized\n");
		ret = -EINVAL;
		goto out_free_slot;
	}

	/* 步骤 2：遍历所有数据块并暂存 redo 到 batch_ctx->entries
	 * 简化：每个数据块对应一个 batch entry
	 * 对于普通块转 mulref 场景，暂存第一个 mulref entry
	 * 第二个 entry 在 apply 阶段分配
	 */
	for (i = 0; i < nr_data_blks; i++) {
		old_blkaddr = data_blks[i];

		if (!__is_valid_data_blkaddr(old_blkaddr)) {
			continue;
		}

		/* 只在关键节点打印进度（每 100 个块） */
		if (i == 0 || i == 100 || i == 200 || i == 300 || i == 400 ||
		    i == 500 || i == 600 || i == 700 || i == 800 || i == nr_data_blks - 1) {
			pr_info("[snapfs batch] staging: i=%d/%d, old_blkaddr=%u\n",
			        i, nr_data_blks, old_blkaddr);
		}

		/* 获取 old summary */
		ret = f2fs_get_summary_by_addr(sbi, old_blkaddr, &old_sum);
		if (ret) {
			pr_err("[snapfs batch] get old summary failed, blkaddr=%u\n",
			       old_blkaddr);
			goto out_free_slot;
		}

		is_mulref = check_sit_mulref_entry(sbi, old_blkaddr);
		segno = GET_SEGNO(sbi, old_blkaddr);
		sit_blkaddr = SIT_MR_I(sbi)->base_addr +
			(segno / SIT_MR_I(sbi)->sments_per_block);

		entry_idx = batch_ctx->entry_count;

		if (entry_idx >= batch_ctx->entry_capacity) {
			pr_err("[snapfs batch] entry capacity exceeded\n");
			ret = -ENOSPC;
			goto out_free_slot;
		}

		/* 设置 batch entry 基本信息 */
		batch_ctx->entries[entry_idx].bitno = lblks[i];
		batch_ctx->entries[entry_idx].data_blkaddr = cpu_to_le32(old_blkaddr);
		batch_ctx->entries[entry_idx].flags = 0;

		pr_info("[snapfs batch] staging: entry_idx=%d, data_blkaddr=%u, flags=0\n",
		        entry_idx, old_blkaddr);

		if (!is_mulref) {
			/* 普通块首次转 mulref：分配第一个 entry
			 * 第二个 entry 在 apply 阶段分配
			 */
			block_t blkaddr1;

			ret = curmulref_alloc_entry(sbi, &eidx);
			if (ret) {
				pr_err("[snapfs batch] alloc entry failed\n");
				goto out_free_slot;
			}
			blkaddr1 = cmr->blkaddr;

			/* 构建第一个 mulref entry（原始块引用 + 指向第二个 entry） */
			/* 注意：第二个 entry 尚未分配，next 指针暂时为 0
			 * 在 apply 阶段分配第二个 entry 后会更新
			 */
			entry = &batch_ctx->entries[entry_idx].mulref.entry;
			entry->m_nid = old_sum.nid;
			entry->m_ofs = old_sum.ofs_in_node;
			entry->m_ver = old_sum.version;
			entry->m_count = 2;  /* 稍后更新为实际值 */
			entry->next = 0;     /* 暂时为 0，apply 阶段更新 */

			batch_ctx->entries[entry_idx].mulref.mr_blkaddr = cpu_to_le32(blkaddr1);
			batch_ctx->entries[entry_idx].mulref.idx = cpu_to_le16(eidx);
			batch_ctx->entries[entry_idx].mulref.valid = 1;
			batch_ctx->entries[entry_idx].flags |= SNAPFS_BATCH_ENTRY_HAS_MULREF |
							     SNAPFS_BATCH_ENTRY_NEED_SECOND_ALLOC;

			/* 构建 summary op - 指向第一个 mulref entry */
			new_sum.nid = cpu_to_le32(blkaddr1);
			new_sum.ofs_in_node = cpu_to_le16(eidx);
			new_sum.version = old_sum.version;

			batch_ctx->entries[entry_idx].sum.data_blkaddr = cpu_to_le32(old_blkaddr);
			batch_ctx->entries[entry_idx].sum.sum = new_sum;
			batch_ctx->entries[entry_idx].flags |= SNAPFS_BATCH_ENTRY_HAS_SUMMARY;

			/* 调试: 打印 staging 阶段的 summary 信息 */
			pr_info("[snapfs batch] staging: !is_mulref: entry_idx=%d, SUM SET, "
			        "new_sum.nid=%u, new_sum.ofs=%u, new_sum.ver=%u, "
			        "mr_blkaddr=%u, eidx=%u\n",
			        entry_idx,
			        le32_to_cpu(new_sum.nid),
			        le16_to_cpu(new_sum.ofs_in_node),
			        le16_to_cpu(new_sum.version),
			        blkaddr1, eidx);

			/* 暂存 SIT op (set mulref) */
			batch_ctx->entries[entry_idx].sit_blkaddr = cpu_to_le32(sit_blkaddr);
			batch_ctx->entries[entry_idx].sit_set = 1;
			batch_ctx->entries[entry_idx].flags |= SNAPFS_BATCH_ENTRY_HAS_SIT;

		} else {
			/* 已经是 mulref：追加引用，分配 1 个 entry */
			pr_info("[snapfs batch] staging: is_mulref=true branch, entry_idx=%d\n",
			        entry_idx);

			ret = curmulref_alloc_entry(sbi, &eidx);
			if (ret) {
				pr_err("[snapfs batch] alloc entry failed for mulref\n");
				goto out_free_slot;
			}
			blkaddr = cmr->blkaddr;

			/* 构建 mulref entry */
			entry = &batch_ctx->entries[entry_idx].mulref.entry;
			entry->m_nid = cpu_to_le32(old_blkaddr);  /* 使用数据块地址，而非 inode 号 */
			entry->m_ofs = cpu_to_le16(lblks[i]);
			entry->m_ver = old_sum.version;
			entry->m_count = 1;
			entry->next = 0;

			batch_ctx->entries[entry_idx].mulref.mr_blkaddr = cpu_to_le32(blkaddr);
			batch_ctx->entries[entry_idx].mulref.idx = cpu_to_le16(eidx);
			batch_ctx->entries[entry_idx].mulref.valid = 1;
			batch_ctx->entries[entry_idx].flags |= SNAPFS_BATCH_ENTRY_HAS_MULREF;

			/* 暂存 summary op */
			new_sum.nid = cpu_to_le32(blkaddr);
			new_sum.ofs_in_node = cpu_to_le16(eidx);
			new_sum.version = old_sum.version;

			batch_ctx->entries[entry_idx].sum.data_blkaddr = cpu_to_le32(old_blkaddr);
			batch_ctx->entries[entry_idx].sum.sum = new_sum;
			batch_ctx->entries[entry_idx].flags |= SNAPFS_BATCH_ENTRY_HAS_SUMMARY;

			/* 调试: 打印 is_mulref=true 时的 summary 信息 */
			pr_info("[snapfs batch] staging: is_mulref=true: entry_idx=%d, SUM SET, "
			        "new_sum.nid=%u, new_sum.ofs=%u, new_sum.ver=%u, "
			        "mr_blkaddr=%u, eidx=%u\n",
			        entry_idx,
			        le32_to_cpu(new_sum.nid),
			        le16_to_cpu(new_sum.ofs_in_node),
			        le16_to_cpu(new_sum.version),
			        blkaddr, eidx);

			/* 已经是 mulref，不需要更新 SIT */
		}

		batch_ctx->entry_count++;
	}

	pr_info("[snapfs batch] staging: ALL DONE, entry_count=%d\n", batch_ctx->entry_count);

	/* 步骤 3：写入 batch header，进入 PREPARING 状态 */
	ret = snapfs_batch_begin(sbi, batch_ctx->slot_id, batch_ctx);
	if (ret) {
		pr_err("[snapfs batch] begin failed: %d\n", ret);
		goto out_free_slot;
	}

	/* 步骤 4：提交 batch（COMMITTED + durable）*/
	ret = snapfs_batch_commit(sbi, batch_ctx);
	if (ret) {
		pr_err("[snapfs batch] commit failed: %d\n", ret);
		goto out_free_slot;
	}

	/* 步骤 5：按 batch entry 逐个 apply（收集 dirty pages） */
	for (i = 0; i < batch_ctx->entry_count; i++) {
		ret = snapfs_batch_apply_one(sbi, batch_ctx, i);
		if (ret) {
			pr_err("[snapfs batch] apply entry %d failed: %d\n", i, ret);
			goto out_free_slot;
		}
	}

	/* 步骤 5b：批量 flush 所有收集的 dirty pages */
	ret = snapfs_batch_flush_all(sbi, batch_ctx);
	if (ret) {
		pr_err("[snapfs batch] flush all failed: %d\n", ret);
		goto out_free_slot;
	}

	/* 步骤 5c：更新 bitmap（标记所有 entry 已完成） */
	for (i = 0; i < batch_ctx->entry_count; i++)
		f2fs_set_bit(i, batch_ctx->bitmap);

	/* 步骤 6：标记 batch 为 APPLIED */
	ret = snapfs_batch_mark_applied(sbi, batch_ctx);
	if (ret) {
		pr_err("[snapfs batch] mark applied failed: %d\n", ret);
		goto out_free_slot;
	}

	/* 关键修复：清理可能阻塞的 overwrite slot */
	snapfs_batch_clear_stale_overwrite(sbi);

	/*
	pr_info("[snapfs batch] node block (%u,%u): %d entries applied, batch completed\n",
		node_nid, node_ofs, batch_ctx->entry_count);
	*/

out_free_slot:
	snapfs_batch_free_slot(sbi, batch_ctx->slot_id);
	return ret;
}

// mulref
int f2fs_alloc_mulref_entry(struct f2fs_sb_info *sbi,
			    block_t *blkaddr, nid_t ino,
			    struct snapfs_cow_progress *progress,
			    u16 progress_bit)
{
    struct f2fs_sm_info *sm = SM_I(sbi);
	// struct curmulref_info *cmr = NULL;
	int ret;
    struct f2fs_summary old_sum;
    struct f2fs_summary sum;
    struct page *mulref_page = NULL;
    struct page *mulref_page2 = NULL;
    struct page *mulref_page3 = NULL;
    struct f2fs_mulref_block *blk, *blk2, *blk3;
    block_t old_blkaddr = *blkaddr;
    bool is_mulref = check_sit_mulref_entry(sbi, old_blkaddr);
    // if(is_mulref) pr_info("[snapfs alloc]: tp1 is_mulref[%u], blkoff [%u],old data blkaddr[%u]\n",is_mulref, GET_BLKOFF_FROM_SEG0(sbi, old_blkaddr),old_blkaddr);
    u16 eidx_tmp = 0;
    u16 eidx1 = 0, eidx2 = 0, eidx3 = 0;
    block_t blkaddr1 = 0;
    block_t blkaddr2 = 0;
    block_t blkaddr3 = 0;
    block_t blkaddr_tmp = 0;
    u32 tmp_next = 0;
    unsigned int old_segno, blk_off;
    struct f2fs_mulref_entry *mgentry, *mgentry2, *mgentry3;
    block_t start_addr = sbi->magic_info->mulref_blkaddr;
    struct curmulref_info *cmr = &sm->curmulref_blk;

    // pr_info("[PID%d CPU%d] ----\n", current->pid, smp_processor_id());
    // pr_info(" +++++\n", current->pid, smp_processor_id());

    // pr_info("[PID%d CPU%d]: blkoff[%u],old data blkaddr[%u]\n",
    //         current->pid, smp_processor_id(),
    //         GET_BLKOFF_FROM_SEG0(sbi, old_blkaddr),old_blkaddr);
    // common
    old_segno = GET_SEGNO(sbi, old_blkaddr);
    blk_off = GET_BLKOFF_FROM_SEG0(sbi, old_blkaddr);

    ret = f2fs_get_summary_by_addr(sbi, old_blkaddr, &old_sum);
    if (ret) {
        pr_err("[snapfs cow2222]: get old summary failed, blkaddr=%u, err=%d\n",
               old_blkaddr, ret);
        goto out;
    }

    /* curmulref_alloc_entry 现在内部使用两阶段锁，不再需要外部获取锁 */
    pr_debug("[f2fs_alloc_mulref] allocating entries for blkaddr=%u\n", old_blkaddr);

    if(!is_mulref){
        // pr_info("[snapfs alloc]: tp2 (!is_mulref)\n");
        ret = curmulref_alloc_entry(sbi, &eidx_tmp);
        if (ret) {
            pr_err("[snapfs cow2222]: debug alloc failed\n");
            // return ret;
            goto out;
        }
        blkaddr1 = cmr->blkaddr;
        eidx1 = eidx_tmp;
        /* 2. 分配第二个 entry，对应传入的 ino */
        ret = curmulref_alloc_entry(sbi, &eidx_tmp);
        if (ret) {
            pr_err("[snapfs cow2222]: debug alloc entry2 failed\n");
            // return ret;
            goto out;
        }
        blkaddr2 = cmr->blkaddr; //上面分配函数可能触发块的切换，如果没切换那更好
        eidx2 = eidx_tmp;
        // pr_info("alloc(addr, ofs) entry1 [%u, %u] entry2 [%u, %u], old sum [%u, %u, %u]\n",
        //         blkaddr1,eidx1,blkaddr2,eidx2,
        //     le16_to_cpu(old_sum.nid),le16_to_cpu(old_sum.ofs_in_node),
        //             old_sum.version);
    }else{
        // pr_info("[snapfs alloc]: tp3 (is_mulref)\n");
        ret = curmulref_alloc_entry(sbi, &eidx_tmp);
        if (ret) {
            pr_err("[snapfs cow2222]: debug alloc failed /is_mulref\n");
            goto out;
            // return ret;
        }
        blkaddr1 = cmr->blkaddr;
        eidx1 = eidx_tmp;
    }
    

    if(!is_mulref){
        // 注意：已在 2446-2448 获取 curmulref_lock，这里不能重复获取
        // pr_info("[snapfs alloc]: tp4 !is_mulref\n");
        if (blkaddr1 == blkaddr2) {// 同一数据块
            mulref_page = f2fs_get_meta_page(sbi, blkaddr1);
            if (IS_ERR(mulref_page)) {
                pr_err("get mulref page failed\n");
                ret = 1;
                goto out;
            }
            blk = (struct f2fs_mulref_block *)page_address(mulref_page);
            if (!blk) {
                pr_err("mulref blk is NULL\n");
                snapfs_put_meta_page_auto(mulref_page);
                ret = 1;
                goto out;
            }
            mgentry = &blk->mrentries[eidx1];
            mgentry->m_nid = old_sum.nid;
            mgentry->m_ofs = old_sum.ofs_in_node;
            mgentry->m_ver = old_sum.version;
            mgentry->m_count += 2;
            mgentry->next = cpu_to_le32((blkaddr2 - start_addr) * MRENTRY_PER_BLOCK + eidx2);
            sum.nid = cpu_to_le32(blkaddr1);
            sum.ofs_in_node = cpu_to_le16(eidx1);
            sum.version = old_sum.version;	

            // pr_info("[snapfs STORE] blkaddr=%u, stored at: mr_blkaddr=%u, eidx=%u\n",
            //         old_blkaddr, blkaddr1, eidx1);
            // pr_info("[snapfs STORE] entry content: m_nid=%u, m_ofs=%u, m_ver=%u\n",
            //         le32_to_cpu(mgentry->m_nid),
            //         le16_to_cpu(mgentry->m_ofs),
            //         mgentry->m_ver);


            // pr_info("[snapfs cow2222]: debug alloc cmr->blkaddr [%u]\n",cmr->blkaddr);
            // if(old_blkaddr >= 4503280 && old_blkaddr <= 4503286){
                // pr_info("[snapfs cow2222]: segno %u addr %u, old sum[%u, %u, %u], new sum[%u, %u, %u],next entry off %u\n",old_segno,
                //     old_blkaddr,le16_to_cpu(old_sum.nid),le16_to_cpu(old_sum.ofs_in_node),
                //     old_sum.version,le32_to_cpu(sum.nid),le16_to_cpu(sum.ofs_in_node),sum.version,eidx2);
            // }
            // pr_info("[snapfs cow2222]: debug alloc new nid[%u],ofs[%u],ver[%u]\n",blkaddr1,eidx1,old_sum.version);
            mgentry2 = &blk->mrentries[eidx2];
            mgentry2->m_nid = cpu_to_le32(ino);
            mgentry2->m_ofs = old_sum.ofs_in_node;
            mgentry2->m_ver = old_sum.version;
            mgentry2->m_count = mgentry->m_count;
            mgentry2->next = 0;

            {
                struct snapfs_txn txn;
                struct page *sum_page = NULL;
                struct page *sit_page = NULL;
                struct f2fs_summary_block *sum_blk;

                sum_page = f2fs_get_sum_page(sbi, old_segno);
                if (IS_ERR(sum_page)) {
                    ret = PTR_ERR(sum_page);
                    sum_page = NULL;
                    goto out;
                }
                sum_blk = (struct f2fs_summary_block *)page_address(sum_page);
                sum_blk->entries[blk_off] = sum;
                set_page_dirty(sum_page);
                /* 新增: 标记该 summary page 为脏，确保后续读取从 SSA */
                mark_sum_page_dirty(sbi, old_segno);

                ret = snapfs_stage_sit_page_change(sbi, old_blkaddr, true, &sit_page);
                if (ret) {
                    snapfs_put_meta_page_auto(sum_page);
                    sum_page = NULL;
                    goto out;
                }

                ret = snapfs_redo_begin(sbi, &txn);
                if (ret) {
                    snapfs_put_meta_page_auto(sit_page);
                    snapfs_put_meta_page_auto(sum_page);
                    goto out;
                }
                {
                    struct page *txn_pages[] = { mulref_page, sum_page, sit_page };
                    snapfs_mark_txn_pages_dirty(txn_pages, ARRAY_SIZE(txn_pages));
                    snapfs_require_redo_for_pages(&txn, txn_pages, ARRAY_SIZE(txn_pages));
                }
                txn.op_type = cpu_to_le32(SNAP_REDO_NORMAL_TO_MR);
                txn.data_blkaddr = cpu_to_le32(old_blkaddr);
                snapfs_txn_attach_pending_progress(&txn, progress, progress_bit);
                ret = snapfs_redo_stage_mulref_op(&txn, blkaddr1, eidx1, true, mgentry);
                if (!ret)
                    ret = snapfs_redo_stage_mulref_op(&txn, blkaddr1, eidx2, true, mgentry2);
                if (!ret)
                    ret = snapfs_redo_stage_summary_final(&txn, old_blkaddr, &sum);
                if (!ret)
                    ret = snapfs_redo_stage_sit_final(&txn, old_blkaddr, true);
                if (!ret)
                    ret = snapfs_redo_commit(&txn);
                if (!ret)
                    ret = snapfs_flush_locked_meta_page(sbi, mulref_page);
                if (!ret)
                    ret = snapfs_flush_locked_meta_page(sbi, sum_page);
                if (!ret)
                    ret = snapfs_flush_locked_meta_page(sbi, sit_page);
                if (!ret)
                    ret = snapfs_progress_commit_after_block(&txn, progress,
                            progress_bit);
                snapfs_redo_end(&txn);
                if (sit_page) {
                    snapfs_put_meta_page_auto(sit_page);
                    sit_page = NULL;
                }
                if (sum_page) {
                    snapfs_put_meta_page_auto(sum_page);
                    sum_page = NULL;
                }
                if (ret)
                    goto out;
            }

            if(mulref_page){
                snapfs_put_meta_page_auto(mulref_page);
                mulref_page = NULL;
            }
        } else { // 跨块处理的情况
            // pr_info("[snapfs alloc]: tp42 !is_mulref\n");
            // 注意：这里不需要重复加锁，因为外层 if(!is_mulref) 已经加过锁了
            // page 1
            mulref_page = f2fs_get_meta_page(sbi, blkaddr1);
            if (IS_ERR(mulref_page)) {
                pr_err("get mulref page failed\n");
                ret = 1;
                goto out;
            }
            // page 2
            mulref_page2 = f2fs_get_meta_page(sbi, blkaddr2);
            if (IS_ERR(mulref_page2)) {
                snapfs_put_meta_page_auto(mulref_page);
                mulref_page = NULL;
                pr_err("get mulref page2 failed\n");
                ret = 1;
                goto out;
            }

            blk = (struct f2fs_mulref_block *)page_address(mulref_page);
            if (!blk) {
                pr_err("mulref blk is NULL\n");
                snapfs_put_meta_page_auto(mulref_page);
                mulref_page = NULL;
                snapfs_put_meta_page_auto(mulref_page2);
                mulref_page2 = NULL;
                ret = 1;
                goto out;
            }
            blk2 = (struct f2fs_mulref_block *)page_address(mulref_page2);
            if (!blk2) {
                pr_err("mulref blk2 is NULL\n");
                snapfs_put_meta_page_auto(mulref_page);
                mulref_page = NULL;
                snapfs_put_meta_page_auto(mulref_page2);
                mulref_page2 = NULL;
                ret = 1;
                goto out;
            }

            mgentry = &blk->mrentries[eidx1];
            mgentry->m_nid = old_sum.nid;
            mgentry->m_ofs = old_sum.ofs_in_node;
            mgentry->m_ver = old_sum.version;
            mgentry->m_count += 2;
            mgentry->next = cpu_to_le32((blkaddr2 - start_addr) * MRENTRY_PER_BLOCK + eidx2);
            sum.nid = cpu_to_le32(blkaddr1);
            sum.ofs_in_node = cpu_to_le16(eidx1);
            sum.version = old_sum.version;	
            // pr_info("[snapfs cow2222]: debug alloc (diff blk) cmr->blkaddr [%u]\n",cmr->blkaddr);
        
            // pr_info("[snapfs cow2222]: debug alloc (diff blk) old nid[%u],ofs[%u],ver[%u]\n",old_sum.nid
                // ,old_sum.ofs_in_node, old_sum.version);
            // pr_info("[snapfs cow2222]: debug alloc (diff blk) new nid[%u],ofs[%u],ver[%u]\n",blkaddr1,eidx1,old_sum.version);
            // pr_info("next: [%u]\n",(blkaddr2 - start_addr) * MRENTRY_PER_BLOCK + eidx2);
            mgentry2 = &blk2->mrentries[eidx2];
            mgentry2->m_nid = ino;
            mgentry2->m_ofs = cpu_to_le16(old_sum.ofs_in_node);
            mgentry2->m_ver = old_sum.version;
            mgentry2->m_count = mgentry->m_count;
            mgentry2->next = 0;

            {
                struct snapfs_txn txn;
                struct page *sum_page = NULL;
                struct page *sit_page = NULL;
                struct f2fs_summary_block *sum_blk;

                sum_page = f2fs_get_sum_page(sbi, old_segno);
                if (IS_ERR(sum_page)) {
                    ret = PTR_ERR(sum_page);
                    sum_page = NULL;
                    goto out;
                }
                sum_blk = (struct f2fs_summary_block *)page_address(sum_page);
                sum_blk->entries[blk_off] = sum;
                set_page_dirty(sum_page);
                /* 新增: 标记该 summary page 为脏，确保后续读取从 SSA */
                mark_sum_page_dirty(sbi, old_segno);

                ret = snapfs_stage_sit_page_change(sbi, old_blkaddr, true, &sit_page);
                if (ret) {
                    snapfs_put_meta_page_auto(sum_page);
                    sum_page = NULL;
                    goto out;
                }

                ret = snapfs_redo_begin(sbi, &txn);
                if (ret) {
                    snapfs_put_meta_page_auto(sit_page);
                    snapfs_put_meta_page_auto(sum_page);
                    goto out;
                }
                {
                    struct page *txn_pages[] = { mulref_page, mulref_page2, sum_page, sit_page };
                    snapfs_mark_txn_pages_dirty(txn_pages, ARRAY_SIZE(txn_pages));
                    snapfs_require_redo_for_pages(&txn, txn_pages, ARRAY_SIZE(txn_pages));
                }
                txn.op_type = cpu_to_le32(SNAP_REDO_NORMAL_TO_MR);
                txn.data_blkaddr = cpu_to_le32(old_blkaddr);
                snapfs_txn_attach_pending_progress(&txn, progress, progress_bit);
                ret = snapfs_redo_stage_mulref_op(&txn, blkaddr1, eidx1, true, mgentry);
                if (!ret)
                    ret = snapfs_redo_stage_mulref_op(&txn, blkaddr2, eidx2, true, mgentry2);
                if (!ret)
                    ret = snapfs_redo_stage_summary_final(&txn, old_blkaddr, &sum);
                if (!ret)
                    ret = snapfs_redo_stage_sit_final(&txn, old_blkaddr, true);
                if (!ret)
                    ret = snapfs_redo_commit(&txn);
                if (!ret)
                    ret = snapfs_flush_locked_meta_page(sbi, mulref_page);
                if (!ret)
                    ret = snapfs_flush_locked_meta_page(sbi, mulref_page2);
                if (!ret)
                    ret = snapfs_flush_locked_meta_page(sbi, sum_page);
                if (!ret)
                    ret = snapfs_flush_locked_meta_page(sbi, sit_page);
                if (!ret)
                    ret = snapfs_progress_commit_after_block(&txn, progress,
                            progress_bit);
                snapfs_redo_end(&txn);
                if (sit_page) {
                    snapfs_put_meta_page_auto(sit_page);
                    sit_page = NULL;
                }
                if (sum_page) {
                    snapfs_put_meta_page_auto(sum_page);
                    sum_page = NULL;
                }
                if (ret)
                    goto out;
            }

            if(mulref_page){
                snapfs_put_meta_page_auto(mulref_page);
                mulref_page = NULL;
            }

            if(mulref_page2){
                snapfs_put_meta_page_auto(mulref_page2);
                mulref_page2 = NULL;
            }
        }
        
    }else{ // 已经是多引用块，也就是多版本快照的处理
        // 分配一个就行，就是 eidx1和blkaddr1
        // 注意：已在 2446-2448 获取 curmulref_lock，这里不能重复获取
        // pr_info("[snapfs alloc]: tp5 is_mulref\n");
        mulref_page = f2fs_get_meta_page(sbi, blkaddr1);
        if (IS_ERR(mulref_page)) {
            pr_err("get mulref page failed\n");
            mulref_page = NULL;
            ret = 1;
            goto out;
        }
        blk = (struct f2fs_mulref_block *)page_address(mulref_page);
        if (!blk) {
            pr_err("mulref blk is NULL\n");
            ret = 1;
            goto out;
        }
        mgentry = &blk->mrentries[eidx1];


        blkaddr2 = le32_to_cpu(old_sum.nid);// head 地址
        eidx2 = le16_to_cpu(old_sum.ofs_in_node);
        if (blkaddr2 == blkaddr1) { //head地址和新分配的地址一致,同数据块
            blk2 = blk;
        } else { // 跨块处理的情况
            mulref_page2 = f2fs_get_meta_page(sbi, blkaddr2);// head
            if (IS_ERR(mulref_page2)) { 
                pr_err("get mulref page3 failed\n"); 
                // mulref_page3 = NULL;
                ret = 1;
                goto out;
                // 需要释放资源并退出 
            }
            blk2 = (struct f2fs_mulref_block *)page_address(mulref_page2);
        }
        
        mgentry2 = &blk2->mrentries[eidx2];// head
        mgentry->m_nid = ino;
        mgentry->m_ofs = mgentry2->m_ofs;
        mgentry->m_ver = mgentry2->m_ver;
        mgentry->m_count = mgentry2->m_count;
        mgentry->next = 0;

        // 更新前节点的next
        tmp_next = le32_to_cpu(mgentry2->next);
        while(1){
            // next计算规则, 计算是第几个entry
            blkaddr3 = tmp_next / MRENTRY_PER_BLOCK + start_addr; 
            eidx3 = tmp_next % MRENTRY_PER_BLOCK;
            //head?
            if (blkaddr3 == blkaddr2) { // head地址和新分配的地址一致
                blk3 = blk2;
            }else if (blkaddr3 == blkaddr_tmp){ // 和上一个tmp blk一致
                // mulref_page3 保持不变
            } else { // 跨块处理的情况,   不等于head， 也不等与上一个，上一个不是head
                // 新的blkaddr
                if(mulref_page3){
                    snapfs_put_meta_page_auto(mulref_page3);
                    mulref_page3 = NULL;
                }
                mulref_page3 = f2fs_get_meta_page(sbi, blkaddr3);//head next
                if (IS_ERR(mulref_page3)) {
                    pr_err("get mulref page3 failed\n");
                    mulref_page3 = NULL;
                    ret = 1;
                    goto out;
                }
                blk3 = (struct f2fs_mulref_block *)page_address(mulref_page3);
            }
            if(!blk3){
                pr_err("[snapfs cow2222]: debug alloc (is_mulref) blk3 failed\n");
                ret = 1;
                goto out;
            }
            mgentry3 = &blk3->mrentries[eidx3];
            tmp_next = le32_to_cpu(mgentry3->next);
            if(tmp_next == 0){
                // 分配一个就行，就是eidx1和blkaddr1, 在尾部加1
                mgentry3->next = cpu_to_le32((blkaddr1 - start_addr) * MRENTRY_PER_BLOCK + eidx1);
                mgentry2->m_count += 1;
                mgentry->m_count = mgentry2->m_count;
                break;
            }
            blkaddr_tmp = blkaddr3;
        }
        
        {
            struct page *sum_page = NULL;
            struct page *sit_page = NULL;
            struct f2fs_summary_block *sum_blk;

            sum_page = f2fs_get_sum_page(sbi, old_segno);
            if (IS_ERR(sum_page)) {
                ret = PTR_ERR(sum_page);
                sum_page = NULL;
                goto out;
            }
            sum_blk = (struct f2fs_summary_block *)page_address(sum_page);
            sum_blk->entries[blk_off] = sum;
            set_page_dirty(sum_page);
            /* 新增: 标记该 summary page 为脏，确保后续读取从 SSA */
            mark_sum_page_dirty(sbi, old_segno);

            ret = snapfs_stage_sit_page_change(sbi, old_blkaddr, true, &sit_page);
            if (ret) {
                snapfs_put_meta_page_auto(sum_page);
                sum_page = NULL;
                goto out;
            }

            {
                struct snapfs_txn txn;

                ret = snapfs_redo_begin(sbi, &txn);
                if (ret) {
                    snapfs_put_meta_page_auto(sit_page);
                    snapfs_put_meta_page_auto(sum_page);
                    goto out;
                }
                {
                    struct page *txn_pages[] = {
                        mulref_page, mulref_page2, mulref_page3,
                        sum_page, sit_page,
                    };
                    snapfs_mark_txn_pages_dirty(txn_pages, ARRAY_SIZE(txn_pages));
                    snapfs_require_redo_for_pages(&txn, txn_pages, ARRAY_SIZE(txn_pages));
                }
                snapfs_txn_attach_pending_progress(&txn, progress, progress_bit);
                txn.op_type = cpu_to_le32(SNAP_REDO_APPEND_REF);
                txn.data_blkaddr = cpu_to_le32(old_blkaddr);
                ret = snapfs_redo_stage_mulref_op(&txn, blkaddr1, eidx1, true, mgentry);
                if (!ret)
                    ret = snapfs_redo_stage_mulref_op(&txn, blkaddr2, eidx2, true, mgentry2);
                if (!ret)
                    ret = snapfs_redo_stage_mulref_op(&txn, blkaddr3, eidx3, true, mgentry3);
                if (!ret)
                    ret = snapfs_redo_stage_summary_final(&txn, old_blkaddr, &sum);
                if (!ret)
                    ret = snapfs_redo_stage_sit_final(&txn, old_blkaddr, true);
                if (!ret)
                    ret = snapfs_redo_commit(&txn);
                if (!ret)
                    ret = snapfs_flush_locked_meta_page(sbi, mulref_page);
                if (!ret && blkaddr2 != blkaddr1)
                    ret = snapfs_flush_locked_meta_page(sbi, mulref_page2);
                if (!ret && blkaddr3 != blkaddr2 && blkaddr3 != blkaddr1)
                    ret = snapfs_flush_locked_meta_page(sbi, mulref_page3);
                if (!ret)
                    ret = snapfs_flush_locked_meta_page(sbi, sum_page);
                if (!ret)
                    ret = snapfs_flush_locked_meta_page(sbi, sit_page);
                if (!ret)
                    ret = snapfs_progress_commit_after_block(&txn, progress,
                            progress_bit);
                snapfs_redo_end(&txn);
                if (sit_page) {
                    snapfs_put_meta_page_auto(sit_page);
                    sit_page = NULL;
                }
                if (sum_page) {
                    snapfs_put_meta_page_auto(sum_page);
                    sum_page = NULL;
                }
                if (ret)
                    goto out;
            }

            if(mulref_page){
                snapfs_put_meta_page_auto(mulref_page);
                mulref_page = NULL;
            }

            if(mulref_page2){
                snapfs_put_meta_page_auto(mulref_page2);
                mulref_page2 = NULL;
            }

            if(mulref_page3){
                snapfs_put_meta_page_auto(mulref_page3);
                mulref_page3 = NULL;
            }
        }
    }
    // pr_info("[snapfs alloc]: over\n");
out:
    /* curmulref_alloc_entry 现在内部使用两阶段锁，不需要外部释放锁 */
    if (mulref_page3) {
        snapfs_put_meta_page_auto(mulref_page3);
        mulref_page3 = NULL;
    }
    if (mulref_page2) {
        snapfs_put_meta_page_auto(mulref_page2);
        mulref_page2 = NULL;
    }
    if (mulref_page) {
        snapfs_put_meta_page_auto(mulref_page);
        mulref_page = NULL;
    }
	return ret;
}

// 什么时候触发 need_scan（非常重要）
// 1. inode 删除
// atomic_set(&mgr->need_scan, 1);
// wake_up(&mgr->wq);
// 2. truncate / unlink 多引用对象
// 3. alloc 失败时（没有 free entry）
int snapfs_is_extension_exist(const unsigned char *s, const char *sub,
						bool tmp_ext)
{
	size_t slen = strlen(s);
	size_t sublen = strlen(sub);
	int i;

	if (sublen == 1 && *sub == '*')
		return 1;

	/*
	 * filename format of multimedia file should be defined as:
	 * "filename + '.' + extension + (optional: '.' + temp extension)".
	 */
	if (slen < sublen + 2)
		return 0;

	if (!tmp_ext) {
		/* file has no temp extension */
		if (s[slen - sublen - 1] != '.')
			return 0;
		return !strncasecmp(s + slen - sublen, sub, sublen);
	}

	for (i = 1; i < slen - sublen; i++) {
		if (s[i] != '.')
			continue;
		if (!strncasecmp(s + i + 1, sub, sublen))
			return 1;
	}

	return 0;
}

void snapfs_set_compress_inode(struct f2fs_sb_info *sbi, struct inode *inode,
						const unsigned char *name)
{
	__u8 (*extlist)[F2FS_EXTENSION_LEN] = sbi->raw_super->extension_list;
	unsigned char (*noext)[F2FS_EXTENSION_LEN] = F2FS_OPTION(sbi).noextensions;
	unsigned char (*ext)[F2FS_EXTENSION_LEN] = F2FS_OPTION(sbi).extensions;
	unsigned char ext_cnt = F2FS_OPTION(sbi).compress_ext_cnt;
	unsigned char noext_cnt = F2FS_OPTION(sbi).nocompress_ext_cnt;
	int i, cold_count, hot_count;

	if (!f2fs_sb_has_compression(sbi) ||
			F2FS_I(inode)->i_flags & F2FS_NOCOMP_FL ||
			!f2fs_may_compress(inode) ||
			(!ext_cnt && !noext_cnt))
		return;

	down_read(&sbi->sb_lock);

	cold_count = le32_to_cpu(sbi->raw_super->extension_count);
	hot_count = sbi->raw_super->hot_ext_count;

	for (i = cold_count; i < cold_count + hot_count; i++) {
		if (snapfs_is_extension_exist(name, extlist[i], false)) {
			up_read(&sbi->sb_lock);
			return;
		}
	}

	up_read(&sbi->sb_lock);

	for (i = 0; i < noext_cnt; i++) {
		if (snapfs_is_extension_exist(name, noext[i], false)) {
			f2fs_disable_compressed_file(inode);
			return;
		}
	}

	if (is_inode_flag_set(inode, FI_COMPRESSED_FILE))
		return;

	for (i = 0; i < ext_cnt; i++) {
		if (!snapfs_is_extension_exist(name, ext[i], false))
			continue;

		/* Do not use inline_data with compression */
		stat_dec_inline_inode(inode);
		clear_inode_flag(inode, FI_INLINE_DATA);
		set_compress_context(inode);
		return;
	}
}

void snapfs_set_file_temperature(struct f2fs_sb_info *sbi, struct inode *inode,
		const unsigned char *name)
{
	__u8 (*extlist)[F2FS_EXTENSION_LEN] = sbi->raw_super->extension_list;
	int i, cold_count, hot_count;

	down_read(&sbi->sb_lock);

	cold_count = le32_to_cpu(sbi->raw_super->extension_count);
	hot_count = sbi->raw_super->hot_ext_count;

	for (i = 0; i < cold_count + hot_count; i++) {
		if (snapfs_is_extension_exist(name, extlist[i], true))
			break;
	}

	up_read(&sbi->sb_lock);

	if (i == cold_count + hot_count)
		return;

	if (i < cold_count)
		file_set_cold(inode);
	else
		file_set_hot(inode);
}

// 在你的 snapshot.c 中添加这个函数
struct inode *snapfs_new_inode(struct inode *dir, umode_t mode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(dir);
	nid_t ino;
	struct inode *inode;
	bool nid_free = false;
	bool encrypt = false;
	int xattr_size = 0;
	int err;

	inode = new_inode(dir->i_sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	f2fs_lock_op(sbi);
	if (!f2fs_alloc_nid(sbi, &ino)) {
		f2fs_unlock_op(sbi);
		err = -ENOSPC;
		goto fail;
	}
	f2fs_unlock_op(sbi);

	nid_free = true;

	inode_init_owner(&init_user_ns, inode, dir, mode);

	inode->i_ino = ino;
	inode->i_blocks = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	F2FS_I(inode)->i_crtime = inode->i_mtime;
	inode->i_generation = prandom_u32();

	if (S_ISDIR(inode->i_mode))
		F2FS_I(inode)->i_current_depth = 1;

	err = insert_inode_locked(inode);
	if (err) {
		err = -EINVAL;
		goto fail;
	}

	if (f2fs_sb_has_project_quota(sbi) &&
		(F2FS_I(dir)->i_flags & F2FS_PROJINHERIT_FL))
		F2FS_I(inode)->i_projid = F2FS_I(dir)->i_projid;
	else
		F2FS_I(inode)->i_projid = make_kprojid(&init_user_ns,
							F2FS_DEF_PROJID);

	err = fscrypt_prepare_new_inode(dir, inode, &encrypt);
	if (err)
		goto fail_drop;

	err = f2fs_dquot_initialize(inode);
	if (err)
		goto fail_drop;

	set_inode_flag(inode, FI_NEW_INODE);

	if (encrypt)
		f2fs_set_encrypted_inode(inode);

	if (f2fs_sb_has_extra_attr(sbi)) {
		set_inode_flag(inode, FI_EXTRA_ATTR);
		F2FS_I(inode)->i_extra_isize = F2FS_TOTAL_EXTRA_ATTR_SIZE;
	}

	if (test_opt(sbi, INLINE_XATTR))
		set_inode_flag(inode, FI_INLINE_XATTR);

	if (f2fs_may_inline_dentry(inode))
		set_inode_flag(inode, FI_INLINE_DENTRY);

	if (f2fs_sb_has_flexible_inline_xattr(sbi)) {
		f2fs_bug_on(sbi, !f2fs_has_extra_attr(inode));
		if (f2fs_has_inline_xattr(inode))
			xattr_size = F2FS_OPTION(sbi).inline_xattr_size;
		/* Otherwise, will be 0 */
	} else if (f2fs_has_inline_xattr(inode) ||
				f2fs_has_inline_dentry(inode)) {
		xattr_size = DEFAULT_INLINE_XATTR_ADDRS;
	}
	F2FS_I(inode)->i_inline_xattr_size = xattr_size;

	f2fs_init_extent_tree(inode, NULL);

	F2FS_I(inode)->i_flags =
		f2fs_mask_flags(mode, F2FS_I(dir)->i_flags & F2FS_FL_INHERITED);

	if (S_ISDIR(inode->i_mode))
		F2FS_I(inode)->i_flags |= F2FS_INDEX_FL;

	if (F2FS_I(inode)->i_flags & F2FS_PROJINHERIT_FL)
		set_inode_flag(inode, FI_PROJ_INHERIT);

	if (f2fs_sb_has_compression(sbi)) {
		/* Inherit the compression flag in directory */
		if ((F2FS_I(dir)->i_flags & F2FS_COMPR_FL) &&
					f2fs_may_compress(inode))
			set_compress_context(inode);
	}

	/* Should enable inline_data after compression set */
	if (test_opt(sbi, INLINE_DATA) && f2fs_may_inline_data(inode))
		set_inode_flag(inode, FI_INLINE_DATA);

	stat_inc_inline_xattr(inode);
	stat_inc_inline_inode(inode);
	stat_inc_inline_dir(inode);

	f2fs_set_inode_flags(inode);
	return inode;

fail:
	make_bad_inode(inode);
	if (nid_free)
		set_inode_flag(inode, FI_FREE_NID);
	iput(inode);
	return ERR_PTR(err);
fail_drop:
	dquot_drop(inode);
	inode->i_flags |= S_NOQUOTA;
	if (nid_free)
		set_inode_flag(inode, FI_FREE_NID);
	clear_nlink(inode);
	unlock_new_inode(inode);
	iput(inode);
	return ERR_PTR(err);
}


static inline u32 magic_hash1(u32 ino)
{
    ino ^= ino >> 16;
    ino *= 0x7feb352d;
    ino ^= ino >> 15;
    ino *= 0x846ca68b;
    ino ^= ino >> 16;
    return ino;
}

static inline u32 magic_hash2(u32 ino)
{
    /* 必须为奇数，保证遍历整个表 */
    return (ino * 0x9e3779b1) | 1;
}



int f2fs_magic_lookup_or_alloc(struct f2fs_sb_info *sbi,
        u32 src_ino, u32 snap_ino, u32 *ret_entry_id)
{
    u32 h1 = magic_hash1(src_ino) % MAGIC_ENTRY_NR;
    u32 h2 = magic_hash2(src_ino) % MAGIC_ENTRY_NR;
    u32 i, j;
    block_t blkaddr;
    block_t blkaddr2, blkaddr3;
    u32 off, off2, off3;
    struct page *page = NULL;
    struct page *page2 = NULL;
    struct page *page3 = NULL;
    struct f2fs_magic_block *mb;
    struct f2fs_magic_entry *me;
    struct f2fs_magic_entry *me2;
    struct f2fs_magic_entry *me3;
    u32 tmp_next, tmp_off;
    struct f2fs_magic_entry *tmp_me;
    struct page *tmp_page = NULL;
    block_t tmp_blkaddr;
    struct f2fs_magic_block *tmp_mb;
    struct f2fs_magic_block *mb2;
    struct f2fs_magic_block *mb3;
    struct inode *snap_inode;
    int ret = 0;
    u32 entry_id = 0;
    if (!sbi->magic_info) {
        pr_err("magic_info is NULL!\n");
        return -ENOENT;
    }
    snap_inode = f2fs_iget(sbi->sb, snap_ino);
    // 加锁保护整个查找/分配过程
    // mutex_lock(&sbi->magic_info->mutex);
    down_write(&sbi->magic_info->rwsem);
    for (i = 0; i < MAGIC_ENTRY_NR; i++) {
        entry_id = (h1 + i * h2) % MAGIC_ENTRY_NR;
        blkaddr = sbi->magic_info->magic_blkaddr + magic_entry_to_blkaddr(entry_id);
        off     = magic_entry_to_offset(entry_id);
        page = f2fs_get_meta_page(sbi, blkaddr);
        if (IS_ERR(page)){
            pr_info("  f2fs_get_meta_page failed: %ld\n", PTR_ERR(page));
            // mutex_unlock(&sbi->magic_info->mutex);
            up_write(&sbi->magic_info->rwsem);
            return PTR_ERR(page);
        }
        mb = (struct f2fs_magic_block *)page_address(page);
        me = &mb->mgentries[off];
        /* bitmap 判断 */
        if (!test_bit(off,(unsigned long *)(mb->multi_bitmap))) {
            /* 空槽：可以直接使用 */
            pr_info("[snapfs set_flag]: write magic page addr/off[%u,%u]\n"
                    ,blkaddr, off);
            set_bit(off, (unsigned long *)(mb->multi_bitmap));
            me->src_ino = cpu_to_le32(src_ino);
            me->snap_ino = cpu_to_le32(snap_ino);
            me->count += 1;
            me->next = 0;
            me->c_time = current_time(snap_inode);
            if (ret_entry_id)
                *ret_entry_id = entry_id;
            goto out;
        }
        
        if (le32_to_cpu(me->src_ino) == src_ino) {
            /* 命中已有映射 */
            pr_info("update magic with addr/off[%u,%u],me->count[%u]\n"
                    ,blkaddr, off, me->count);
            blkaddr2 = blkaddr;
            if(me->count == 1){
                for(j = 1; j < MAGIC_ENTRY_NR; j++){
                    mb2 = mb;
                    if(off >= MGENTRY_PER_BLOCK - 1){
                        blkaddr2 += 1;
                        page2 = f2fs_get_meta_page(sbi, blkaddr2);
                        if (IS_ERR(page2)){
                            pr_info("2snap f2fs_get_meta_page failed: %ld\n", PTR_ERR(page2));
                            f2fs_put_page(page, 1);
                            // mutex_unlock(&sbi->magic_info->mutex);
                            up_write(&sbi->magic_info->rwsem);
                            return PTR_ERR(page2);
                        }
                        mb2 = (struct f2fs_magic_block *)page_address(page2);
                    }
                    off2 = (off + j) % MGENTRY_PER_BLOCK;
                    me2 = &mb2->mgentries[off2];
                    if (le32_to_cpu(me2->src_ino)) {
                        f2fs_put_page(page2, 1);
                        continue;
                    }
                    break;    
                }
                set_bit(off2, (unsigned long *)(mb->multi_bitmap));
                me->count += 1;
                me->next = cpu_to_le32(off2 + (blkaddr2 - sbi->magic_info->magic_blkaddr) * MGENTRY_PER_BLOCK);
                // pr_info("me->next[%u] = (le32 to cpu) off2[%u] * blkaddr2[%u] * 139\n",
                //         me->next, off2, blkaddr2);
                me2 = &mb2->mgentries[off2];
                me2->src_ino = cpu_to_le32(src_ino);
                me2->snap_ino = cpu_to_le32(snap_ino);
                me2->count = me->count;
                me2->next = 0;
                me2->c_time = current_time(snap_inode);
                if (ret_entry_id)
                    *ret_entry_id = off2 + (blkaddr2 - sbi->magic_info->magic_blkaddr) * MGENTRY_PER_BLOCK;
                pr_info("[snapfs set_flag]: write magic page addr2/off2[%u,%u]\n"
                    ,blkaddr2, off2);
                // pr_info("2snap addr[%u], off2[%u], next[%u]\n", blkaddr2, off2, me2->next);
            }else if(me->count > 1){
                me->count += 1;
                tmp_next = le32_to_cpu(me->next);
                while(tmp_next){
                    tmp_blkaddr = sbi->magic_info->magic_blkaddr + magic_entry_to_blkaddr(tmp_next);
                    tmp_off     = magic_entry_to_offset(tmp_next);
                    // pr_info("tmp_next[%u], tmp_blkaddr[%u]\n", tmp_next, tmp_blkaddr);
                    if(tmp_blkaddr == blkaddr){
                        // pr_info("2+ same tmp_off[%u]\n", tmp_off);
                        tmp_me = &mb->mgentries[tmp_off];
                        if(!tmp_me->next){
                            //wanmei 找到tail了
                            // pr_info("2+snap tail\n");
                            blkaddr3 = tmp_blkaddr;
                            for(j = 1; j < MAGIC_ENTRY_NR; j++){
                                mb3 = mb;
                                if(tmp_off >= MGENTRY_PER_BLOCK - 1){
                                    blkaddr3 += 1;
                                    page3 = f2fs_get_meta_page(sbi, blkaddr3);
                                    if (IS_ERR(page3)){
                                        pr_info("f2fs_get_meta_page failed 1: %ld\n", PTR_ERR(page3));
                                        f2fs_put_page(page, 1);
                                        up_write(&sbi->magic_info->rwsem);
                                        // mutex_unlock(&sbi->magic_info->mutex);
                                        return PTR_ERR(page3);
                                    }
                                    mb3 = (struct f2fs_magic_block *)page_address(page3);
                                }
                                off3 = (tmp_off + j) % MGENTRY_PER_BLOCK;
                                me3 = &mb3->mgentries[off3];
                                if (le32_to_cpu(me3->src_ino)) {
                                    f2fs_put_page(page3, 1);
                                    continue;
                                }
                                break;    
                            }
                            set_bit(off3, (unsigned long *)(mb->multi_bitmap));
                            tmp_me->count = me->count;
                            tmp_me->next = cpu_to_le32(off3 + (blkaddr3 - sbi->magic_info->magic_blkaddr) * MGENTRY_PER_BLOCK);
                            me3->src_ino = cpu_to_le32(src_ino);
                            me3->snap_ino = cpu_to_le32(snap_ino);
                            me3->count = me->count;
                            me3->next = 0;
                            me3->c_time = current_time(snap_inode);
                            if (ret_entry_id)
                                *ret_entry_id = off3 + (blkaddr3 - sbi->magic_info->magic_blkaddr) * MGENTRY_PER_BLOCK;
                            // pr_info("2+ snap addr[%u], off3[%u], next3[%u]\n", blkaddr3, off3, me3->next);
                            break; 
                        }else{
                            tmp_next = tmp_me->next;
                        }
                    }else{// 跨块处理
                        tmp_page = f2fs_get_meta_page(sbi, tmp_blkaddr);
                        if (IS_ERR(tmp_page)){
                            pr_info("f2fs_get_meta_page failed 2: %ld\n", PTR_ERR(tmp_page));
                            f2fs_put_page(page, 1);
                            // mutex_unlock(&sbi->magic_info->mutex);
                            up_write(&sbi->magic_info->rwsem);
                            return PTR_ERR(tmp_page);
                        }
                        tmp_mb = (struct f2fs_magic_block *)page_address(tmp_page);
                        tmp_me = &tmp_mb->mgentries[tmp_off];
                        tmp_me->count = me->count;
                        if(!tmp_me->next){
                            //wanmei. 找到tail了
                            blkaddr3 = tmp_blkaddr;
                            tmp_me = &tmp_mb->mgentries[tmp_off];
                            for(j = 1; j < MAGIC_ENTRY_NR; j++){
                                mb3 = tmp_mb;
                                if(off >= MGENTRY_PER_BLOCK - 1){
                                    blkaddr3 += 1;
                                    page3 = f2fs_get_meta_page(sbi, blkaddr3);
                                    if (IS_ERR(page3)){
                                        pr_info("f2fs_get_meta_page failed 3: %ld\n", PTR_ERR(page3));
                                        f2fs_put_page(page, 1);
                                        f2fs_put_page(tmp_page, 1);
                                        // mutex_unlock(&sbi->magic_info->mutex);
                                        up_write(&sbi->magic_info->rwsem);
                                        return PTR_ERR(page3);
                                    }
                                    mb3 = (struct f2fs_magic_block *)page_address(page3);
                                }
                                off3 = (tmp_off + j) % MGENTRY_PER_BLOCK;
                                me3 = &mb3->mgentries[off3];
                                if (le32_to_cpu(me3->src_ino)) {
                                    f2fs_put_page(page3, 1);
                                    continue;
                                }
                                break;    
                            }
                            set_bit(off3, (unsigned long *)(mb->multi_bitmap));
                            tmp_me->next = cpu_to_le32(off3 + (blkaddr3 - sbi->magic_info->magic_blkaddr) * MGENTRY_PER_BLOCK);
                            off2 = (off + 1) % MGENTRY_PER_BLOCK;
                            me3->src_ino = cpu_to_le32(src_ino);
                            me3->snap_ino = cpu_to_le32(snap_ino);
                            me3->count = me->count;
                            me3->next = 0;
                            me3->c_time = current_time(snap_inode);
                            if (ret_entry_id)
                                *ret_entry_id = off3 + (blkaddr3 - sbi->magic_info->magic_blkaddr) * MGENTRY_PER_BLOCK;
                            break; 
                        }else{
                            tmp_next = tmp_me->next;
                            f2fs_put_page(tmp_page, 1);
                        }
                    }
                }
                pr_info("[snapfs set_flag]: write magic page addr3/off3[%u,%u]\n"
                    ,blkaddr3, off3);
            }
            if(page2){
                set_page_dirty(page2);
                f2fs_put_page(page2, 1);
            }
            goto out;
        }
        /* 冲突：继续 probing */
        f2fs_put_page(page, 1);
    }
    ret = -ENOSPC;  /* 所有 slot 都被占满 */
out:
    iput(snap_inode);
    set_page_dirty(page);
    f2fs_put_page(page, 1);
    up_write(&sbi->magic_info->rwsem);
    // mutex_unlock(&sbi->magic_info->mutex);
    return ret;  /* 所有 slot 都被占满 */
}

int f2fs_magic_lookup(struct f2fs_sb_info *sbi, u32 src_ino,
        u32 *ret_entry_id, struct f2fs_magic_entry *ret_entry)
{
    u32 h1 = magic_hash1(src_ino) % MAGIC_ENTRY_NR;
    u32 h2 = magic_hash2(src_ino) % MAGIC_ENTRY_NR;
    u32 i;
    block_t blkaddr;
    u32 off;
    struct page *page;
    struct f2fs_magic_block *mb;
    struct f2fs_magic_entry *me;
    u32 entry_id = 0;
    // u32 ret_entry_id;
    // struct f2fs_magic_entry *ret_entry;
    if (!sbi->magic_info) {
        pr_err("magic_info is NULL!\n");
        return -ENOENT;
    }
    // 加锁保护整个查找/分配过程
    // mutex_lock(&sbi->magic_info->mutex);
    down_read(&sbi->magic_info->rwsem);
    for (i = 0; i < MAGIC_ENTRY_NR; i++) {
        entry_id = (h1 + i * h2) % MAGIC_ENTRY_NR;
        blkaddr = sbi->magic_info->magic_blkaddr + magic_entry_to_blkaddr(entry_id);
        off     = magic_entry_to_offset(entry_id);

        // pr_info("f2fs_magic_lookup Test point 2  magic_blk[%u, %u]\n",
                // sbi->magic_info->magic_blkaddr + (entry_id / MGENTRY_PER_BLOCK),blkaddr);
        
        page = f2fs_get_meta_page(sbi, blkaddr);
        if (IS_ERR(page)){
            pr_info("  f2fs_get_meta_page failed: %ld\n", PTR_ERR(page));
            // mutex_unlock(&sbi->magic_info->mutex);
            up_read(&sbi->magic_info->rwsem);
            return PTR_ERR(page);
        }
        mb = (struct f2fs_magic_block *)page_address(page);
        /* bitmap 判断 */
        if (test_bit(off,(unsigned long *)(mb->multi_bitmap))) {
            me = &mb->mgentries[off];
            // pr_info("lookup me snap[%u] next[%u]\n",le32_to_cpu(me->snap_ino),le32_to_cpu(me->next));
            if (le32_to_cpu(me->src_ino) == src_ino) {
                /* 命中已有映射 */
                if(SNAPFS_DEBUG) pr_info("[snapfs cow]: debug find mgentry, addr/off[%u,%u] with entry id[%u],src_ino[%u]\n"
                        ,blkaddr, off, entry_id, src_ino);       
                *ret_entry_id = entry_id;
                memcpy(ret_entry, me, sizeof(*me));
                up_read(&sbi->magic_info->rwsem);
                // mutex_unlock(&sbi->magic_info->mutex);
                f2fs_put_page(page, 1);
                return 0;
            }else{
                // 该位置不为空，且不是该src_ino对应信息，
                // 那么需要探测冲突后，下一个可能分配给这个src_ino的entry
                f2fs_put_page(page, 1);
                continue;
            }
        }else{
            // 空slot，那么就是该src_ino没快照
            // pr_info("empty slot\n");
            f2fs_put_page(page, 1);
            break;
        }
    }

    // mutex_unlock(&sbi->magic_info->mutex);
    up_read(&sbi->magic_info->rwsem);
    return -ENOSPC;  /* 所有 slot 都被占满 */
}

// hopscotch
static inline u32 magic_home(u32 ino)
{
    return magic_hash1(ino) % MAGIC_ENTRY_NR;
}

static inline unsigned int hop_distance(unsigned int home,
                                        unsigned int pos,
                                        unsigned int table_size)
{
    if (pos >= home)
        return pos - home;
    return pos + table_size - home;
}

/* Get current hop_range value */
static inline u32 get_hop_range(struct f2fs_sb_info *sbi)
{
    return sbi->magic_info->hop_range;
}

int f2fs_magic_lookup_or_alloc_hopscotch(
        struct f2fs_sb_info *sbi,
        u32 src_ino,
        u32 *ret_entry_id,
        struct f2fs_magic_entry **ret_entry,
        struct page **ret_page)
{
    u32 home = magic_home(src_ino);
    u32 i;
    u32 free;
    struct page *free_page = NULL;
    block_t blk;
    u32 off;
    struct page *page;
    struct f2fs_magic_block *mb;
    struct f2fs_magic_entry *me;
    u32 eid;
    u32 current_hop_range = get_hop_range(sbi);

    /* ---------- 1. 查询阶段：只扫 current_hop_range ---------- */
    for (i = 0; i < current_hop_range; i++) {
        eid = (home + i) % MAGIC_ENTRY_NR;
        blk = sbi->magic_info->magic_blkaddr + magic_entry_to_blkaddr(eid);
        off = magic_entry_to_offset(eid);
        page = f2fs_get_meta_page(sbi, blk);
        if (IS_ERR(page))
            return PTR_ERR(page);

        mb = (struct f2fs_magic_block *)page_address(page);

        if (test_bit(off, (unsigned long *)(mb->multi_bitmap))) {
            me = &mb->mgentries[off];
            if (le32_to_cpu(me->src_ino) == src_ino) {
                *ret_entry_id = eid;
                *ret_entry = me;
                *ret_page = page;
                return 0;
            }
        }

        f2fs_put_page(page, 1);
    }

    /* ---------- 2. 插入阶段：找空槽 ---------- */
    free = home;
    

    for (i = 0; i < MAGIC_ENTRY_NR; i++) {
        eid = (home + i) % MAGIC_ENTRY_NR;
        blk = sbi->magic_info->magic_blkaddr + magic_entry_to_blkaddr(eid);
        off = magic_entry_to_offset(eid);
 

        page = f2fs_get_meta_page(sbi, blk);
        if (IS_ERR(page))
            return PTR_ERR(page);

        mb = (struct f2fs_magic_block *)page_address(page);

        if (!test_bit(off, (unsigned long *)(mb->multi_bitmap))) {
            free = eid;
            free_page = page;
            break;
        }

        f2fs_put_page(page, 1);
    }

    if (!free_page)
        return -ENOSPC;

    /* ---------- 3. 尝试把空槽搬回 home ---------- */
    while (hop_distance(home, free, MAGIC_ENTRY_NR) >= current_hop_range) {
        bool moved = false;
        u32 j;

        for (j = current_hop_range - 1; j > 0; j--) {
            u32 cand = (free + MAGIC_ENTRY_NR - j) % MAGIC_ENTRY_NR;
            block_t blk = sbi->magic_info->magic_blkaddr + magic_entry_to_blkaddr(cand);
            u32 off = magic_entry_to_offset(cand);
            struct page *page;
            struct f2fs_magic_block *mb;
            struct f2fs_magic_entry *me;
            u32 cand_home;

            page = f2fs_get_meta_page(sbi, blk);
            if (IS_ERR(page))
                continue;

            mb = (struct f2fs_magic_block *)page_address(page);

            if (!test_bit(off, (unsigned long *)(mb->multi_bitmap))) {
                f2fs_put_page(page, 1);
                continue;
            }

            me = &mb->mgentries[off];
            cand_home = magic_home(le32_to_cpu(me->src_ino));

            if (hop_distance(cand_home, free, MAGIC_ENTRY_NR) < current_hop_range) {
                /* swap */
                memcpy(&mb->mgentries[magic_entry_to_offset(free)],
                       me, sizeof(*me));
                clear_bit(off, (unsigned long *)(mb->multi_bitmap));
                set_bit(magic_entry_to_offset(free), (unsigned long *)(mb->multi_bitmap));

                set_page_dirty(page);
                f2fs_put_page(page, 1);

                free = cand;
                moved = true;
                break;
            }

            f2fs_put_page(page, 1);
        }

        if (!moved)
            return -ENOSPC;
    }

    /* ---------- 4. 成功返回 free slot ---------- */
    atomic_inc(&sbi->magic_info->used_entries);

    *ret_entry_id = free;
    *ret_page = free_page;
    *ret_entry =
        &((struct f2fs_magic_block *)
            page_address(free_page))
            ->mgentries[magic_entry_to_offset(free)];

    return 0;
}



int get_mulref_entry(block_t blkaddr)
{
    // 判断这个block是不是多引用块
    return 0;
}

int get_magic_entry(block_t blkaddr)
{
    // 判断这个block是不是多引用块
    return 0;
}

bool is_mulref_blk(block_t blkaddr)
{
    // 判断这个block是不是多引用块
    return false;
}

bool is_modified_cow(block_t blkaddr)
{
    // 判断这个block是不是多引用块
    return true;
}

/*
 * f2fs_is_under_snapshot_dir - 检查 inode 是否在快照目录下
 * @inode: 要检查的 inode
 *
 * 从当前 inode 开始，向上遍历父目录，检查是否有任何一级是快照目录。
 * 如果自身或任何父目录是快照目录，返回 true。
 *
 * 返回: true - 在快照目录下（禁止 rm 删除）
 *       false - 不在快照目录下（可以正常删除）
 */
bool f2fs_is_under_snapshot_dir(struct inode *inode)
{
    struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
    struct f2fs_magic_entry tmp_me;
    u32 entry_id = 0;
    struct inode *cur_inode = inode;
    struct dentry *dentry = NULL;
    struct dentry *parent_dentry = NULL;
    bool result = false;
    int depth = 0;
    const int max_depth = 256; /* 防止无限循环 */

    memset(&tmp_me, 0, sizeof(tmp_me));

    /* 先检查自身是否是快照目录 */
    if (!f2fs_magic_lookup(sbi, cur_inode->i_ino, &entry_id, &tmp_me)) {
        pr_info("[snapfs rm]: inode %lu is a snapshot directory, rm denied\n",
                cur_inode->i_ino);
        return true;
    }

    /* 向上遍历父目录 */
    while (depth < max_depth) {
        depth++;

        dentry = d_find_any_alias(cur_inode);
        if (!dentry)
            break;

        parent_dentry = dget_parent(dentry);
        dput(dentry);

        if (!parent_dentry)
            break;

        /* 到达根目录 */
        if (parent_dentry == parent_dentry->d_parent) {
            dput(parent_dentry);
            break;
        }

        cur_inode = d_inode(parent_dentry);
        if (!cur_inode) {
            dput(parent_dentry);
            break;
        }

        /* 检查父目录是否是快照目录 */
        memset(&tmp_me, 0, sizeof(tmp_me));
        entry_id = 0;
        if (!f2fs_magic_lookup(sbi, cur_inode->i_ino, &entry_id, &tmp_me)) {
            pr_info("[snapfs rm]: parent dir %lu is a snapshot directory, rm denied\n",
                    cur_inode->i_ino);
            dput(parent_dentry);
            result = true;
            break;
        }

        dput(parent_dentry);
    }

    return result;
}

bool is_snapshot_inode(struct inode *inode, 
    struct f2fs_magic_entry *me, u32 *entry_id)
{
    struct f2fs_sb_info *sbi = NULL;
    struct f2fs_magic_entry tmp_me;
	u32 tmp_entry_id = 0;
    memset(&tmp_me, 0, sizeof(tmp_me));
    sbi = F2FS_I_SB(inode);
    struct dentry *dentry = NULL;
    dentry = d_find_any_alias(inode);
    if(dentry) dput(dentry);
    if(SNAPFS_DEBUG) pr_info("[snapfs cow1]: debug check file[%s]\n",dentry->d_name.name);
	if (f2fs_magic_lookup(sbi, inode->i_ino, &tmp_entry_id, &tmp_me)) {// 未找到或者冲突未解决
		// pr_info("[%u] is not snapshot\n", inode->i_ino);
        return false;
	}
    memcpy(me, &tmp_me, sizeof(tmp_me));
    *entry_id = tmp_entry_id;
    // pr_info("[%u] is snapshot: \n",inode->i_ino);
    return true;
}

int set_mulref_entry(struct f2fs_sb_info *sbi, block_t blkaddr, nid_t ino,
		u32 src_ino, struct snapfs_cow_progress *progress, u16 progress_bit){ //, struct page *ipage

    int ret;
    block_t local_blk = blkaddr;
    ret = f2fs_alloc_mulref_entry(sbi, &local_blk, ino, progress, progress_bit);
    if(ret){
        pr_info("[snapfs cow222]: debug setmulref failed! blk[%u]\n",blkaddr);
        return ret;
    }
    return 0;
}

bool f2fs_is_empty_file(struct f2fs_sb_info *sbi,
                    struct inode *inode){

    struct f2fs_inode *ri;
    struct page *page;
    loff_t isize;

    page = f2fs_get_node_page(sbi, inode->i_ino);
    if (IS_ERR(page)) {
        pr_err("[snapfs cow22]: debug get page failed[%lu]\n", inode->i_ino); 
        return true;
    }
    ri = F2FS_INODE(page);
    isize  = le64_to_cpu(ri->i_size); 
    if (isize == 0) {
        f2fs_put_page(page, 1);
		if(SNAPFS_DEBUG) pr_info("[snapfs cow22]: debug inode %lu is empty file\n", inode->i_ino);
		return true;
	}else{
        if(SNAPFS_DEBUG) pr_info("[snapfs cow22]: debug inode %lu is non empty file\n", inode->i_ino);
    }
    f2fs_put_page(page, 1);
    return false; // 需要cow处理
}

/*
 * 处理一个 direct node 中所有有效数据块（使用批量 redo）
 *
 * @inode: 源文件 inode
 * @src_ino: 源文件 inode 号
 * @node_nid: direct node 的 nid
 * @node_ofs: node block 的 offset（在文件树中的位置）
 *
 * 返回值：0 成功，非 0 失败
 */
/*
 * 处理一个 direct node 中的指定范围数据块（使用批量 redo）
 *
 * @inode: 源文件 inode
 * @src_ino: 源文件 inode 号
 * @node_nid: direct node 的 nid
 * @node_ofs: node block 的 offset（用于标识）
 * @start: 数据块在 direct node 中的起始偏移
 * @len: 要处理的数据块数量
 *
 * 返回值：0 成功，非 0 失败
 */
static int __f2fs_cow_direct_node_batch(struct inode *inode, u32 src_ino,
					nid_t node_nid, u16 node_ofs,
					long start, long len)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct page *dn_ipage;
	struct direct_node *dn;
	block_t *data_blks;
	u16 *lblks;
	int ret = 0;
	int i;

	if (len <= 0)
		return 0;

	/* 防御性检查：验证 direct node nid 范围 */
	if (node_nid >= NM_I(sbi)->max_nid) {
		pr_err("[snapfs batch] __f2fs_cow_direct_node_batch: invalid node_nid=%u (max_nid=%u)\n",
		       node_nid, NM_I(sbi)->max_nid);
		return -EINVAL;
	}

	/* 分配临时数组 */
	data_blks = kcalloc(len, sizeof(block_t), GFP_NOFS);
	lblks = kcalloc(len, sizeof(u16), GFP_NOFS);
	if (!data_blks || !lblks) {
		ret = -ENOMEM;
		goto out;
	}

	/* 获取 direct node */
	dn_ipage = f2fs_get_node_page(sbi, node_nid);
	if (IS_ERR(dn_ipage)) {
		ret = PTR_ERR(dn_ipage);
		goto out;
	}
	dn = (struct direct_node *)page_address(dn_ipage);

	/* 收集指定范围内的有效数据块 */
	for (i = 0; i < len; i++) {
		block_t blkaddr = le32_to_cpu(dn->addr[start + i]);
		if (__is_valid_data_blkaddr(blkaddr)) {
			data_blks[i] = blkaddr;
			lblks[i] = (u16)(start + i);
		} else {
			data_blks[i] = 0;
			lblks[i] = (u16)(start + i);
		}
	}

	f2fs_put_page(dn_ipage, 1);

	/* 调用批量 redo 函数处理该 node block */
	ret = f2fs_cow_node_block_batch(inode, src_ino, node_nid, node_ofs,
					data_blks, len, lblks);
	if (ret) {
		pr_err("[snapfs batch] failed to cow direct node %u: %d\n",
		       node_nid, ret);
	}

out:
	kfree(data_blks);
	kfree(lblks);
	return ret;
}

/*
 * 处理 inode 直接地址区中的指定范围有效数据块（使用批量 redo）
 *
 * @inode: 源文件 inode
 * @src_ino: 源文件 inode 号
 * @i_addr: inode 的数据块地址数组
 * @start: 起始逻辑块号
 * @end: 结束逻辑块号（不包含）
 *
 * 返回值：0 成功，非 0 失败
 */
static int __f2fs_cow_inode_direct_batch(struct inode *inode, u32 src_ino,
					 block_t *i_addr, long start, long end)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	block_t *data_blks;
	u16 *lblks;
	long len = end - start;
	int nr_data_blks = 0;
	int ret = 0;
	long i;

	if (len <= 0)
		return 0;

	/* 分配临时数组 */
	data_blks = kcalloc(len, sizeof(block_t), GFP_NOFS);
	lblks = kcalloc(len, sizeof(u16), GFP_NOFS);
	if (!data_blks || !lblks) {
		ret = -ENOMEM;
		goto out;
	}

	/* 收集指定范围内的有效数据块 */
	for (i = 0; i < len; i++) {
		block_t blkaddr = le32_to_cpu(i_addr[start + i]);
		if (__is_valid_data_blkaddr(blkaddr)) {
			data_blks[nr_data_blks] = blkaddr;
			lblks[nr_data_blks] = (u16)(start + i);
			nr_data_blks++;
		}
	}

	if (nr_data_blks == 0) {
		pr_info("[snapfs batch] inode direct [%ld-%ld]: no valid data blocks, nr_data_blks=%d\n",
			 start, end, nr_data_blks);
		goto out;
	}

	pr_info("[snapfs batch] calling f2fs_cow_node_block_batch: nr_data_blks=%d, data_blks[0]=%u\n",
	        nr_data_blks, data_blks[0]);

	/* 调用批量 redo 函数处理 inode 直接地址区 */
	ret = f2fs_cow_node_block_batch(inode, src_ino, 0, 0,
					data_blks, nr_data_blks, lblks);
	if (ret) {
		pr_err("[snapfs batch] failed to cow inode direct [%ld-%ld]: %d\n",
		       start, end, ret);
	}

out:
	kfree(data_blks);
	kfree(lblks);
	return ret;
}

static int __f2fs_set_mulref_blocks(struct inode *inode, u32 src_ino,
					 struct snapfs_cow_progress *resume_progress)
{
	/* 调试日志：跟踪 __f2fs_set_mulref_blocks 调用 */
	pr_info("[snapfs mulref] ====== __f2fs_set_mulref_blocks ENTER ======\n");
	pr_info("[snapfs mulref] inode=%u, src_ino=%u, i_size=%llu, i_blocks=%lu\n",
	       inode->i_ino, src_ino, inode->i_size, inode->i_blocks);
	pr_info("[snapfs mulref] resume_progress=%s\n",
	       (resume_progress && resume_progress->active) ? "active" : "NULL");

	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct snapfs_cow_progress progress;
	loff_t isize;
	pgoff_t lblk, max_lblk, start_lblk = 0;
	unsigned int blkbits;
	struct f2fs_inode *fi;
    struct page *ipage;
    struct page *dn_ipage;
    nid_t nid = 0;
    block_t blkaddr = 0;
    struct direct_node *dn;
    u32 i_nid[5];
    struct page *indirect_page;
    struct indirect_node *indirect;

    struct page *indirect_page2;
    struct indirect_node *indirect2;

    long in_dn = 0;
    long in_dn2 = 0;
    long off_in_dn = 0;
    long off_in_dn2 = 0;

    block_t *i_addr = NULL;
    bool batch_mode = false;

    int ret = 0;

    /* 打印 max_nid 用于调试 */
#if 0
    pr_err("[snapfs mulref] max_nid=%u\n", NM_I(sbi)->max_nid);
#endif

    if (resume_progress && resume_progress->active) {
        progress = *resume_progress;
        ret = snapfs_progress_group_start_lblk(inode, &progress, &start_lblk);
        if (ret)
            return ret;
    } else {
        snapfs_progress_reset(&progress);
    }

    if(S_ISREG(inode->i_mode)){
        if(SNAPFS_DEBUG) pr_info("[snapfs cow22]: debug setmulref [noninline data]\n");
    }

    const long direct_index = ADDRS_PER_INODE(inode);// 923
	const long direct_blks = ADDRS_PER_BLOCK(inode);// 1018
    const long level1_blks = direct_index + direct_blks;// 923 + 1018
    const long level2_blks = level1_blks + direct_blks;// 923 + 1018 + 1018
    const long level3_blks = level2_blks + direct_blks * direct_blks; // 923 + 1018 + 1018 + 1018*1018
    const long level4_blks = level3_blks + direct_blks * direct_blks;// 923 + 1018 + 1018 + 1018*1018+ 1018*1018
    const long level5_blks = level4_blks + direct_blks * direct_blks * direct_blks;
    // 923 + 1018 + 1018 + 1018*1018+ 1018*1018 + 1018*1018*1018

    const long double_dir_blk = direct_blks * direct_blks;

    /* 获取 inode page 并设置必要变量 */
    ipage = f2fs_get_node_page(sbi, inode->i_ino);
    if (IS_ERR(ipage)) {
        ret = PTR_ERR(ipage);
        pr_err("[snapfs cow22]: debug get page failed[%lu]\n", inode->i_ino);
        goto out;
    }
    fi = F2FS_INODE(ipage);
    isize = le64_to_cpu(fi->i_size);
    blkbits = inode->i_blkbits;
    max_lblk = (isize + (1ULL << blkbits) - 1) >> blkbits;

    i_nid[0] = le32_to_cpu(fi->i_nid[0]);
    i_nid[1] = le32_to_cpu(fi->i_nid[1]);
    i_nid[2] = le32_to_cpu(fi->i_nid[2]);
    i_nid[3] = le32_to_cpu(fi->i_nid[3]);
    i_nid[4] = le32_to_cpu(fi->i_nid[4]);

    /* 调试日志：打印读取到的 i_nid */
#if 0
    pr_err("[snapfs mulref] i_nid[0]=%u, i_nid[1]=%u, i_nid[2]=%u, i_nid[3]=%u, i_nid[4]=%u\n",
           i_nid[0], i_nid[1], i_nid[2], i_nid[3], i_nid[4]);
    pr_err("[snapfs mulref] i_nid[0-4] validity: [%s,%s,%s,%s,%s]\n",
           (i_nid[0] < NM_I(sbi)->max_nid) ? "valid" : "INVALID",
           (i_nid[1] < NM_I(sbi)->max_nid) ? "valid" : "INVALID",
           (i_nid[2] < NM_I(sbi)->max_nid) ? "valid" : "INVALID",
           (i_nid[3] < NM_I(sbi)->max_nid) ? "valid" : "INVALID",
           (i_nid[4] < NM_I(sbi)->max_nid) ? "valid" : "INVALID");
#endif

    /* 从 inode 复制 direct address 数组 */
    {
        int max_addrs = ADDRS_PER_INODE(inode);
        block_t *src_addr = (block_t *)fi->i_addr;
        block_t *local_i_addr = kmalloc(max_addrs * sizeof(block_t), GFP_NOFS);
        if (!local_i_addr) {
            ret = -ENOMEM;
            goto out_skip_progress;
        }
        memcpy(local_i_addr, src_addr, max_addrs * sizeof(block_t));
        /* 保存到 i_addr 指针变量中 */
        i_addr = local_i_addr;
    }

    /* 检查 batch redo 模式（在获取 inode page 之后设置） */
    batch_mode = (sbi->magic_info->redo_info &&
                  sbi->magic_info->redo_info->batch_mode);

    /*
     * Batch Redo 模式：按 node block 批量处理
     * 以下变量在 batch mode 下使用
     */
    if (batch_mode) {
        long batch_in_dn_idx;
        long batch_in_dn2_idx;
        long batch_in_dn3_idx;
        long batch_dn_offset_start;
        long batch_this_start;
        long batch_this_end;
        long batch_this_len;
        long batch_start_in_dn;
        long batch_end_in_dn;
        long batch_level_start;
        long batch_level_end;
        struct page *batch_indirect_page = NULL;
        struct page *batch_indirect2_page = NULL;
        struct page *batch_dn_ipage = NULL;
        struct indirect_node *batch_indirect = NULL;
        struct indirect_node *batch_indirect2 = NULL;
        struct direct_node *batch_dn = NULL;
        nid_t batch_direct_nid;
        nid_t batch_indirect2_nid;
        block_t *batch_data_blks = NULL;
        u16 *batch_lblks = NULL;

        /*
         * 步骤 1: 处理 Level 0 (inode 直接地址区)
         */
        batch_level_start = start_lblk;
        batch_level_end = (max_lblk < direct_index) ? max_lblk : direct_index;
        if (batch_level_start < batch_level_end) {
            ret = __f2fs_cow_inode_direct_batch(inode, src_ino, i_addr,
                                                batch_level_start, batch_level_end);
            if (ret) {
                pr_err("[snapfs batch] level0 batch failed: %d\n", ret);
                goto batch_out;
            }
        }

        /*
         * 步骤 2: 处理 Level 1 (direct nodes from i_nid[0])
         */
        if (max_lblk > direct_index && i_nid[0] != 0) {
            batch_level_start = (start_lblk > direct_index) ? start_lblk : direct_index;
            batch_level_end = (max_lblk < level1_blks) ? max_lblk : level1_blks;
            if (batch_level_start < batch_level_end) {
                ret = __f2fs_cow_direct_node_batch(inode, src_ino, i_nid[0],
                                                    1, batch_level_start - direct_index,
                                                    batch_level_end - batch_level_start);
                if (ret) {
                    pr_err("[snapfs batch] level1 batch failed: %d\n", ret);
                    goto batch_out;
                }
            }
        }

        /*
         * 步骤 3: 处理 Level 2 (direct nodes from i_nid[1])
         */
        if (max_lblk > level1_blks && i_nid[1] != 0) {
            batch_level_start = (start_lblk > level1_blks) ? start_lblk : level1_blks;
            batch_level_end = (max_lblk < level2_blks) ? max_lblk : level2_blks;
            if (batch_level_start < batch_level_end) {
                ret = __f2fs_cow_direct_node_batch(inode, src_ino, i_nid[1],
                                                    2, batch_level_start - level1_blks,
                                                    batch_level_end - batch_level_start);
                if (ret) {
                    pr_err("[snapfs batch] level2 batch failed: %d\n", ret);
                    goto batch_out;
                }
            }
        }

        /*
         * 步骤 4: 处理 Level 3 (indirect nodes from i_nid[2])
         */
        if (max_lblk > level2_blks && i_nid[2] != 0) {
            /* 防御性检查：验证 i_nid[2] 范围 */
            if (i_nid[2] >= NM_I(sbi)->max_nid) {
#if 0
                pr_info("[snapfs batch] level3 invalid i_nid[2]=%u (max_nid=%u), skipping\n",
                       i_nid[2], NM_I(sbi)->max_nid);
#endif
            } else {
            batch_level_start = (start_lblk > level2_blks) ? start_lblk : level2_blks;
            batch_level_end = (max_lblk < level3_blks) ? max_lblk : level3_blks;

            batch_indirect_page = f2fs_get_node_page(sbi, i_nid[2]);
            if (IS_ERR(batch_indirect_page)) {
                ret = PTR_ERR(batch_indirect_page);
                pr_err("[snapfs batch] level3 get indirect_page failed\n");
                goto batch_out;
            }
            batch_indirect = (struct indirect_node *)page_address(batch_indirect_page);

            batch_start_in_dn = (batch_level_start - level2_blks) / direct_blks;
            batch_end_in_dn = ((batch_level_end - 1 - level2_blks) / direct_blks) + 1;

            for (batch_in_dn_idx = batch_start_in_dn;
                 batch_in_dn_idx < batch_end_in_dn && batch_in_dn_idx < direct_blks;
                 batch_in_dn_idx++) {
                batch_direct_nid = le32_to_cpu(batch_indirect->nid[batch_in_dn_idx]);
                if (batch_direct_nid == 0)
                    continue;
                /* 防御性检查：验证从 batch indirect node 读取的 nid */
                if (batch_direct_nid >= NM_I(sbi)->max_nid) {
#if 0
                    pr_info("[snapfs batch] level3 invalid batch_direct_nid=%u (max_nid=%u), skipping\n",
                           batch_direct_nid, NM_I(sbi)->max_nid);
#endif
                    continue;
                }

                batch_dn_ipage = f2fs_get_node_page(sbi, batch_direct_nid);
                if (IS_ERR(batch_dn_ipage)) {
                    ret = PTR_ERR(batch_dn_ipage);
                    pr_err("[snapfs batch] level3 get batch_dn_ipage failed: nid=%u, ret=%d\n",
                           batch_direct_nid, ret);
                    f2fs_put_page(batch_indirect_page, 1);
                    batch_indirect_page = NULL;
                    goto batch_out;
                }
                batch_dn = (struct direct_node *)page_address(batch_dn_ipage);

                batch_this_start = level2_blks + batch_in_dn_idx * direct_blks;
                batch_this_end = batch_this_start + direct_blks;
                if (batch_level_start > batch_this_start)
                    batch_this_start = batch_level_start;
                if (batch_level_end < batch_this_end)
                    batch_this_end = batch_level_end;
                batch_this_len = batch_this_end - batch_this_start;

                if (batch_this_len > 0) {
                    batch_data_blks = kmalloc(batch_this_len * sizeof(block_t), GFP_NOFS);
                    batch_lblks = kmalloc(batch_this_len * sizeof(u16), GFP_NOFS);
                    if (!batch_data_blks || !batch_lblks) {
                        ret = -ENOMEM;
                        kfree(batch_data_blks);
                        kfree(batch_lblks);
                        batch_data_blks = NULL;
                        batch_lblks = NULL;
                        f2fs_put_page(batch_dn_ipage, 1);
                        f2fs_put_page(batch_indirect_page, 1);
                        batch_dn_ipage = NULL;
                        batch_indirect_page = NULL;
                        goto batch_out;
                    }

                    batch_dn_offset_start = batch_this_start - (level2_blks + batch_in_dn_idx * direct_blks);
                    for (batch_in_dn3_idx = 0; batch_in_dn3_idx < batch_this_len; batch_in_dn3_idx++) {
                        batch_data_blks[batch_in_dn3_idx] =
                            le32_to_cpu(batch_dn->addr[batch_dn_offset_start + batch_in_dn3_idx]);
                        batch_lblks[batch_in_dn3_idx] =
                            (u16)(batch_dn_offset_start + batch_in_dn3_idx);
                    }

                    ret = f2fs_cow_node_block_batch(inode, src_ino, batch_direct_nid,
                                                    (u16)(3 + batch_in_dn_idx),
                                                    batch_data_blks, batch_this_len, batch_lblks);
                    kfree(batch_data_blks);
                    kfree(batch_lblks);
                    batch_data_blks = NULL;
                    batch_lblks = NULL;
                    if (ret) {
                        pr_err("[snapfs batch] f2fs_cow_node_block_batch failed: ret=%d, batch_direct_nid=%u, batch_this_len=%ld\n",
                               ret, batch_direct_nid, batch_this_len);
                        kfree(batch_data_blks);
                        kfree(batch_lblks);
                        batch_data_blks = NULL;
                        batch_lblks = NULL;
                        f2fs_put_page(batch_dn_ipage, 1);
                        f2fs_put_page(batch_indirect_page, 1);
                        batch_dn_ipage = NULL;
                        batch_indirect_page = NULL;
                        goto batch_out;
                    }
                }

                f2fs_put_page(batch_dn_ipage, 1);
                batch_dn_ipage = NULL;
            }

            f2fs_put_page(batch_indirect_page, 1);
            batch_indirect_page = NULL;
            }  /* 关闭 else 块 (i_nid[2] >= max_nid 检查) */
        }

        /*
         * 步骤 5: 处理 Level 4 (indirect nodes from i_nid[3])
         */
        if (max_lblk > level3_blks && i_nid[3] != 0) {
            /* 防御性检查：验证 i_nid[3] 范围 */
            if (i_nid[3] >= NM_I(sbi)->max_nid) {
#if 0
                pr_info("[snapfs batch] level4 invalid i_nid[3]=%u (max_nid=%u), skipping\n",
                       i_nid[3], NM_I(sbi)->max_nid);
#endif
            } else {
            batch_level_start = (start_lblk > level3_blks) ? start_lblk : level3_blks;
            batch_level_end = (max_lblk < level4_blks) ? max_lblk : level4_blks;

            /* DEBUG: 打印 level4 的边界信息 */
#if 0
            pr_info("[snapfs batch] level4 DEBUG: i_nid[3]=%u, batch_level_start=%ld, batch_level_end=%ld, "
                    "batch_start_in_dn=%ld, batch_end_in_dn=%ld, max_lblk=%lu\n",
                    i_nid[3], batch_level_start, batch_level_end,
                    (batch_level_start - level3_blks) / direct_blks,
                    ((batch_level_end - 1 - level3_blks) / direct_blks) + 1,
                    (unsigned long)max_lblk);
#endif

            batch_indirect_page = f2fs_get_node_page(sbi, i_nid[3]);
            if (IS_ERR(batch_indirect_page)) {
                ret = PTR_ERR(batch_indirect_page);
                pr_err("[snapfs batch] level4 get indirect_page failed\n");
                goto batch_out;
            }
            batch_indirect = (struct indirect_node *)page_address(batch_indirect_page);
#if 0
            /* 调试日志：打印 level4 indirect_node 的 i_nid[3] 和部分 child nids */
            {
                int dbg_i;
                int invalid_count = 0;
                pr_info("[snapfs batch] level4 indirect_node scan: total %d nids, checking invalid (>= max_nid=%u):\n",
                        NIDS_PER_BLOCK, NM_I(sbi)->max_nid);
                for (dbg_i = 0; dbg_i < NIDS_PER_BLOCK; dbg_i++) {
                    nid_t dbg_nid = le32_to_cpu(batch_indirect->nid[dbg_i]);
                    if (dbg_nid >= NM_I(sbi)->max_nid || (dbg_nid != 0 && dbg_nid < F2FS_ROOT_INO(sbi))) {
                        pr_info("    [%d] = %u (INVALID!)\n", dbg_i, dbg_nid);
                        invalid_count++;
                    }
                }
                pr_info("  Total invalid indirect2_nids in level4 indirect_node: %d\n", invalid_count);
                pr_info("  level4 indirect_node child nids (first 5):\n");
                for (dbg_i = 0; dbg_i < 5 && dbg_i < NIDS_PER_BLOCK; dbg_i++) {
                    nid_t dbg_nid = le32_to_cpu(batch_indirect->nid[dbg_i]);
                    pr_info("    [%d] = %u\n", dbg_i, dbg_nid);
                }
                pr_info("  level4 indirect_node child nids (last 5):\n");
                for (dbg_i = NIDS_PER_BLOCK - 5; dbg_i < NIDS_PER_BLOCK; dbg_i++) {
                    nid_t dbg_nid = le32_to_cpu(batch_indirect->nid[dbg_i]);
                    pr_info("    [%d] = %u\n", dbg_i, dbg_nid);
                }
            }
#endif

            batch_start_in_dn = (batch_level_start - level3_blks) / direct_blks;
            batch_end_in_dn = ((batch_level_end - 1 - level3_blks) / direct_blks) + 1;
            /*
            pr_info("[snapfs batch] level4 loop bounds: batch_level_start=%ld, batch_level_end=%ld, "
                    "batch_start_in_dn=%ld, batch_end_in_dn=%ld, snap_inode i_size=%llu, max_lblk=%lu\n",
                    batch_level_start, batch_level_end, batch_start_in_dn, batch_end_in_dn,
                    inode->i_size, (unsigned long)max_lblk);
            */

            for (batch_in_dn_idx = batch_start_in_dn;
                 batch_in_dn_idx < batch_end_in_dn && batch_in_dn_idx < direct_blks;
                 batch_in_dn_idx++) {
                batch_indirect2_nid = le32_to_cpu(batch_indirect->nid[batch_in_dn_idx]);
                /*
                pr_info("[snapfs batch] level4: reading batch_indirect->nid[%ld] = %u\n",
                        batch_in_dn_idx, batch_indirect2_nid);
                */
                if (batch_indirect2_nid == 0)
                    continue;
                if (batch_indirect2_nid >= NM_I(sbi)->max_nid) {
#if 0
                    pr_info("[snapfs batch] level4: invalid indirect2_nid=%u at idx=%ld, skipping (max_nid=%u)\n",
                           batch_indirect2_nid, batch_in_dn_idx, NM_I(sbi)->max_nid);
#endif
                    continue;
                }

                batch_indirect2_page = f2fs_get_node_page(sbi, batch_indirect2_nid);
                if (IS_ERR(batch_indirect2_page)) {
                    ret = PTR_ERR(batch_indirect2_page);
                    pr_err("[snapfs batch] level4 get batch_indirect2_page failed: nid=%u, ret=%d\n",
                           batch_indirect2_nid, ret);
                    f2fs_put_page(batch_indirect_page, 1);
                    batch_indirect_page = NULL;
                    batch_indirect2_page = NULL;
                    goto batch_out;
                }
                batch_indirect2 = (struct indirect_node *)page_address(batch_indirect2_page);

                /*
                pr_info("[snapfs batch] level4: indirect2_node at idx=%ld, nids[0..4]=[%u,%u,%u,%u,%u]\n",
                        batch_in_dn_idx,
                        le32_to_cpu(batch_indirect2->nid[0]),
                        le32_to_cpu(batch_indirect2->nid[1]),
                        le32_to_cpu(batch_indirect2->nid[2]),
                        le32_to_cpu(batch_indirect2->nid[3]),
                        le32_to_cpu(batch_indirect2->nid[4]));
                */

                for (batch_in_dn2_idx = 0; batch_in_dn2_idx < direct_blks; batch_in_dn2_idx++) {
                    batch_direct_nid = le32_to_cpu(batch_indirect2->nid[batch_in_dn2_idx]);
                    /*
                    pr_info("[snapfs batch] level4: reading indirect2->nid[%ld][%ld] = %u\n",
                            batch_in_dn_idx, batch_in_dn2_idx, batch_direct_nid);
                    */
                    if (batch_direct_nid == 0)
                        continue;
                    if (batch_direct_nid >= NM_I(sbi)->max_nid) {
                        /* DEBUG: 打印无效 nid 的详细信息 */
                        // pr_info("[snapfs batch] level4: invalid batch_direct_nid=%u at indirect2[%ld][%ld], skipping (max_nid=%u)\n",
                        //        batch_direct_nid, batch_in_dn_idx, batch_in_dn2_idx, NM_I(sbi)->max_nid);
                        continue;
                    }

                    batch_this_start = level3_blks +
                        (batch_in_dn_idx * direct_blks + batch_in_dn2_idx) * direct_blks;
                    batch_this_end = batch_this_start + direct_blks;

                    if (batch_this_end <= batch_level_start ||
                        batch_this_start >= batch_level_end)
                        continue;

                    batch_dn_ipage = f2fs_get_node_page(sbi, batch_direct_nid);
                    if (IS_ERR(batch_dn_ipage)) {
                        ret = PTR_ERR(batch_dn_ipage);
                        pr_err("[snapfs batch] level4 get batch_dn_ipage failed: nid=%u, ret=%d\n",
                               batch_direct_nid, ret);
                        f2fs_put_page(batch_indirect2_page, 1);
                        f2fs_put_page(batch_indirect_page, 1);
                        batch_indirect2_page = NULL;
                        batch_indirect_page = NULL;
                        goto batch_out;
                    }
                    batch_dn = (struct direct_node *)page_address(batch_dn_ipage);

                    if (batch_level_start > batch_this_start)
                        batch_this_start = batch_level_start;
                    if (batch_level_end < batch_this_end)
                        batch_this_end = batch_level_end;
                    batch_this_len = batch_this_end - batch_this_start;

                    if (batch_this_len > 0) {
                        batch_data_blks = kmalloc(batch_this_len * sizeof(block_t), GFP_NOFS);
                        batch_lblks = kmalloc(batch_this_len * sizeof(u16), GFP_NOFS);
                        if (!batch_data_blks || !batch_lblks) {
                            ret = -ENOMEM;
                            kfree(batch_data_blks);
                            kfree(batch_lblks);
                            batch_data_blks = NULL;
                            batch_lblks = NULL;
                            f2fs_put_page(batch_dn_ipage, 1);
                            f2fs_put_page(batch_indirect2_page, 1);
                            f2fs_put_page(batch_indirect_page, 1);
                            batch_dn_ipage = NULL;
                            batch_indirect2_page = NULL;
                            batch_indirect_page = NULL;
                            goto batch_out;
                        }

                        batch_dn_offset_start = batch_this_start -
                            (level3_blks + (batch_in_dn_idx * direct_blks + batch_in_dn2_idx) * direct_blks);
                        for (batch_in_dn3_idx = 0; batch_in_dn3_idx < batch_this_len; batch_in_dn3_idx++) {
                            batch_data_blks[batch_in_dn3_idx] =
                                le32_to_cpu(batch_dn->addr[batch_dn_offset_start + batch_in_dn3_idx]);
                            batch_lblks[batch_in_dn3_idx] =
                                (u16)(batch_dn_offset_start + batch_in_dn3_idx);
                        }

                        ret = f2fs_cow_node_block_batch(inode, src_ino, batch_direct_nid,
                                                        (u16)(1022 + batch_in_dn_idx * direct_blks + batch_in_dn2_idx),
                                                        batch_data_blks, batch_this_len, batch_lblks);
                        kfree(batch_data_blks);
                        kfree(batch_lblks);
                        batch_data_blks = NULL;
                        batch_lblks = NULL;
                        if (ret) {
                            pr_err("[snapfs batch] level4 f2fs_cow_node_block_batch failed: ret=%d\n", ret);
                            kfree(batch_data_blks);
                            kfree(batch_lblks);
                            batch_data_blks = NULL;
                            batch_lblks = NULL;
                            f2fs_put_page(batch_dn_ipage, 1);
                            f2fs_put_page(batch_indirect2_page, 1);
                            f2fs_put_page(batch_indirect_page, 1);
                            batch_dn_ipage = NULL;
                            batch_indirect2_page = NULL;
                            batch_indirect_page = NULL;
                            goto batch_out;
                        }
                    }

                    f2fs_put_page(batch_dn_ipage, 1);
                    batch_dn_ipage = NULL;
                }

                f2fs_put_page(batch_indirect2_page, 1);
                batch_indirect2_page = NULL;
            }

            f2fs_put_page(batch_indirect_page, 1);
            batch_indirect_page = NULL;
            }  /* 关闭 else 块 (i_nid[3] >= max_nid 检查) */
        }

        /*
         * 步骤 6: 处理 Level 5 (double indirect nodes from i_nid[4])
         * i_nid[4] -> indirect node -> indirect nodes -> direct nodes -> data blocks
         */
        if (max_lblk > level4_blks && i_nid[4] != 0) {
            /* 防御性检查：验证 i_nid[4] 范围 */
            if (i_nid[4] >= NM_I(sbi)->max_nid) {
#if 0
                pr_info("[snapfs batch] level5 invalid i_nid[4]=%u (max_nid=%u), skipping\n",
                       i_nid[4], NM_I(sbi)->max_nid);
#endif
            } else {
            struct page *indirect3_page = NULL;
            struct indirect_node *indirect3 = NULL;
            struct page *indirect2_page = NULL;
            struct indirect_node *indirect2 = NULL;

            batch_level_start = (start_lblk > level4_blks) ? start_lblk : level4_blks;
            batch_level_end = max_lblk;

            pr_debug("[snapfs batch] level5: processing double indirect, lblk %ld to %ld\n",
                     batch_level_start, batch_level_end);

            /* 获取第3级 indirect node (i_nid[4]) */
            indirect3_page = f2fs_get_node_page(sbi, i_nid[4]);
            if (IS_ERR(indirect3_page)) {
                ret = PTR_ERR(indirect3_page);
                pr_err("[snapfs batch] level5 get indirect3_page failed\n");
                goto batch_out;
            }
            indirect3 = (struct indirect_node *)page_address(indirect3_page);
#if 0
            /* 调试日志：打印 level5 indirect3 (i_nid[4]) 的部分 child nids */
            pr_info("[snapfs batch] level5: i_nid[4]=%u, indirect3 at %p\n",
                    i_nid[4], indirect3);
            {
                int dbg_i;
                pr_info("  level5 indirect3 child nids (first 5):\n");
                for (dbg_i = 0; dbg_i < 5 && dbg_i < NIDS_PER_BLOCK; dbg_i++) {
                    nid_t dbg_nid = le32_to_cpu(indirect3->nid[dbg_i]);
                    pr_info("    [%d] = %u\n", dbg_i, dbg_nid);
                }
                pr_info("  level5 indirect3 child nids (last 5):\n");
                for (dbg_i = NIDS_PER_BLOCK - 5; dbg_i < NIDS_PER_BLOCK; dbg_i++) {
                    nid_t dbg_nid = le32_to_cpu(indirect3->nid[dbg_i]);
                    pr_info("    [%d] = %u\n", dbg_i, dbg_nid);
                }
            }
#endif

            /* 计算涉及的第2级 indirect node 范围 */
            {
                unsigned long dn_idx_start, dn_idx_end;
                unsigned long lblk_in_double_indirect;
                unsigned long indirect2_idx_start, indirect2_idx_end;

                lblk_in_double_indirect = batch_level_start - level4_blks;

                /* 每个 i_nid[4] 的 entry 覆盖 direct_blks * direct_blks 个块 */
                indirect2_idx_start = lblk_in_double_indirect / (direct_blks * direct_blks);
                lblk_in_double_indirect = batch_level_end - 1 - level4_blks;
                indirect2_idx_end = (lblk_in_double_indirect / (direct_blks * direct_blks)) + 1;

                dn_idx_start = 0;
                dn_idx_end = direct_blks;

                pr_debug("[snapfs batch] level5: indirect2_idx %lu to %lu\n",
                         indirect2_idx_start, indirect2_idx_end);

                for (batch_in_dn_idx = indirect2_idx_start;
                     batch_in_dn_idx < indirect2_idx_end && batch_in_dn_idx < direct_blks;
                     batch_in_dn_idx++) {
                    nid_t indirect2_nid = le32_to_cpu(indirect3->nid[batch_in_dn_idx]);
                    if (indirect2_nid == 0)
                        continue;

                    /* 获取第2级 indirect node */
                    indirect2_page = f2fs_get_node_page(sbi, indirect2_nid);
                    if (IS_ERR(indirect2_page)) {
                        ret = PTR_ERR(indirect2_page);
                        pr_err("[snapfs batch] level5 get indirect2_page %u failed: ret=%d\n",
                               indirect2_nid, ret);
                        f2fs_put_page(indirect3_page, 1);
                        indirect3_page = NULL;
                        indirect2_page = NULL;
                        goto batch_out;
                    }
                    indirect2 = (struct indirect_node *)page_address(indirect2_page);

                    for (batch_in_dn2_idx = dn_idx_start;
                         batch_in_dn2_idx < dn_idx_end && batch_in_dn2_idx < NIDS_PER_BLOCK;
                         batch_in_dn2_idx++) {
                        nid_t direct_nid = le32_to_cpu(indirect2->nid[batch_in_dn2_idx]);
                        if (direct_nid == 0)
                            continue;
                        /* DEBUG: 检查 direct_nid 是否有效 */
                        if (direct_nid >= NM_I(sbi)->max_nid) {
#if 0
                            pr_info("[snapfs batch] level5: invalid direct_nid=%u at indirect3[%ld]->indirect2[%ld][%ld], skipping (max_nid=%u)\n",
                                   direct_nid, batch_in_dn_idx, batch_in_dn2_idx, NM_I(sbi)->max_nid);
#endif
                            continue;
                        }

                        /* 计算这个 direct node 覆盖的逻辑块范围 */
                        batch_this_start = level4_blks +
                            (batch_in_dn_idx * direct_blks + batch_in_dn2_idx) * direct_blks;
                        batch_this_end = batch_this_start + direct_blks;

                        /* 检查是否与目标范围有交集 */
                        if (batch_this_end <= batch_level_start ||
                            batch_this_start >= batch_level_end)
                            continue;

                        batch_dn_ipage = f2fs_get_node_page(sbi, direct_nid);
                        if (IS_ERR(batch_dn_ipage)) {
                            ret = PTR_ERR(batch_dn_ipage);
                            pr_err("[snapfs batch] level5 get dn_page %u failed: ret=%d\n",
                                   direct_nid, ret);
                            f2fs_put_page(indirect2_page, 1);
                            f2fs_put_page(indirect3_page, 1);
                            indirect2_page = NULL;
                            indirect3_page = NULL;
                            batch_dn_ipage = NULL;
                            goto batch_out;
                        }
                        batch_dn = (struct direct_node *)page_address(batch_dn_ipage);

                        /* 计算实际需要处理的块范围 */
                        if (batch_level_start > batch_this_start)
                            batch_this_start = batch_level_start;
                        if (batch_level_end < batch_this_end)
                            batch_this_end = batch_level_end;
                        batch_this_len = batch_this_end - batch_this_start;

                        if (batch_this_len > 0) {
                            batch_data_blks = kmalloc(batch_this_len * sizeof(block_t), GFP_NOFS);
                            batch_lblks = kmalloc(batch_this_len * sizeof(u16), GFP_NOFS);
                            if (!batch_data_blks || !batch_lblks) {
                                ret = -ENOMEM;
                                kfree(batch_data_blks);
                                kfree(batch_lblks);
                                batch_data_blks = NULL;
                                batch_lblks = NULL;
                                f2fs_put_page(batch_dn_ipage, 1);
                                f2fs_put_page(indirect2_page, 1);
                                f2fs_put_page(indirect3_page, 1);
                                batch_dn_ipage = NULL;
                                indirect2_page = NULL;
                                indirect3_page = NULL;
                                goto batch_out;
                            }

                            /* 计算 direct node 中的偏移 */
                            batch_dn_offset_start = batch_this_start -
                                (level4_blks + (batch_in_dn_idx * direct_blks + batch_in_dn2_idx) * direct_blks);

                            for (batch_in_dn3_idx = 0; batch_in_dn3_idx < batch_this_len; batch_in_dn3_idx++) {
                                batch_data_blks[batch_in_dn3_idx] =
                                    le32_to_cpu(batch_dn->addr[batch_dn_offset_start + batch_in_dn3_idx]);
                                batch_lblks[batch_in_dn3_idx] =
                                    (u16)(batch_dn_offset_start + batch_in_dn3_idx);
                            }

                            /* node_ofs = 2041 + idx1 * direct_blks + idx2 */
                            ret = f2fs_cow_node_block_batch(inode, src_ino, direct_nid,
                                    (u16)(2041 + batch_in_dn_idx * direct_blks + batch_in_dn2_idx),
                                    batch_data_blks, batch_this_len, batch_lblks);
                            kfree(batch_data_blks);
                            kfree(batch_lblks);
                            batch_data_blks = NULL;
                            batch_lblks = NULL;
                            if (ret) {
                                pr_err("[snapfs batch] level5 f2fs_cow_node_block_batch failed: ret=%d\n", ret);
                                kfree(batch_data_blks);
                                kfree(batch_lblks);
                                batch_data_blks = NULL;
                                batch_lblks = NULL;
                                f2fs_put_page(batch_dn_ipage, 1);
                                f2fs_put_page(indirect2_page, 1);
                                f2fs_put_page(indirect3_page, 1);
                                batch_dn_ipage = NULL;
                                indirect2_page = NULL;
                                indirect3_page = NULL;
                                goto batch_out;
                            }
                        }

                        f2fs_put_page(batch_dn_ipage, 1);
                        batch_dn_ipage = NULL;
                    }

                    f2fs_put_page(indirect2_page, 1);
                    indirect2_page = NULL;
                }
            }

            f2fs_put_page(indirect3_page, 1);
            indirect3_page = NULL;
            }  /* 关闭 else 块 (i_nid[4] >= max_nid 检查) */
        }

batch_out:
        /* 清理 batch 模式下可能残留的页面 */
        pr_debug("[snapfs batch] batch_out: cleaning up, batch_dn_ipage=%p, batch_indirect2_page=%p, batch_indirect_page=%p\n",
                 batch_dn_ipage, batch_indirect2_page, batch_indirect_page);
        if (batch_dn_ipage) {
            f2fs_put_page(batch_dn_ipage, 1);
            batch_dn_ipage = NULL;
        }
        if (batch_indirect2_page) {
            f2fs_put_page(batch_indirect2_page, 1);
            batch_indirect2_page = NULL;
        }
        if (batch_indirect_page) {
            f2fs_put_page(batch_indirect_page, 1);
            batch_indirect_page = NULL;
        }
        kfree(batch_data_blks);
        kfree(batch_lblks);

batch_out_no_resume:
        /* Batch 模式下不更新 progress */
        goto out_skip_progress;
    }

    /* 以下是原有的逐块处理逻辑（batch mode 禁用时使用） */
	for (lblk = start_lblk; lblk < max_lblk; lblk++) {

        if(lblk < direct_index){//873
            // if(SNAPFS_DEBUG) pr_info("------------------direct_index------------------\n");
            if (__is_valid_data_blkaddr(le32_to_cpu(i_addr[lblk]))) {
                // 开始set mulref flag
                // if(check_sit_mulref_entry(sbi, le32_to_cpu(fi->i_addr[lblk]))){
                //     pr_info("direct_index [%u] is mulref\n",lblk);
                // }
                // pr_info("level0_blks lblk %u, node id %u, addr %u\n",lblk,inode->i_ino,le32_to_cpu(i_addr[lblk]));
                if (snapfs_progress_bit_done(&progress, src_ino, inode->i_ino,
					      0, 0, ADDRS_PER_INODE(inode), lblk))
                    continue;
                ret = snapfs_progress_switch_group(sbi, &progress, src_ino,
					inode->i_ino, 0, 0,
					ADDRS_PER_INODE(inode));
                if (ret)
                    goto out;
                ret = set_mulref_entry(sbi, le32_to_cpu(i_addr[lblk]), inode->i_ino, src_ino,
					  &progress, lblk);
                if(ret){
                    pr_err("[snapfs cow22]: debug setmulref failed![direct_index]\n");
                    goto out;
                    // return ret;
                }
            }
            // if(lblk == 0){
            //     // pr_info("lblk[%u] start blkaddr %u\n",lblk,le32_to_cpu(fi->i_addr[lblk]));
            // } 
              
            // if(lblk == max_lblk - 1){
            //     // pr_info("lblk[%u] end blkaddr %u\n",lblk, le32_to_cpu(fi->i_addr[lblk]));  
            // }
            continue;
        }else if(lblk < (pgoff_t)level1_blks){//1891
            // pr_err("level1_blks lblk %u node id ?\n",lblk);
            if(ipage){
                f2fs_put_page(ipage, 1);
                ipage = NULL;
            }
            // nid = le32_to_cpu(fi->i_nid[0]);
            nid = i_nid[0];
            /* 防御性检查：验证 direct_node nid 范围 */
            if (nid >= NM_I(sbi)->max_nid) {
                pr_err("[snapfs cow22]: level1 invalid nid=%u (max_nid=%u), skipping lblk=%lu\n",
                       nid, NM_I(sbi)->max_nid, (unsigned long)lblk);
                continue;
            }
            if(nid == 0) {
                pr_info("level1_blks lblk %u node id is 0\n",lblk);
                continue;
            }
            // if(SNAPFS_DEBUG) pr_info("------------------level1_blks------------------\n");
            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) {
                pr_err("[snapfs cow22]: debug setmulref get dn_ipage failed[%d < direct_index]\n", lblk);
                goto out;
            }
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[lblk - direct_index]);
            f2fs_put_page(dn_ipage, 1);
            dn_ipage = NULL;
            // pr_info("blkaddr %u, lblk - direct_index (%u - %u = %u)\n",blkaddr,lblk,direct_index,lblk - direct_index);
            if (__is_valid_data_blkaddr(blkaddr)) {
                // if(check_sit_mulref_entry(sbi, blkaddr)){
                //     pr_info("level1_blks [%u] is mulref\n",lblk);
                // }
                // 开始set mulref flag
                // pr_info("level1_blks lblk %u node id %u, addr %u\n",lblk,nid,blkaddr);
                if (snapfs_progress_bit_done(&progress, src_ino, inode->i_ino,
					      nid, 1, ADDRS_PER_BLOCK(inode),
					      lblk - direct_index))
                    continue;
                ret = snapfs_progress_switch_group(sbi, &progress, src_ino,
					inode->i_ino, nid, 1,
					ADDRS_PER_BLOCK(inode));
                if (ret)
                    goto out;
                ret = set_mulref_entry(sbi, blkaddr, nid, src_ino, &progress,
					  lblk - direct_index);
                if(ret){
                    pr_err("[snapfs cow22]: debug setmulref failed![level1_blks]\n");
                    goto out;
                    // return ret;
                }
            }
            // if(lblk == max_lblk - 1){
            //     pr_info("lblk[%u] level1_blks end blkaddr %u\n",lblk,blkaddr);  
            // }
            continue;   
            
        }else if(lblk < (pgoff_t)level2_blks){// 2909
            // nid = le32_to_cpu(fi->i_nid[1]);
            nid = i_nid[1];
            /* 防御性检查：验证 direct_node nid 范围 */
            if (nid >= NM_I(sbi)->max_nid) {
                pr_err("[snapfs cow22]: level2 invalid nid=%u (max_nid=%u), skipping lblk=%lu\n",
                       nid, NM_I(sbi)->max_nid, (unsigned long)lblk);
                continue;
            }
            // pr_err("level1_blks lblk %u node id is ?[%u]\n",lblk,nid);
            if(nid == 0) {
                pr_info("level2_blks lblk %u node id is 0\n",lblk);
                continue;
            }
            // if(SNAPFS_DEBUG) pr_info("------------------level2_blks------------------\n");
            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) {
                pr_err("[snapfs cow22]: debug setmulref get dn_ipage failed[%d < level2_blks]\n", lblk);
                goto out;
            }
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[lblk - level1_blks]);
            f2fs_put_page(dn_ipage, 1);
            dn_ipage = NULL;
            // pr_info("blkaddr %u, lblk - level1_blks (%u - %u = %u)\n",blkaddr,lblk,level1_blks,lblk - level1_blks);
            // pr_info("direct_index [%u]\n",direct_index);
            if (__is_valid_data_blkaddr(blkaddr)) {
                // if(check_sit_mulref_entry(sbi, blkaddr)){
                //     pr_info("level2_blks [%u] is mulref\n",lblk);
                // }
                // 开始set mulref flag
                // pr_info("level2_blks lblk %u node id %u, addr %u\n",lblk,nid,blkaddr);
                if (snapfs_progress_bit_done(&progress, src_ino, inode->i_ino,
					      nid, 2, ADDRS_PER_BLOCK(inode),
					      lblk - level1_blks))
                    continue;
                ret = snapfs_progress_switch_group(sbi, &progress, src_ino,
					inode->i_ino, nid, 2,
					ADDRS_PER_BLOCK(inode));
                if (ret)
                    goto out;
                ret = set_mulref_entry(sbi, blkaddr, nid, src_ino, &progress,
					  lblk - level1_blks);
                if(ret){
                    pr_err("[snapfs cow22]: debug setmulref failed![level2_blks]\n");
                    // f2fs_put_page(dn_ipage, 1);
                    goto out;
                    // return ret;
                }
            }
            // if(lblk == max_lblk - 1){
            //     pr_info("lblk[%u] level2_blks end blkaddr %u\n",lblk,blkaddr);  
            // }
            continue;
            
        }else if(lblk < level3_blks){//1039233
            // nid = le32_to_cpu(fi->i_nid[2]);
            nid = i_nid[2];
            /* 防御性检查：验证 indirect node nid 范围 */
            if (nid >= NM_I(sbi)->max_nid) {
                pr_err("[snapfs cow22]: level3 invalid indirect nid=%u (max_nid=%u), skipping lblk=%lu\n",
                       nid, NM_I(sbi)->max_nid, (unsigned long)lblk);
                continue;
            }
            if(nid == 0) {
                pr_info("level3_blks lblk %u node id is 0\n",lblk);
                continue;
            }
            // if(SNAPFS_DEBUG) pr_info("------------------level3_blks------------------\n");
            indirect_page = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(indirect_page)){
                pr_err("[snapfs setmulref]: get indirect_page failed[%d < level3_blks]\n", lblk);
                goto out;
                // return PTR_ERR(indirect_page);
            }
            // pr_info("level3_blks tp1? nid[%u]\n",nid);
            in_dn = (lblk - level2_blks) / direct_blks;
            off_in_dn = (lblk - level2_blks) % direct_blks;
            indirect = (struct indirect_node *)page_address(indirect_page);
            nid = le32_to_cpu(indirect->nid[in_dn]);
            /* DEBUG: 打印读取到的 child nid */
            pr_err("[snapfs cow22]: level3_blks lblk=%lu, indirect_nid=%u, child_nid=%u, max_nid=%u\n",
                   (unsigned long)lblk, i_nid[2], nid, NM_I(sbi)->max_nid);
            if(nid == 0){
                f2fs_put_page(indirect_page, 1);
                indirect_page = NULL;
                continue;
            }
            // pr_info("nid[%u],indirect[%u], in_dn[%u],off_in_dn[%u]\n ",nid,indirect,in_dn,off_in_dn);
            /* 防御性检查：在调用 f2fs_get_node_page 之前验证 nid */
            if (nid >= NM_I(sbi)->max_nid) {
                pr_err("[snapfs cow22]: level3 invalid child nid=%u (max_nid=%u), skipping\n",
                       nid, NM_I(sbi)->max_nid);
                f2fs_put_page(indirect_page, 1);
                indirect_page = NULL;
                continue;
            }
            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) {
                pr_err("[snapfs cow22]: debug setmulref get dn_ipage failed[%d < level3_blks], nid=%u\n", lblk, nid);
                f2fs_put_page(indirect_page, 1);
                goto out;
            }
            // pr_info("level3_blks tp2?\n");
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[off_in_dn]);
            f2fs_put_page(dn_ipage, 1);
            f2fs_put_page(indirect_page, 1);
            // if(SNAPFS_DEBUG) {
            //     pr_info("blkaddr %u, lblk - level2_blks (%u - %u = %u)\n",blkaddr,lblk,level2_blks,lblk - level2_blks);
            //     pr_info("direct_index [%u]\n",direct_index);
            //     pr_info("level1_blks [%u]\n",level1_blks);
            // }
            if (__is_valid_data_blkaddr(blkaddr)) {
                // 开始set mulref flag
                // if(check_sit_mulref_entry(sbi, blkaddr)){
                //     pr_info("level3_blks [%u] is mulref\n",lblk);
                // }
                // pr_info("level3_blks lblk %u node id %u addr %u\n",lblk,nid,blkaddr);
                if (snapfs_progress_bit_done(&progress, src_ino, inode->i_ino,
					      nid, 3 + in_dn, ADDRS_PER_BLOCK(inode),
					      off_in_dn))
                    continue;
                ret = snapfs_progress_switch_group(sbi, &progress, src_ino,
					inode->i_ino, nid, 3 + in_dn,
					ADDRS_PER_BLOCK(inode));
                if (ret)
                    goto out;
                ret = set_mulref_entry(sbi, blkaddr, nid, src_ino, &progress,
					  off_in_dn);
                if(ret){
                    pr_err("[snapfs cow22]: debug setmulref failed![level3_blks]\n");
                    goto out;
                    // return ret;
                }
            }
            // if(lblk == max_lblk - 1){
            //     pr_info("lblk[%u] level3_blks end blkaddr %u\n",lblk,blkaddr);  
            // }
            continue;
            // f2fs_put_page(dn_ipage, 1);
            // f2fs_put_page(indirect_page, 1);
        }else if(lblk < level4_blks){
            // nid = le32_to_cpu(fi->i_nid[3]);
            nid = i_nid[3];
            /* 防御性检查：验证 indirect node nid 范围 */
            if (nid >= NM_I(sbi)->max_nid) {
                pr_err("[snapfs cow22]: level4 invalid indirect nid=%u (max_nid=%u), skipping lblk=%lu\n",
                       nid, NM_I(sbi)->max_nid, (unsigned long)lblk);
                continue;
            }
            if(nid == 0) continue; 
            // if(SNAPFS_DEBUG) pr_info("------------------level4_blks------------------\n");
            indirect_page = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(indirect_page)){
                pr_err("[snapfs cow22]: debug setmulref get indirect_page failed[%d < level4_blks]\n", lblk);
                goto out;
                // return PTR_ERR(indirect_page);
            }
            
            in_dn = (lblk - level3_blks) / direct_blks;
            off_in_dn = (lblk - level3_blks) % direct_blks;
            indirect = (struct indirect_node *)page_address(indirect_page);
            // pr_info("level4_blks indirect lblk %u node id %u addr %u\n",lblk,nid,le32_to_cpu(indirect->nid[in_dn]));
            nid = le32_to_cpu(indirect->nid[in_dn]);
            /* 防御性检查：在调用 f2fs_get_node_page 之前验证 nid */
            if (nid >= NM_I(sbi)->max_nid) {
                pr_err("[snapfs cow22]: level4 invalid child nid=%u (max_nid=%u), skipping\n",
                       nid, NM_I(sbi)->max_nid);
                f2fs_put_page(indirect_page, 1);
                indirect_page = NULL;
                continue;
            }
            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) {
                pr_err("[snapfs cow22]: debug setmulref get dn_ipage failed[%d < level3_blks]\n", lblk);
                f2fs_put_page(indirect_page, 1);
                goto out;
            }
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[off_in_dn]);
            f2fs_put_page(dn_ipage, 1);
            f2fs_put_page(indirect_page, 1);
            // pr_info("blkaddr %u, lblk - level3_blks (%u - %u = %u)\n",blkaddr,lblk,level3_blks,lblk - level3_blks);
            // pr_info("direct_index [%u]\n",direct_index);
            // pr_info("level1_blks [%u]\n",level1_blks);
            // pr_info("level2_blks [%u]\n",level2_blks);
            if (__is_valid_data_blkaddr(blkaddr)) {
                // 开始set mulref flag
                // if(check_sit_mulref_entry(sbi, blkaddr)){
                //     pr_info("level4_blks [%u] is mulref\n",lblk);
                // }
                // pr_info("level4_blks lblk %u node id %u addr %u\n",lblk,nid,blkaddr);
                if (snapfs_progress_bit_done(&progress, src_ino, inode->i_ino,
					      nid, 1022 + in_dn, ADDRS_PER_BLOCK(inode),
					      off_in_dn))
                    continue;
                ret = snapfs_progress_switch_group(sbi, &progress, src_ino,
					inode->i_ino, nid, 1022 + in_dn,
					ADDRS_PER_BLOCK(inode));
                if (ret)
                    goto out;
                ret = set_mulref_entry(sbi, blkaddr, nid, src_ino, &progress,
					  off_in_dn);
                if(ret){
                    pr_err("[snapfs cow22]: debug setmulref failed![level4_blks]\n");
                    // f2fs_put_page(dn_ipage, 1);
                    // f2fs_put_page(indirect_page, 1);
                    goto out;
                    // return ret;
                }
            }
            // if(lblk == max_lblk - 1){
            //     pr_info("lblk[%u] level4_blks end blkaddr %u\n",lblk,blkaddr);  
            // }
            continue;
            // f2fs_put_page(dn_ipage, 1);
            // f2fs_put_page(indirect_page, 1);
        }else if(lblk < level5_blks){
            // nid = le32_to_cpu(fi->i_nid[4]);
            nid = i_nid[4];
            /* 防御性检查：验证 double indirect node nid 范围 */
            if (nid >= NM_I(sbi)->max_nid) {
                pr_err("[snapfs cow22]: level5 invalid indirect nid=%u (max_nid=%u), skipping lblk=%lu\n",
                       nid, NM_I(sbi)->max_nid, (unsigned long)lblk);
                continue;
            }
            if(nid == 0) continue;
            if(SNAPFS_DEBUG) pr_info("----level5_blks--nid %u-lblk %u-\n",nid,lblk);
            indirect_page = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(indirect_page)){
                pr_err("[snapfs cow22]: debug setmulref get indirect_page failed[%d < level5_blks]\n", lblk);
                goto out;
                // return PTR_ERR(indirect_page);
            }
            in_dn = (lblk - level4_blks) / double_dir_blk;
            off_in_dn = (lblk - level4_blks) % double_dir_blk;
            indirect = (struct indirect_node *)page_address(indirect_page);
            nid = le32_to_cpu(indirect->nid[in_dn]);
            f2fs_put_page(indirect_page, 1);
            indirect_page = NULL;
            /* 防御性检查：验证从 indirect node 读取的 nid */
            if (nid == 0) {
                // indirect_page 已经释放，不要重复释放
                continue;
            }
            if (nid >= NM_I(sbi)->max_nid) {
                pr_err("[snapfs cow22]: level5 invalid indirect nid=%u (max_nid=%u), skipping\n",
                       nid, NM_I(sbi)->max_nid);
                continue;
            }
            indirect_page2 = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(indirect_page2)){
                pr_err("[snapfs cow22]: debug setmulref get indirect_page2 failed[%d < level5_blks]\n", lblk);
                // f2fs_put_page(indirect_page, 1);
                goto out;
                // return PTR_ERR(indirect_page);
            }
            in_dn2 = off_in_dn / direct_blks;
            off_in_dn2 = off_in_dn % direct_blks;
            indirect2 = (struct indirect_node *)page_address(indirect_page2);
            nid = le32_to_cpu(indirect2->nid[in_dn2]);
            f2fs_put_page(indirect_page2, 1);
            indirect_page2 = NULL;
            /* 防御性检查：验证从 indirect2 node 读取的 child nid */
            if (nid == 0) {
                // indirect_page2 已经释放，不要重复释放
                continue;
            }
            if (nid >= NM_I(sbi)->max_nid) {
                pr_err("[snapfs cow22]: level5 invalid child nid=%u (max_nid=%u), skipping\n",
                       nid, NM_I(sbi)->max_nid);
                continue;
            }
            // pr_info("Tp 3 indirect2 [%u]\n",indirect2);
            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) {
                pr_err("[snapfs cow22]: debug setmulref get dn_ipage failed[%d < level3_blks]\n", lblk);
                goto out;
            }
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[off_in_dn2]);
            f2fs_put_page(dn_ipage, 1);
            dn_ipage = NULL;
            if (__is_valid_data_blkaddr(blkaddr)) {
                // 开始set mulref flag
                // if(check_sit_mulref_entry(sbi, blkaddr)){
                //     pr_info("level5_blks [%u] is mulref ,with blkaddr %u\n",lblk, blkaddr);
                // }
                // pr_info("level5_blks lblk %u node id %u addr %u\n",lblk,nid,blkaddr);
                if (snapfs_progress_bit_done(&progress, src_ino, inode->i_ino,
					      nid, 2041 + in_dn * direct_blks + in_dn2,
					      ADDRS_PER_BLOCK(inode), off_in_dn2))
                    continue;
                ret = snapfs_progress_switch_group(sbi, &progress, src_ino,
					inode->i_ino, nid, 2041 + in_dn * direct_blks + in_dn2,
					ADDRS_PER_BLOCK(inode));
                if (ret)
                    goto out;
                ret = set_mulref_entry(sbi, blkaddr, nid, src_ino, &progress,
					  off_in_dn2);
                if(ret){
                    pr_err("[snapfs cow22]: debug setmulref failed![level5_blks]\n");
                    goto out;
                    // return ret;
                }
            }
            if(lblk == max_lblk - 1){
                // pr_info("lblk[%u] level5_blks end blkaddr %u\n",lblk,blkaddr);  
            }
            continue;
        }
    }
    // pr_info("lblk final: %u, max_lblk %u\n",lblk,max_lblk);
out_skip_progress:
    if(ipage){
        f2fs_put_page(ipage, 1);
        ipage = NULL;
    }
    if(i_addr){
        kfree(i_addr);
    }
    return ret;

out:
    // f2fs_put_page(ipage, 1);
    if(ipage){
        f2fs_put_page(ipage, 1);
        ipage = NULL;
    }
    if(i_addr){
        kfree(i_addr);
    }
    if (!ret)
        ret = snapfs_progress_finish(sbi, &progress);
    return ret;
}

int f2fs_set_mulref_blocks(struct inode *inode, u32 src_ino)
{
    pr_info("[snapfs mulref] f2fs_set_mulref_blocks ENTER: inode=%u, src_ino=%u\n",
            inode->i_ino, src_ino);
    return __f2fs_set_mulref_blocks(inode, src_ino, NULL);
}

static int snapfs_resume_cow_slot(struct f2fs_sb_info *sbi, u32 slot_idx)
{
    struct page *page;
    struct snap_redo_slot *slot;
    struct snapfs_cow_progress progress;
    struct inode *snap_inode = NULL;
    int ret;

    page = f2fs_get_meta_page(sbi, snapfs_redo_slot_blkaddr(sbi, slot_idx));
    if (IS_ERR(page))
        return PTR_ERR(page);

    slot = (struct snap_redo_slot *)page_address(page);
    if (!snapfs_redo_slot_valid(slot) ||
        slot->record_type == SNAPFS_REDO_REC_OVERWRITE ||
        (le16_to_cpu(slot->state) != SNAPFS_PROGRESS_GROUP_IN_PROGRESS &&
         le16_to_cpu(slot->state) != SNAPFS_PROGRESS_BLOCK_TXN_COMMITTED)) {
        f2fs_put_page(page, 1);
        return -ENOENT;
    }

    if (le16_to_cpu(slot->state) == SNAPFS_PROGRESS_BLOCK_TXN_COMMITTED) {
        ret = snapfs_replay_slot(sbi, slot_idx, slot, true);
        if (ret) {
            f2fs_put_page(page, 1);
            return ret;
        }
        f2fs_put_page(page, 1);
        page = f2fs_get_meta_page(sbi, snapfs_redo_slot_blkaddr(sbi, slot_idx));
        if (IS_ERR(page))
            return PTR_ERR(page);
        slot = (struct snap_redo_slot *)page_address(page);
        if (!snapfs_redo_slot_valid(slot) ||
            slot->record_type == SNAPFS_REDO_REC_OVERWRITE ||
            le16_to_cpu(slot->state) != SNAPFS_PROGRESS_GROUP_IN_PROGRESS) {
            f2fs_put_page(page, 1);
            return -ENOENT;
        }
    }

    snapfs_progress_from_slot(&progress, slot, slot_idx);
    f2fs_put_page(page, 1);

    snap_inode = f2fs_iget(sbi->sb, le32_to_cpu(progress.snap_ino));
    if (IS_ERR(snap_inode))
        return PTR_ERR(snap_inode);

    inode_lock(snap_inode);
    ret = __f2fs_set_mulref_blocks(snap_inode,
            le32_to_cpu(progress.src_ino), &progress);
    inode_unlock(snap_inode);
    iput(snap_inode);
    return ret;
}

int snapfs_resume_all_cow_slots(struct f2fs_sb_info *sbi)
{
    struct snap_redo_info *redo;
    u32 i;
    int ret;

    if (!sbi->magic_info || !sbi->magic_info->redo_info)
        return -EINVAL;

    redo = sbi->magic_info->redo_info;
    for (i = 0; i < redo->cow_nr_slots; i++) {
        ret = snapfs_resume_cow_slot(sbi, i);
        if (ret == -ENOENT)
            continue;
        if (ret)
            return ret;
    }

    return 0;
}

int snapfs_resume_cow_from_slot(struct f2fs_sb_info *sbi, u32 snap_ino)
{
    u32 slot_idx;
    int ret;

    if (!sbi->magic_info || !sbi->magic_info->redo_info)
        return -EINVAL;
    ret = snapfs_redo_find_slot_by_snap(sbi, snap_ino, &slot_idx);
    if (ret)
        return ret;

    return snapfs_resume_cow_slot(sbi, slot_idx);
}

/*
 * f2fs_dir_has_mulref_dentry - 检查目录的 dentry block 是否有 mulref
 * @dir: 目录 inode
 *
 * 遍历目录的所有 dentry block，检查是否有任何块被标记为 mulref。
 * 如果有，说明该目录被其他快照引用，不能直接删除。
 *
 * 返回: true - 有 mulref（被其他快照引用）
 *       false - 没有 mulref（可以安全删除）
 */
bool f2fs_dir_has_mulref_dentry(struct inode *dir)
{
    struct f2fs_sb_info *sbi = F2FS_I_SB(dir);
    loff_t isize;
    pgoff_t lblk, max_lblk;
    unsigned int blkbits;
    struct f2fs_inode *fi;
    struct page *ipage = NULL;
    struct page *dn_ipage = NULL;
    nid_t nid = 0;
    block_t blkaddr = 0;
    struct direct_node *dn;
    u32 i_nid[5];
    struct page *indirect_page = NULL;
    struct indirect_node *indirect;
    struct page *indirect_page2 = NULL;
    struct indirect_node *indirect2;
    long in_dn = 0;
    long in_dn2 = 0;
    long off_in_dn = 0;
    long off_in_dn2 = 0;
    bool has_mulref = false;

    const long direct_index = ADDRS_PER_INODE(dir);
    const long direct_blks = ADDRS_PER_BLOCK(dir);
    const long level1_blks = direct_index + direct_blks;
    const long level2_blks = level1_blks + direct_blks;
    const long level3_blks = level2_blks + direct_blks * direct_blks;
    const long level4_blks = level3_blks + direct_blks * direct_blks;
    const long level5_blks = level4_blks + direct_blks * direct_blks * direct_blks;
    const long double_dir_blk = direct_blks * direct_blks;

    /* inline dentry 存储在 inode page 中，不涉及数据块 mulref */
    if (f2fs_has_inline_dentry(dir))
        return false;

    ipage = f2fs_get_node_page(sbi, dir->i_ino);
    if (IS_ERR(ipage)) {
        pr_err("[snapfs del_snap]: failed to get inode page[%lu]\n", dir->i_ino);
        /* 出错时保守返回 true，阻止删除 */
        return true;
    }

    fi = F2FS_INODE(ipage);
    isize = le64_to_cpu(fi->i_size);
    blkbits = dir->i_blkbits;
    max_lblk = (isize + (1ULL << blkbits) - 1) >> blkbits;

    i_nid[0] = le32_to_cpu(fi->i_nid[0]);
    i_nid[1] = le32_to_cpu(fi->i_nid[1]);
    i_nid[2] = le32_to_cpu(fi->i_nid[2]);
    i_nid[3] = le32_to_cpu(fi->i_nid[3]);
    i_nid[4] = le32_to_cpu(fi->i_nid[4]);

    for (lblk = 0; lblk < max_lblk; lblk++) {
        blkaddr = 0;

        if (lblk < direct_index) {
            /* direct blocks */
            blkaddr = le32_to_cpu(fi->i_addr[lblk]);
        } else if (lblk < (pgoff_t)level1_blks) {
            /* level 1 indirect */
            if (ipage) {
                f2fs_put_page(ipage, 1);
                ipage = NULL;
            }
            nid = i_nid[0];
            if (nid == 0) continue;

            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) {
                has_mulref = true;
                goto out;
            }
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[lblk - direct_index]);
            f2fs_put_page(dn_ipage, 1);
            dn_ipage = NULL;
        } else if (lblk < (pgoff_t)level2_blks) {
            /* level 2 indirect */
            nid = i_nid[1];
            if (nid == 0) continue;

            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) {
                has_mulref = true;
                goto out;
            }
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[lblk - level1_blks]);
            f2fs_put_page(dn_ipage, 1);
            dn_ipage = NULL;
        } else if (lblk < level3_blks) {
            /* level 3 indirect */
            nid = i_nid[2];
            if (nid == 0) continue;

            indirect_page = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(indirect_page)) {
                has_mulref = true;
                goto out;
            }

            in_dn = (lblk - level2_blks) / direct_blks;
            off_in_dn = (lblk - level2_blks) % direct_blks;
            indirect = (struct indirect_node *)page_address(indirect_page);
            nid = le32_to_cpu(indirect->nid[in_dn]);
            f2fs_put_page(indirect_page, 1);
            indirect_page = NULL;

            if (nid == 0) continue;

            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) {
                has_mulref = true;
                goto out;
            }
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[off_in_dn]);
            f2fs_put_page(dn_ipage, 1);
            dn_ipage = NULL;
        } else if (lblk < level4_blks) {
            /* level 4 indirect */
            nid = i_nid[3];
            if (nid == 0) continue;

            indirect_page = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(indirect_page)) {
                has_mulref = true;
                goto out;
            }

            in_dn = (lblk - level3_blks) / direct_blks;
            off_in_dn = (lblk - level3_blks) % direct_blks;
            indirect = (struct indirect_node *)page_address(indirect_page);
            nid = le32_to_cpu(indirect->nid[in_dn]);
            f2fs_put_page(indirect_page, 1);
            indirect_page = NULL;

            if (nid == 0) continue;

            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) {
                has_mulref = true;
                goto out;
            }
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[off_in_dn]);
            f2fs_put_page(dn_ipage, 1);
            dn_ipage = NULL;
        } else if (lblk < level5_blks) {
            /* level 5 indirect (double indirect) */
            nid = i_nid[4];
            if (nid == 0) continue;

            indirect_page = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(indirect_page)) {
                has_mulref = true;
                goto out;
            }

            in_dn = (lblk - level4_blks) / double_dir_blk;
            off_in_dn = (lblk - level4_blks) % double_dir_blk;
            indirect = (struct indirect_node *)page_address(indirect_page);
            nid = le32_to_cpu(indirect->nid[in_dn]);
            f2fs_put_page(indirect_page, 1);
            indirect_page = NULL;

            if (nid == 0) continue;

            indirect_page2 = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(indirect_page2)) {
                has_mulref = true;
                goto out;
            }

            in_dn2 = off_in_dn / direct_blks;
            off_in_dn2 = off_in_dn % direct_blks;
            indirect2 = (struct indirect_node *)page_address(indirect_page2);
            nid = le32_to_cpu(indirect2->nid[in_dn2]);
            f2fs_put_page(indirect_page2, 1);
            indirect_page2 = NULL;

            if (nid == 0) continue;

            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) {
                has_mulref = true;
                goto out;
            }
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[off_in_dn2]);
            f2fs_put_page(dn_ipage, 1);
            dn_ipage = NULL;
        }

        /* 检查 mulref */
        if (__is_valid_data_blkaddr(blkaddr)) {
            if (check_sit_mulref_entry(sbi, blkaddr)) {
                pr_info("[snapfs del_snap]: dir %lu has mulref dentry block at lblk %lu, blkaddr %u\n",
                        dir->i_ino, lblk, blkaddr);
                has_mulref = true;
                goto out;
            }
        }
    }

out:
    if (ipage)
        f2fs_put_page(ipage, 1);
    if (dn_ipage)
        f2fs_put_page(dn_ipage, 1);
    if (indirect_page)
        f2fs_put_page(indirect_page, 1);
    if (indirect_page2)
        f2fs_put_page(indirect_page2, 1);

    return has_mulref;
}

/*
 * f2fs clear mulref blocks - 清除快照 inode 所有数据块的 mulref 引用
 * @inode: 快照 inode
 *
 * 遍历快照 inode 的所有数据块，对每个有 mulref 的块调用 f2fs mulref overwrite
 * 来减少引用计数。这是 f2fs_set_mulref_blocks 的逆操作。
 */
int f2fs_clear_mulref_blocks(struct inode *inode)
{
    struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
    loff_t isize;
    pgoff_t lblk, max_lblk;
    unsigned int blkbits;
    struct f2fs_inode *fi;
    struct page *ipage = NULL;
    struct page *dn_ipage = NULL;
    nid_t nid = 0;
    block_t blkaddr = 0;
    struct direct_node *dn;
    u32 i_nid[5];
    struct page *indirect_page = NULL;
    struct indirect_node *indirect;
    struct page *indirect_page2 = NULL;
    struct indirect_node *indirect2;
    long in_dn = 0;
    long in_dn2 = 0;
    long off_in_dn = 0;
    long off_in_dn2 = 0;
    int ret = 0;
    int cleared_count = 0;

    const long direct_index = ADDRS_PER_INODE(inode);
    const long direct_blks = ADDRS_PER_BLOCK(inode);
    const long level1_blks = direct_index + direct_blks;
    const long level2_blks = level1_blks + direct_blks;
    const long level3_blks = level2_blks + direct_blks * direct_blks;
    const long level4_blks = level3_blks + direct_blks * direct_blks;
    const long level5_blks = level4_blks + direct_blks * direct_blks * direct_blks;
    const long double_dir_blk = direct_blks * direct_blks;

    pr_info("[snapfs del_snap]: clearing mulref blocks for inode %lu\n", inode->i_ino);

    if (f2fs_is_empty_file(sbi, inode)) {
        pr_info("[snapfs del_snap]: empty file, no mulref to clear\n");
        return 0;
    }

    ipage = f2fs_get_node_page(sbi, inode->i_ino);
    if (IS_ERR(ipage)) {
        pr_err("[snapfs del_snap]: failed to get inode page[%lu]\n", inode->i_ino);
        return PTR_ERR(ipage);
    }

    fi = F2FS_INODE(ipage);
    isize = le64_to_cpu(fi->i_size);
    blkbits = inode->i_blkbits;
    max_lblk = (isize + (1ULL << blkbits) - 1) >> blkbits;

    i_nid[0] = le32_to_cpu(fi->i_nid[0]);
    i_nid[1] = le32_to_cpu(fi->i_nid[1]);
    i_nid[2] = le32_to_cpu(fi->i_nid[2]);
    i_nid[3] = le32_to_cpu(fi->i_nid[3]);
    i_nid[4] = le32_to_cpu(fi->i_nid[4]);

    pr_info("[snapfs del_snap]: processing %lu blocks\n", max_lblk);

    for (lblk = 0; lblk < max_lblk; lblk++) {
        blkaddr = 0;
        nid = 0;

        if (lblk < direct_index) {
            /* direct blocks */
            blkaddr = le32_to_cpu(fi->i_addr[lblk]);
            nid = inode->i_ino;
        } else if (lblk < (pgoff_t)level1_blks) {
            /* level 1 indirect */
            if (ipage) {
                f2fs_put_page(ipage, 1);
                ipage = NULL;
            }
            nid = i_nid[0];
            if (nid == 0) continue;

            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) {
                pr_err("[snapfs del_snap]: failed to get dn_ipage\n");
                goto out;
            }
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[lblk - direct_index]);
            f2fs_put_page(dn_ipage, 1);
            dn_ipage = NULL;
        } else if (lblk < (pgoff_t)level2_blks) {
            /* level 2 indirect */
            nid = i_nid[1];
            if (nid == 0) continue;

            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) goto out;
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[lblk - level1_blks]);
            f2fs_put_page(dn_ipage, 1);
            dn_ipage = NULL;
        } else if (lblk < level3_blks) {
            /* level 3 indirect */
            nid = i_nid[2];
            if (nid == 0) continue;

            indirect_page = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(indirect_page)) goto out;

            in_dn = (lblk - level2_blks) / direct_blks;
            off_in_dn = (lblk - level2_blks) % direct_blks;
            indirect = (struct indirect_node *)page_address(indirect_page);
            nid = le32_to_cpu(indirect->nid[in_dn]);
            f2fs_put_page(indirect_page, 1);
            indirect_page = NULL;

            if (nid == 0) continue;

            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) goto out;
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[off_in_dn]);
            f2fs_put_page(dn_ipage, 1);
            dn_ipage = NULL;
        } else if (lblk < level4_blks) {
            /* level 4 indirect */
            nid = i_nid[3];
            if (nid == 0) continue;

            indirect_page = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(indirect_page)) goto out;

            in_dn = (lblk - level3_blks) / direct_blks;
            off_in_dn = (lblk - level3_blks) % direct_blks;
            indirect = (struct indirect_node *)page_address(indirect_page);
            nid = le32_to_cpu(indirect->nid[in_dn]);
            f2fs_put_page(indirect_page, 1);
            indirect_page = NULL;

            if (nid == 0) continue;

            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) goto out;
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[off_in_dn]);
            f2fs_put_page(dn_ipage, 1);
            dn_ipage = NULL;
        } else if (lblk < level5_blks) {
            /* level 5 indirect (double indirect) */
            nid = i_nid[4];
            if (nid == 0) continue;

            indirect_page = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(indirect_page)) goto out;

            in_dn = (lblk - level4_blks) / double_dir_blk;
            off_in_dn = (lblk - level4_blks) % double_dir_blk;
            indirect = (struct indirect_node *)page_address(indirect_page);
            nid = le32_to_cpu(indirect->nid[in_dn]);
            f2fs_put_page(indirect_page, 1);
            indirect_page = NULL;

            if (nid == 0) continue;

            indirect_page2 = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(indirect_page2)) goto out;

            in_dn2 = off_in_dn / direct_blks;
            off_in_dn2 = off_in_dn % direct_blks;
            indirect2 = (struct indirect_node *)page_address(indirect_page2);
            nid = le32_to_cpu(indirect2->nid[in_dn2]);
            f2fs_put_page(indirect_page2, 1);
            indirect_page2 = NULL;

            if (nid == 0) continue;

            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) goto out;
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[off_in_dn2]);
            f2fs_put_page(dn_ipage, 1);
            dn_ipage = NULL;
        }

        /* 检查并清除 mulref */
        if (__is_valid_data_blkaddr(blkaddr)) {
            if (check_sit_mulref_entry(sbi, blkaddr)) {
                ret = f2fs_mulref_overwrite(sbi, blkaddr, nid);
                if (ret == 0) {
                    cleared_count++;
                } else if (ret == 1) {
                    /* entry not found, skip */
                    pr_info("[snapfs del_snap]: mulref entry not found for blk %u, nid %u\n", blkaddr, nid);
                    ret = 0;
                } else if (ret < 0) {
                    pr_err("[snapfs del_snap]: failed to clear mulref for blk %u, err=%d\n", blkaddr, ret);
                }
            }
        }
    }

    pr_info("[snapfs del_snap]: cleared %d mulref blocks\n", cleared_count);

out:
    if (ipage)
        f2fs_put_page(ipage, 1);
    if (dn_ipage)
        f2fs_put_page(dn_ipage, 1);
    if (indirect_page)
        f2fs_put_page(indirect_page, 1);
    if (indirect_page2)
        f2fs_put_page(indirect_page2, 1);

    return ret < 0 ? ret : 0;
}

/*
 * f2fs_delete_snap_inode - 删除单个快照 inode（文件或空目录）
 * @dir: 父目录 inode
 * @inode: 要删除的 inode
 * @name: 文件名
 * @name_len: 文件名长度
 *
 * 清除 mulref 并删除目录项
 */
static int f2fs_delete_snap_inode(struct inode *dir, struct inode *inode,
                                   const unsigned char *name, int name_len)
{
    struct f2fs_sb_info *sbi = F2FS_I_SB(dir);
    struct f2fs_dir_entry *de;
    struct page *page = NULL;
    struct qstr qname;
    int err = 0;

    qname.name = name;
    qname.len = name_len;

    pr_info("[snapfs del_snap]: deleting inode %lu, name=%.*s\n",
            inode->i_ino, name_len, name);

    /* 清除 mulref（仅对普通文件） */
    if (S_ISREG(inode->i_mode)) {
        err = f2fs_clear_mulref_blocks(inode);
        if (err) {
            pr_err("[snapfs del_snap]: failed to clear mulref for ino %lu\n", inode->i_ino);
            err = 0; /* 继续删除 */
        }
    }

    /* 初始化 dquot */
    err = f2fs_dquot_initialize(dir);
    if (err)
        return err;
    err = f2fs_dquot_initialize(inode);
    if (err)
        return err;

    /* 查找目录项 */
    de = f2fs_find_entry(dir, &qname, &page);
    if (!de) {
        if (IS_ERR(page))
            return PTR_ERR(page);
        return -ENOENT;
    }

    f2fs_balance_fs(sbi, true);

    f2fs_lock_op(sbi);

    err = f2fs_acquire_orphan_inode(sbi);
    if (err) {
        f2fs_unlock_op(sbi);
        f2fs_put_page(page, 0);
        return err;
    }

    f2fs_delete_entry(de, page, dir, inode);

    f2fs_unlock_op(sbi);

    return 0;
}

/*
 * f2fs_delete_snap_dir_recursive - 递归删除快照目录
 * @dir: 要删除的目录 inode
 *
 * 遍历目录中的所有条目，递归删除子目录，删除文件
 */
int f2fs_delete_snap_dir_recursive(struct inode *dir)
{
    struct f2fs_sb_info *sbi = F2FS_I_SB(dir);
    unsigned long bidx;
    struct page *dentry_page;
    unsigned int bit_pos;
    struct f2fs_dentry_block *dentry_blk;
    unsigned long nblock;
    struct f2fs_dir_entry *de;
    struct inode *child_inode;
    int err = 0;
    int slots;

    /* 处理 inline dentry */
    if (f2fs_has_inline_dentry(dir)) {
        struct page *ipage;
        void *inline_dentry;
        struct f2fs_dentry_ptr d;

        ipage = f2fs_get_node_page(sbi, dir->i_ino);
        if (IS_ERR(ipage))
            return PTR_ERR(ipage);

        inline_dentry = inline_data_addr(dir, ipage);
        make_dentry_ptr_inline(dir, &d, inline_dentry);

        bit_pos = 2; /* 跳过 . 和 .. */
        while (bit_pos < d.max) {
            bit_pos = find_next_bit_le(d.bitmap, d.max, bit_pos);
            if (bit_pos >= d.max)
                break;

            de = &d.dentry[bit_pos];
            if (de->name_len == 0) {
                bit_pos++;
                continue;
            }

            child_inode = f2fs_iget(sbi->sb, le32_to_cpu(de->ino));
            if (IS_ERR(child_inode)) {
                pr_err("[snapfs del_snap]: failed to get child inode %u\n",
                       le32_to_cpu(de->ino));
                bit_pos += GET_DENTRY_SLOTS(le16_to_cpu(de->name_len));
                continue;
            }

            f2fs_put_page(ipage, 1);

            if (S_ISDIR(child_inode->i_mode)) {
                /* 递归删除子目录 */
                err = f2fs_delete_snap_dir_recursive(child_inode);
                if (err) {
                    iput(child_inode);
                    return err;
                }
            }

            /* 删除这个 inode */
            err = f2fs_delete_snap_inode(dir, child_inode, d.filename[bit_pos],
                                         le16_to_cpu(de->name_len));
            iput(child_inode);

            if (err) {
                pr_err("[snapfs del_snap]: failed to delete child inode\n");
                return err;
            }

            /* 重新获取 ipage，因为目录可能已经改变 */
            ipage = f2fs_get_node_page(sbi, dir->i_ino);
            if (IS_ERR(ipage))
                return PTR_ERR(ipage);

            inline_dentry = inline_data_addr(dir, ipage);
            make_dentry_ptr_inline(dir, &d, inline_dentry);

            bit_pos = 2; /* 从头开始，因为目录已改变 */
        }

        f2fs_put_page(ipage, 1);
        return 0;
    }

    /* 处理普通 dentry block */
restart:
    nblock = ((unsigned long long)(i_size_read(dir) + PAGE_SIZE - 1)) >> PAGE_SHIFT;
    for (bidx = 0; bidx < nblock; bidx++) {
        dentry_page = f2fs_get_lock_data_page(dir, bidx, false);
        if (IS_ERR(dentry_page)) {
            if (PTR_ERR(dentry_page) == -ENOENT)
                continue;
            return PTR_ERR(dentry_page);
        }

        dentry_blk = page_address(dentry_page);
        bit_pos = (bidx == 0) ? 2 : 0; /* 第一个块跳过 . 和 .. */

        while (bit_pos < NR_DENTRY_IN_BLOCK) {
            bit_pos = find_next_bit_le(&dentry_blk->dentry_bitmap,
                                       NR_DENTRY_IN_BLOCK, bit_pos);
            if (bit_pos >= NR_DENTRY_IN_BLOCK)
                break;

            de = &dentry_blk->dentry[bit_pos];
            if (de->name_len == 0) {
                bit_pos++;
                continue;
            }

            child_inode = f2fs_iget(sbi->sb, le32_to_cpu(de->ino));
            if (IS_ERR(child_inode)) {
                pr_err("[snapfs del_snap]: failed to get child inode %u\n",
                       le32_to_cpu(de->ino));
                slots = GET_DENTRY_SLOTS(le16_to_cpu(de->name_len));
                bit_pos += slots;
                continue;
            }

            f2fs_put_page(dentry_page, 1);

            if (S_ISDIR(child_inode->i_mode)) {
                /* 递归删除子目录 */
                err = f2fs_delete_snap_dir_recursive(child_inode);
                if (err) {
                    iput(child_inode);
                    return err;
                }
            }

            /* 删除这个 inode */
            err = f2fs_delete_snap_inode(dir, child_inode,
                                         dentry_blk->filename[bit_pos],
                                         le16_to_cpu(de->name_len));
            iput(child_inode);

            if (err) {
                pr_err("[snapfs del_snap]: failed to delete child inode\n");
                return err;
            }

            /* 目录已改变，从头开始 */
            goto restart;
        }

        f2fs_put_page(dentry_page, 1);
    }

    return 0;
}


// /mnt/df/dir/*  快照df /mnt/snap/dir/*
// 原始df/dir、dir/* 就是pra_inode/son_inodes
// 快照snap/dir、dir/* 就是snap_inode/new_inode
// 两个dir inode不同
// 函数作用: 创建新的inode，共享旧数据块引用，即生成new_inode
int f2fs_cow(struct inode *pra_inode,
             struct inode *snap_inode,
             struct inode *son_inode,
             const char *old_name,
             unsigned int old_name_len,
             struct inode **new_inode){
    /* 调试日志：跟踪 f2fs_cow 调用 */
#if 0
    pr_err("[snapfs cow] ====== f2fs_cow ENTER ======\n");
    pr_err("[snapfs cow] pra_inode: ino=%u, snap_inode: ino=%u, son_inode: ino=%u, name=%.*s\n",
           pra_inode->i_ino, snap_inode->i_ino, son_inode->i_ino, old_name_len, old_name);
    pr_err("[snapfs cow] son_inode i_size=%llu, i_blocks=%lu\n",
           son_inode->i_size, son_inode->i_blocks);
#endif

    // 判断name of son_inode是否已经存在snap_inode下
    // struct dentry *snap_dentry = NULL, *son_dentry = NULL, *new_dentry = NULL;
    struct dentry *snap_dentry = NULL, *new_dentry = NULL;
    struct f2fs_dir_entry *de = NULL;
    struct page *page = NULL;
    struct super_block *sb = pra_inode->i_sb;
    struct inode *tmp_inode = NULL;
    umode_t mode;
    int ret = 0;
    // struct qstr *d_name = NULL;
    // char *filename;
    struct qstr d_name;
    char filename[F2FS_NAME_LEN];

    struct f2fs_sb_info *sbi = F2FS_I_SB(pra_inode);
    nid_t ino;
    struct page *son_ipage = NULL, *new_ipage = NULL, *new_dpage = NULL;
    void *page_addr;
	void *inline_dentry, *inline_dentry2; // inline数据
    
    struct f2fs_inode *son_fi = NULL, *new_fi = NULL;
    struct fscrypt_str dot = FSTR_INIT(".", 1);
	struct fscrypt_str dotdot = FSTR_INIT("..", 2);
	struct f2fs_dentry_ptr d;
    // 安全检查
    if (unlikely(f2fs_cp_error(sbi))) {
        ret = -EIO;
        goto next_free;
    }
    
    if (!f2fs_is_checkpoint_ready(sbi)) {
        ret = -ENOSPC;
        goto next_free;
    }

    // 初始化配额
    ret = f2fs_dquot_initialize(snap_inode);
    if (ret)
        goto next_free;

    // son_dentry = d_find_any_alias(son_inode);
    // if (!son_dentry)
	// 	goto next_free;

    snap_dentry = d_find_any_alias(snap_inode);
    if (!snap_dentry)
		goto next_free;
    // dget(son_dentry);
    // dget(snap_dentry);


    // d_name = &son_dentry->d_name;

    if (!old_name || !old_name_len || old_name_len >= F2FS_NAME_LEN) {
        ret = -EINVAL;
        goto next_free;
    }

    memcpy(filename, old_name, old_name_len);
    filename[old_name_len] = '\0';

    d_name.name = filename;
    d_name.len  = old_name_len;
    /*
    * 如果你这版内核的 f2fs_find_entry 依赖 qstr.hash，
    * 这里再补一行 hash 初始化；如果编译报错，再按你内核版本适配。
    *
    * d_name.hash = full_name_hash(NULL, d_name.name, d_name.len);
    */


    // de = f2fs_find_entry(snap_inode, d_name, &page);
    de = f2fs_find_entry(snap_inode, &d_name, &page);
    // pr_info("f2fs cow dump %s\n",d_name->name);
    // f2fs_dump_nonzero_sit_mulref_entries_simple(sbi);
    if(de){
        // 快照目录下对应的数据COW过, 那两个目录下的inode就不相等
        // 若没有cow，iget获得的就是son_inode
        tmp_inode = f2fs_iget(sb, le32_to_cpu(de->ino));
        if (IS_ERR(tmp_inode)) {
            ret = PTR_ERR(tmp_inode);
            tmp_inode = NULL;
            pr_info("fuck you baby!!!! ret %u\n",ret);
            goto next_free;
        }
        // if((le32_to_cpu(de->ino) != son_inode->i_ino) && (tmp_inode->i_size == son_inode->i_size)){
        if((le32_to_cpu(de->ino) != son_inode->i_ino)){
            if(SNAPFS_DEBUG) pr_info("[snapfs cow2]: file[%s] of snap[%lu] had cowed!!!\n",
                    filename, snap_inode->i_ino);
            *new_inode = tmp_inode;
            tmp_inode = NULL;
            // if (tmp_inode) {
            //     iput(tmp_inode);
            //     tmp_inode = NULL;
            // }
            page = NULL; 
            goto next_free;
        }
        // 快照目录下对应的数据没有COW过, 那两个目录下的inode就相等
        f2fs_delete_entry(de, page, snap_inode, NULL);
        page = NULL;
        // 准备创建dentry
        // 创建新的inode（使用son_inode的mode）
        mode = son_inode->i_mode;
        tmp_inode = snapfs_new_inode(snap_inode, mode);
        if (IS_ERR(tmp_inode)) {
            ret = PTR_ERR(tmp_inode);
            pr_err("[snapfs cow2]: failed to create new inode: %d\n", ret);
            goto next_free;
        }

        /* 复制 inode 扩展属性：i_projid 和 i_pino */
        F2FS_I(tmp_inode)->i_projid = F2FS_I(son_inode)->i_projid;
        F2FS_I(tmp_inode)->i_pino = F2FS_I(son_inode)->i_pino;

        if (!test_opt(sbi, DISABLE_EXT_IDENTIFY))
            // snapfs_set_file_temperature(sbi, tmp_inode, d_name->name);
            snapfs_set_file_temperature(sbi, tmp_inode, filename);
        /* 3. 初始化 inode 元数据 */
        // snapfs_set_compress_inode(sbi, tmp_inode, d_name->name);
        snapfs_set_compress_inode(sbi, tmp_inode, filename);
        // 设置inode操作
        if (S_ISREG(son_inode->i_mode)) {
            tmp_inode->i_op = &f2fs_file_inode_operations;
            tmp_inode->i_fop = &f2fs_file_operations;
            tmp_inode->i_mapping->a_ops = &f2fs_dblock_aops;
        } else if (S_ISDIR(son_inode->i_mode)) {
            tmp_inode->i_op = &f2fs_dir_inode_operations;
            tmp_inode->i_fop = &f2fs_dir_operations;
            tmp_inode->i_mapping->a_ops = &f2fs_dblock_aops;
            mapping_set_gfp_mask(tmp_inode->i_mapping, GFP_NOFS);
            set_inode_flag(tmp_inode, FI_INC_LINK);
        } else if (S_ISLNK(son_inode->i_mode)) {
            tmp_inode->i_op = &f2fs_symlink_inode_operations;
            tmp_inode->i_mapping->a_ops = &f2fs_dblock_aops;
        }

        ino = tmp_inode->i_ino;
        // filename = son_dentry->d_name.name;
        // 使用 d_alloc 直接创建 dentry，避免 lookup_one_len 对目录结构的依赖
        new_dentry = d_alloc(snap_dentry, &d_name);
        if (IS_ERR(new_dentry)) {
            ret = PTR_ERR(new_dentry);
            new_dentry = NULL;
            goto next_free;
        }
        f2fs_lock_op(sbi);
        /* 4. 在 snap_inode 下创建目录项 link */
        ret = f2fs_add_link(new_dentry, tmp_inode);
        if (ret) {
            f2fs_unlock_op(sbi);
              
            pr_err("[snapfs cow2]: failed to add link: %d\n", ret);
            goto next_free;
        }
        f2fs_unlock_op(sbi);
        f2fs_alloc_nid_done(sbi, ino);
	    d_instantiate_new(new_dentry, tmp_inode);

        if(SNAPFS_DEBUG) {
            struct dentry *snap_alias = d_find_any_alias(snap_inode);
            pr_info("[snapfs cow2]: dentry[%s/%u] found in [%s/%u], new[%s/%u]\n", 
                filename, le32_to_cpu(de->ino), 
                snap_alias ? snap_alias->d_name.name : "<?>",
                snap_inode->i_ino,
                new_dentry->d_name.name, tmp_inode->i_ino);
            if (snap_alias)
                dput(snap_alias);
        }
        // 复制inode的属性
        tmp_inode->i_atime = son_inode->i_atime;
        tmp_inode->i_mtime = son_inode->i_mtime;
        tmp_inode->i_ctime = son_inode->i_ctime;
        tmp_inode->i_uid = son_inode->i_uid;
        tmp_inode->i_gid = son_inode->i_gid;
        if (S_ISDIR(mode)) {
            // 目录的链接数：自身(.) + 父目录(..)
            inc_nlink(tmp_inode);
            // 父目录链接数增加
            inc_nlink(snap_inode);
            f2fs_mark_inode_dirty_sync(snap_inode, true);
        }
        // 创建的tmp_inode，需要从son_inode复制数据

        if(S_ISDIR(son_inode->i_mode)){
            if (f2fs_has_inline_dentry(son_inode)){
                if(SNAPFS_DEBUG) pr_info("[snapfs cow2]: subdir(%lu) with inline\n", son_inode->i_ino);
                set_inode_flag(tmp_inode, FI_INLINE_DENTRY);
                son_ipage = f2fs_get_node_page(sbi, son_inode->i_ino);
                if (IS_ERR(son_ipage)) {
                    pr_err("[snapfs cow2]: get src_page[%lu] failed\n", son_inode->i_ino);
                    goto next_free;
                }
                new_ipage = f2fs_get_node_page(sbi, tmp_inode->i_ino);
                if (IS_ERR(new_ipage)) {
                    pr_err("[snapfs cow2]: get snap page[%lu] failed\n", tmp_inode->i_ino);
                    f2fs_put_page(son_ipage, 1);
                    goto next_free;
                }
                inline_dentry = inline_data_addr(son_inode, son_ipage);
                inline_dentry2 = inline_data_addr(tmp_inode, new_ipage);
                f2fs_truncate_inline_inode(tmp_inode, new_ipage, 0);
                memcpy(inline_dentry2, inline_dentry, MAX_INLINE_DATA(son_inode));
                // 更新.和..
                make_dentry_ptr_inline(tmp_inode, &d, inline_dentry2);
                /* update dirent of "." */
                f2fs_update_dentry(tmp_inode->i_ino, tmp_inode->i_mode, &d, &dot, 0, 0);
                /* update dirent of ".." */
                f2fs_update_dentry(tmp_inode->i_ino, tmp_inode->i_mode, &d, &dotdot, 0, 1);
                tmp_inode->i_size = le64_to_cpu(F2FS_INODE(son_ipage)->i_size);
                set_page_dirty(new_ipage);
                f2fs_put_page(new_ipage, 1);
                f2fs_put_page(son_ipage, 1);
            } else{
                if(SNAPFS_DEBUG) pr_info("[snapfs cow2]: subdir(%lu) without inline\n", son_inode->i_ino);
            
                son_ipage = f2fs_get_node_page(sbi, son_inode->i_ino);
                if (IS_ERR(son_ipage)) {
                    pr_err("[snapfs cow2]: failed to get src page[%lu]\n", son_inode->i_ino);
                    goto next_free;
                }
                new_ipage = f2fs_get_node_page(sbi, tmp_inode->i_ino);
                if (IS_ERR(new_ipage)) {
                    pr_err("[snapfs cow2]: failed to get snap page[%lu]\n", tmp_inode->i_ino);
                    f2fs_put_page(son_ipage, 1);
                    goto next_free;
                }
                if (f2fs_has_inline_dentry(tmp_inode)) {
                    inline_dentry = inline_data_addr(tmp_inode, new_ipage);
                    // 执行convert， 主要是删除inline数据区域和清除inline flag
                    // f2fs_snap_inline_to_dirdata
                    ret = f2fs_snap_inline_to_dirents(tmp_inode, inline_dentry, new_ipage);
                    if(ret){
                        f2fs_put_page(son_ipage, 1);
                        f2fs_put_page(new_ipage, 1);
                        pr_info("[snapfs cow2]: convert inline failed\n");
                        goto next_free;
                    }
                }
                son_fi = F2FS_INODE(son_ipage);
                new_fi = F2FS_INODE(new_ipage);

                update_f2fs_inode(son_fi, new_fi);
                son_inode->i_size = le64_to_cpu(son_fi->i_size);
                tmp_inode->i_blocks = le64_to_cpu(son_fi->i_blocks);
                f2fs_cow_update_inode(son_inode, tmp_inode);

                set_page_dirty(new_ipage);
                f2fs_put_page(son_ipage, 1);
                f2fs_put_page(new_ipage, 1);

                /* 复制 node 树，为快照创建独立的间接节点 */
                ret = f2fs_cow_copy_all_nodes(son_inode, tmp_inode);
                if (ret) {
                    pr_err("[snapfs cow2]: failed to copy nodes for dir %lu\n", son_inode->i_ino);
                    goto next_free;
                }

                new_dpage = f2fs_get_lock_data_page(tmp_inode, 0, false);
                page_addr = page_address(new_dpage);
                make_dentry_ptr_block(tmp_inode, &d, page_addr);
                f2fs_update_dentry(tmp_inode->i_ino, tmp_inode->i_mode, &d, &dot, 0, 0);
                f2fs_update_dentry(tmp_inode->i_ino, tmp_inode->i_mode, &d, &dotdot, 0, 1);
                f2fs_put_page(new_dpage, 1);
            }
        }else if(S_ISREG(son_inode->i_mode)){
            if(f2fs_has_inline_data(son_inode)){
                if(SNAPFS_DEBUG) pr_info("[snapfs cow2]: subfile(%lu) with inline\n", son_inode->i_ino);
                set_inode_flag(tmp_inode, FI_INLINE_DATA);
                son_ipage = f2fs_get_node_page(sbi, son_inode->i_ino);
                new_ipage = f2fs_get_node_page(sbi, tmp_inode->i_ino);
                inline_dentry = inline_data_addr(son_inode, son_ipage);
                inline_dentry2 = inline_data_addr(tmp_inode, new_ipage);
                f2fs_truncate_inline_inode(tmp_inode, new_ipage, 0);
                memcpy(inline_dentry2, inline_dentry, MAX_INLINE_DATA(son_inode));
                tmp_inode->i_size = son_inode->i_size;
                set_page_dirty(new_ipage);
                f2fs_put_page(new_ipage, 1);
                f2fs_put_page(son_ipage, 1);
            } else{ // non inline process
                if(SNAPFS_DEBUG) pr_info("[snapfs cow2]: subfile(%lu) without inline\n", son_inode->i_ino);
                // set_inode_flag(tmp_inode, FI_INLINE_DATA);
                son_ipage = f2fs_get_node_page(sbi, son_inode->i_ino);
                if (IS_ERR(son_ipage)) {
                    pr_err("[snapfs cow2]: failed to get src page[%lu]\n", son_inode->i_ino);
                    goto next_free;
                }
                new_ipage = f2fs_get_node_page(sbi, tmp_inode->i_ino);
                if (IS_ERR(new_ipage)) {
                    pr_err("[snapfs cow2]: failed to get snap page[%lu]\n", tmp_inode->i_ino);
                    f2fs_put_page(son_ipage, 1);
                    goto next_free;
                }
                if (f2fs_has_inline_data(tmp_inode)) {
                    inline_dentry = inline_data_addr(tmp_inode, new_ipage);
                    ret = f2fs_snap_inline_to_dirdata(tmp_inode, inline_dentry, new_ipage);
                    if(ret){
                        f2fs_put_page(son_ipage, 1);
                        f2fs_put_page(new_ipage, 1);
                        pr_info("[snapfs cow2]: convert inline failed\n");
                        goto next_free;
                    }
                }
                son_fi = F2FS_INODE(son_ipage);
                new_fi = F2FS_INODE(new_ipage);

                update_f2fs_inode(son_fi, new_fi);
                tmp_inode->i_size = le64_to_cpu(son_inode->i_size);
                tmp_inode->i_blocks = le64_to_cpu(son_inode->i_blocks);
                f2fs_cow_update_inode(son_inode, tmp_inode);

                set_page_dirty(new_ipage);
                f2fs_put_page(son_ipage, 1);
                f2fs_put_page(new_ipage, 1);

                /* 复制 node 树，为快照创建独立的间接节点 */
                ret = f2fs_cow_copy_all_nodes(son_inode, tmp_inode);
                if (ret) {
                    pr_err("[snapfs cow2]: failed to copy nodes for file %lu\n", son_inode->i_ino);
                    goto next_free;
                }
            }
        }
        f2fs_mark_inode_dirty_sync(snap_inode, true);
        f2fs_mark_inode_dirty_sync(tmp_inode, true);
        *new_inode = tmp_inode;
        if(!tmp_inode){
            pr_info("tmp_inode is null\n");
            goto next_free;
        }
        // pr_info("inode[%s, %u]\n",d_find_any_alias(tmp_inode)->d_name.name, tmp_inode->i_ino);

        if(S_ISDIR(son_inode->i_mode)){
            if (f2fs_has_inline_dentry(son_inode)){
                pr_info("son_inode inode is inline dir\n");
                return 0;
            }
        }else if(S_ISREG(son_inode->i_mode)){
            if (f2fs_has_inline_data(son_inode)){
                pr_info("son_inode inode is inline data\n");
                return 0;
            }
        }

        if(S_ISDIR(tmp_inode->i_mode)){
            if (f2fs_has_inline_dentry(tmp_inode)){
                pr_info("tmp_inode inode is inline dir\n");
            }
        }else if(S_ISREG(tmp_inode->i_mode)){
            if (f2fs_has_inline_data(tmp_inode)){
                pr_info("tmp_inode inode is inline data\n");
            }
        }
        // pr_info("*new_inode[%s, %u]\n",d_find_any_alias(*new_inode)->d_name.name, (*new_inode)->i_ino);
        tmp_inode = NULL;
        // if (tmp_inode) {
        //     iput(tmp_inode);
        //     tmp_inode = NULL;
        // }
        goto out_success; 
    }else{
        if(SNAPFS_DEBUG) pr_info("[snapfs cow debug] not found dentry for file '%s' (inode %lu) in snap dir %lu\n",
                               filename, son_inode->i_ino, snap_inode->i_ino);
        goto next_free;
    }

out_success:    
    // pr_info("set mulref start\n");
    // f2fs_dump_nonzero_sit_mulref_entries_simple(sbi);
    ret = f2fs_set_mulref_blocks(*new_inode, son_inode->i_ino);
    // pr_info("set mulref over\n");
    // f2fs_dump_nonzero_sit_mulref_entries_simple(sbi);
next_free:
    // if (son_dentry)
    //     dput(son_dentry);
    if (snap_dentry)
        dput(snap_dentry);
    if (new_dentry) {
        dput(new_dentry);
    }
    if (page)
        f2fs_put_page(page, 1);
    
    return ret;
}

bool f2fs_inode_is_new_or_cowed(struct f2fs_sb_info *sbi,
                    struct inode *inode,
                    const struct timespec64 *snap_time){
    struct f2fs_inode *ri;
    struct page *page;
    struct timespec64 ts;
    
    page = f2fs_get_node_page(sbi, inode->i_ino);
    if (IS_ERR(page)) {
        pr_err("[snapfs cow1]: debug get page failed[%lu]\n", inode->i_ino); 
        return true;
    }
    ri = F2FS_INODE(page);
    ts.tv_sec  = le64_to_cpu(ri->i_mtime);      // 秒
    ts.tv_nsec = le32_to_cpu(ri->i_mtime_nsec); // 纳秒
    // pr_info("inode ctime: %us, %uns\n",ts.tv_sec, ts.tv_nsec);
    // pr_info("snap  ctime: %us, %uns\n",snap_time->tv_sec, snap_time->tv_nsec);
    if(timespec64_compare(snap_time, &ts) < 0){
        // 新文件或者创建快照后修改文件 都直接返回，不需要做cow
        // pr_info("inode is new\n");
        // pr_info("[snapfs cow]: debug snap,but is newfile or had cow\n");
        if(SNAPFS_DEBUG) pr_info("[snapfs cow]: debug snap,but is newfile or had cow\n");
        f2fs_put_page(page, 1);
        return true; // 已经处理过了
    }
    f2fs_put_page(page, 1);
    // pr_info("[snapfs cow]: old file, needw cown");
    return false; // 需要cow处理
}



#define SNAPFS_PATH_INIT_CAP 16

struct snap_path_ent {
    nid_t ino;                     /* 当前对象 inode */
    u16 name_len;                  /* 当前对象在父目录下的旧名字长度 */
    char old_name[F2FS_NAME_LEN];  /* 当前对象在父目录下的旧名字；root 为空串 */
};

struct snap_path_vec {
    struct snap_path_ent *ents;    /* leaf -> root */
    int nr;
    int cap;
};

static void snapfs_free_path(struct snap_path_vec *path)
{
    kfree(path->ents);
    path->ents = NULL;
    path->nr = 0;
    path->cap = 0;
}

static int snapfs_path_expand(struct snap_path_vec *path)
{
    int new_cap;
    struct snap_path_ent *new_ents;

    if (path->nr < path->cap)
        return 0;

    new_cap = path->cap ? path->cap * 2 : SNAPFS_PATH_INIT_CAP;
    new_ents = krealloc(path->ents,
                        sizeof(struct snap_path_ent) * new_cap,
                        GFP_NOFS);
    if (!new_ents)
        return -ENOMEM;

    path->ents = new_ents;
    path->cap = new_cap;
    return 0;
}

/*
 * 采集完整路径，按 leaf -> root 保存。
 * ents[0] = file
 * ents[1] = parent dir
 * ...
 * ents[n-1] = mount root
 *
 * old_name 保存“当前对象在其父目录下的名字”：
 *   file      -> 在 dir4 下的名字
 *   dir4      -> 在 dir3 下的名字
 *   ...
 *   mountroot -> 空串
 */
static int snapfs_collect_full_path_leaf_to_root(struct inode *inode,
                                                 struct snap_path_vec *path)
{
    struct dentry *dentry = NULL, *parent = NULL;
    struct super_block *sb = inode->i_sb;
    int ret = 0;

    memset(path, 0, sizeof(*path));

    dentry = d_find_any_alias(inode);
    if (!dentry) {
        pr_err("[snapfs cow]: get dentry failed with inode %lu\n", inode->i_ino);
        return -ENOENT;
    }

    while (dentry) {
        int idx, n;

        ret = snapfs_path_expand(path);
        if (ret)
            goto out;

        idx = path->nr++;
        path->ents[idx].ino = d_inode(dentry)->i_ino;

        if (IS_ROOT(dentry) || dentry == sb->s_root) {
            path->ents[idx].name_len = 0;
            path->ents[idx].old_name[0] = '\0';
            break;
        }

        n = min_t(int, dentry->d_name.len, F2FS_NAME_LEN - 1);
        memcpy(path->ents[idx].old_name, dentry->d_name.name, n);
        path->ents[idx].old_name[n] = '\0';
        path->ents[idx].name_len = n;

        parent = dget_parent(dentry);
        dput(dentry);
        dentry = parent;
        parent = NULL;
    }

out:
    if (parent)
        dput(parent);
    if (dentry)
        dput(dentry);

    if (ret) {
        snapfs_free_path(path);
        return ret;
    }
    return 0;
}

/*
 * 对单个 snapshot version 回放固定好的路径。
 *
 * 路径是 leaf -> root：
 *   [0]=file, [1]=dir4, [2]=dir3, [3]=dir2 ...
 *
 * 如果 snap_idx == 2，表示当前命中的 snapshot 层是 dir3，
 * 那么要依次处理：
 *   dir3 -> dir4
 *   dir4 -> file
 */
static int snapfs_replay_one_snapshot(struct super_block *sb,
                                      const struct snap_path_vec *path,
                                      int snap_idx,
                                      struct inode *snap_inode)
{
    /* 调试日志：跟踪 snapfs_replay_one_snapshot 调用 */
#if 0
    pr_err("[snapfs replay] ====== snapfs_replay_one_snapshot ENTER ======\n");
    pr_err("[snapfs replay] snap_idx=%d, snap_inode=%u\n", snap_idx, snap_inode->i_ino);
    pr_err("[snapfs replay] path entries:\n");
    {
        int j;
        for (j = 0; j <= snap_idx; j++) {
            pr_err("  [%d] ino=%u, name_len=%u, name=%.*s\n",
                   j, path->ents[j].ino, path->ents[j].name_len,
                   path->ents[j].name_len, path->ents[j].old_name);
        }
    }
#endif

    struct inode *pra_inode = NULL;
    struct inode *son_inode = NULL;
    struct inode *cur_snap = snap_inode;
    struct inode *next_snap = NULL;
    bool cur_snap_is_borrowed = true;
    int i, ret = 0;

    for (i = snap_idx; i > 0; i--) {
        pra_inode = f2fs_iget(sb, path->ents[i].ino);
        if (IS_ERR(pra_inode)) {
            ret = PTR_ERR(pra_inode);
            pra_inode = NULL;
            goto out;
        }

        son_inode = f2fs_iget(sb, path->ents[i - 1].ino);
        if (IS_ERR(son_inode)) {
            ret = PTR_ERR(son_inode);
            son_inode = NULL;
            goto out;
        }

#if 0
        /* 调试日志：在调用 f2fs_cow 之前 */
        pr_err("[snapfs replay] calling f2fs_cow: pra_inode=%u, cur_snap=%u, son_inode=%u\n",
               pra_inode->i_ino, cur_snap->i_ino, son_inode->i_ino);
        {
            struct f2fs_sb_info *sbi = F2FS_I_SB(son_inode);
            struct page *son_ipage = f2fs_get_node_page(sbi, son_inode->i_ino);
            if (!IS_ERR(son_ipage)) {
                struct f2fs_inode *son_fi = F2FS_INODE(son_ipage);
                pr_err("[snapfs replay] son_inode i_size=%llu, i_blocks=%lu, i_nid[0-4]=[%u,%u,%u,%u,%u]\n",
                       son_inode->i_size, son_inode->i_blocks,
                       le32_to_cpu(son_fi->i_nid[0]), le32_to_cpu(son_fi->i_nid[1]),
                       le32_to_cpu(son_fi->i_nid[2]), le32_to_cpu(son_fi->i_nid[3]),
                       le32_to_cpu(son_fi->i_nid[4]));
                f2fs_put_page(son_ipage, 1);
            } else {
                pr_err("[snapfs replay] son_inode i_size=%llu, i_blocks=%lu, i_nid=get_node_page FAILED\n",
                       son_inode->i_size, son_inode->i_blocks);
            }
        }
#endif

        next_snap = NULL;
        ret = f2fs_cow(pra_inode,
                       cur_snap,
                       son_inode,
                       path->ents[i - 1].old_name,
                       path->ents[i - 1].name_len,
                       &next_snap);
        iput(pra_inode);
        pra_inode = NULL;
        iput(son_inode);
        son_inode = NULL;

        if (ret) {
            pr_err("[snapfs cow]: replay failed at parent=%u child=%u name=%s\n",
                   path->ents[i].ino,
                   path->ents[i - 1].ino,
                   path->ents[i - 1].old_name);
            ret = -EIO;
            goto out;
        }

        if (!cur_snap_is_borrowed && cur_snap)
            iput(cur_snap);

        cur_snap = next_snap;
        cur_snap_is_borrowed = false;
    }

out:
    if (pra_inode)
        iput(pra_inode);
    if (son_inode)
        iput(son_inode);
    if (!cur_snap_is_borrowed && cur_snap)
        iput(cur_snap);
    return ret;
}

/*
 * 处理当前命中的 snapshot inode 对应的所有版本：
 *   - 第一个版本在 first_me
 *   - 后续版本沿 magic entry 链向后找
 *
 * did_replay:
 *   0 -> 当前这层没有真正回放（例如已经 cow 过）
 *   1 -> 当前这层至少回放了一次
 */
static int snapfs_process_snapshot_versions(struct inode *inode,
                                            const struct snap_path_vec *path,
                                            int snap_idx,
                                            struct f2fs_magic_entry *first_me,
                                            int *did_replay)
{
    struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
    struct super_block *sb = inode->i_sb;
    struct inode *snap_inode = NULL;
    struct page *page = NULL;
    block_t prev_blkaddr = 0;
    block_t blkaddr;
    u32 off;
    u32 next;
    int i, ret = 0;

    *did_replay = 0;

    /* 第一个版本 */
    if (!f2fs_inode_is_new_or_cowed(sbi, inode, &first_me->c_time)) {
        snap_inode = f2fs_iget(sb, le32_to_cpu(first_me->snap_ino));
        if (IS_ERR(snap_inode))
            return PTR_ERR(snap_inode);

        ret = snapfs_replay_one_snapshot(sb, path, snap_idx, snap_inode);
        iput(snap_inode);
        snap_inode = NULL;
        if (ret)
            return ret;

        *did_replay = 1;
    }

    next = le32_to_cpu(first_me->next);
    if (!next)
        return 0;

    down_read(&sbi->magic_info->rwsem);

    blkaddr = sbi->magic_info->magic_blkaddr + magic_entry_to_blkaddr(next);
    off     = magic_entry_to_offset(next);

    for (i = 0; i < first_me->count - 1 && next; i++) {
        struct f2fs_magic_block *mb;
        struct f2fs_magic_entry *me;

        if (prev_blkaddr != blkaddr) {
            page = f2fs_get_meta_page(sbi, blkaddr);
            if (IS_ERR(page)) {
                ret = PTR_ERR(page);
                page = NULL;
                goto out_unlock;
            }
        }

        mb = (struct f2fs_magic_block *)page_address(page);
        me = &mb->mgentries[off];
        next = le32_to_cpu(me->next);

        if (!f2fs_inode_is_new_or_cowed(sbi, inode, &me->c_time)) {
            snap_inode = f2fs_iget(sb, le32_to_cpu(me->snap_ino));
            if (IS_ERR(snap_inode)) {
                ret = PTR_ERR(snap_inode);
                snap_inode = NULL;
                goto out_unlock;
            }

            ret = snapfs_replay_one_snapshot(sb, path, snap_idx, snap_inode);
            iput(snap_inode);
            snap_inode = NULL;
            if (ret)
                goto out_unlock;

            *did_replay = 1;
        }

        prev_blkaddr = blkaddr;
        if (!next)
            break;

        blkaddr = sbi->magic_info->magic_blkaddr + magic_entry_to_blkaddr(next);
        off     = magic_entry_to_offset(next);

        if (page && prev_blkaddr != blkaddr) {
            f2fs_put_page(page, 1);
            page = NULL;
        }
    }

out_unlock:
    if (page)
        f2fs_put_page(page, 1);
    up_read(&sbi->magic_info->rwsem);
    return ret;
}

static int __f2fs_snapshot_cow_from_path(struct inode *inode,
                                         struct snap_path_vec *path)
{
    struct f2fs_magic_entry tmp_me;
    struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
    struct super_block *sb = inode->i_sb;
    struct inode *cur_inode = NULL;
    u32 entry_id = 0;
    int i, ret = 1;
    int did_replay = 0;

    memset(&tmp_me, 0, sizeof(tmp_me));

    ret = 1;
    for (i = 1; i < path->nr; i++) {
        int one_replayed = 0;

        cur_inode = f2fs_iget(sb, path->ents[i].ino);
        if (IS_ERR(cur_inode)) {
            ret = PTR_ERR(cur_inode);
            cur_inode = NULL;
            goto out;
        }

        memset(&tmp_me, 0, sizeof(tmp_me));
        entry_id = 0;

        if (is_snapshot_inode(cur_inode, &tmp_me, &entry_id)) {
            ret = snapfs_process_snapshot_versions(inode,
                                                  path,
                                                  i,
                                                  &tmp_me,
                                                  &one_replayed);
            iput(cur_inode);
            cur_inode = NULL;
            if (ret)
                goto out;

            if (one_replayed)
                did_replay = 1;
        } else {
            iput(cur_inode);
            cur_inode = NULL;
        }
    }

    ret = did_replay ? 0 : 1;

out:
    if (cur_inode)
        iput(cur_inode);
    return ret;
}

int f2fs_snapshot_cow_nolock(struct inode *inode)
{
    struct f2fs_magic_entry tmp_me;
    struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
    struct snap_path_vec path;
    u32 entry_id = 0;
    int ret = 1;

    if (SNAPFS_DEBUG)
        pr_info("[snapfs cow]: debug start[%u]\n", inode->i_ino);

    memset(&tmp_me, 0, sizeof(tmp_me));
    memset(&path, 0, sizeof(path));

    /* 保留 file 自己是不是 snapshot inode 的判断 */
    if (is_snapshot_inode(inode, &tmp_me, &entry_id))
        goto out;

    /* 这里不拿锁，直接收集 path */
    ret = snapfs_collect_full_path_leaf_to_root(inode, &path);
    if (ret)
        goto out;

    ret = __f2fs_snapshot_cow_from_path(inode, &path);

out:
    snapfs_free_path(&path);

    if (SNAPFS_DEBUG)
        pr_info("[snapfs cow]: debug end [%d](0: success, 1: no-op)\n", ret);

    return ret;
}


int f2fs_snapshot_cow(struct inode *inode)
{
    struct f2fs_magic_entry tmp_me;
    struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
    struct super_block *sb = inode->i_sb;
    struct snap_path_vec path;
    struct inode *cur_inode = NULL;
    u32 entry_id = 0;
    int i, ret = 1;          /* 保持你原函数“1 表示本次无实际 COW”的风格 */
    int did_replay = 0;

    if (SNAPFS_DEBUG)
        pr_info("[snapfs cow]: debug start[%u]\n", inode->i_ino);

    memset(&tmp_me, 0, sizeof(tmp_me));
    memset(&path, 0, sizeof(path));

    /*
     * 1) 最外层仍然先判断 file 自己是不是 snapshot inode；
     *    这是你原设计里支持文件级快照的入口，保留。
     */
    if (is_snapshot_inode(inode, &tmp_me, &entry_id))
        goto out;

    /*
     * 2) 这里就是“固定路径”的阶段。
     *    如果你已经在 sbi 里加了 snap_path_sem，把 lock 放在这两行外面即可：
     *
     *      down_read(&sbi->snap_path_sem);
     *      ret = snapfs_collect_full_path_leaf_to_root(inode, &path);
     *      up_read(&sbi->snap_path_sem);
     */
    down_read(&sbi->snap_path_sem);
    ret = snapfs_collect_full_path_leaf_to_root(inode, &path);
    up_read(&sbi->snap_path_sem);

    if (ret)
        goto out;

    ret = __f2fs_snapshot_cow_from_path(inode, &path);

out:
    // if (cur_inode)
    //     iput(cur_inode);
    snapfs_free_path(&path);

    if (SNAPFS_DEBUG)
        pr_info("[snapfs cow]: debug end [%d](0: success, 1: no-op)\n", ret);

    return ret;
}

//  update mulref

bool f2fs_is_mulref_blkaddr(struct f2fs_sb_info *sbi,
					 block_t blkaddr)
{
	struct sit_mulref_info *smi = SIT_MR_I(sbi);
	struct sit_mulref_entry *me;
	unsigned int segno, blkoff;

	/* 无 mulref 支持 */
	if (unlikely(!smi))
		return false;

	/* NULL / NEW addr 一定不是 mulref */
	if (blkaddr == NULL_ADDR || blkaddr == NEW_ADDR)
		return false;

	segno  = GET_SEGNO(sbi, blkaddr);
	/* 只允许 main area / SSA 范围 */
	if (segno >= le32_to_cpu(F2FS_RAW_SUPER(sbi)->segment_count_ssa))
		return false;

	blkoff = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);

	down_read(&smi->smentry_lock);
	me = &smi->smentries[segno];
	if (unlikely(!me->mblocks)) {
		up_read(&smi->smentry_lock);
		return false;
	}
	// if (test_bit(blkoff, (unsigned long *)me->mvalid_map)) {
    if (f2fs_test_bit(blkoff, (char *)me->mvalid_map)) {
		up_read(&smi->smentry_lock);
		return true;
	}
	up_read(&smi->smentry_lock);
	return false;
}

int f2fs_get_summary_by_addr(struct f2fs_sb_info *sbi,
                                    block_t blkaddr,
                                    struct f2fs_summary *sum)
{
    unsigned int segno = GET_SEGNO(sbi, blkaddr);
    unsigned int blkoff = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);
    unsigned int type;
    struct curseg_info *curseg;
    struct f2fs_summary_block *sum_blk;
    struct page *sum_page;
    struct sit_mulref_info *smi = SIT_MR_I(sbi);
    bool force_ssa = false;
    bool bitmap_was_set = false;

    /* === 调试: 检查脏标记 === */
    if (smi && smi->dirty_sum_pages_bitmap &&
        test_bit(segno, smi->dirty_sum_pages_bitmap)) {
        force_ssa = true;
        bitmap_was_set = true;
    }

    /* 1. 先查 curseg cache (除非被标记为脏) */
    if (!force_ssa) {
        /* 调试: 记录从 cache 读取的情况 */
        bool found_in_cache = false;
        down_read(&SM_I(sbi)->curseg_lock);
        for (type = CURSEG_HOT_DATA; type <= CURSEG_COLD_DATA; type++) {
            curseg = CURSEG_I(sbi, type);
            if (curseg->segno == segno && curseg->sum_blk) {
                mutex_lock(&curseg->curseg_mutex);
                *sum = curseg->sum_blk->entries[blkoff];
                mutex_unlock(&curseg->curseg_mutex);
                found_in_cache = true;
                break;
            }
        }
        up_read(&SM_I(sbi)->curseg_lock);

        /* 调试: 打印从 cache 读取的 summary */
        /* === 方案1修复: 添加 cache 值验证 === */
        if (found_in_cache) {
            block_t sum_nid = le32_to_cpu(sum->nid);
            block_t mr_base = sbi->magic_info->mulref_blkaddr;
            block_t mr_end = mr_base + MAGIC_MAX;

            /* 检查 sum.nid 是否是有效的 SSA 或 mulref block 地址 */
            bool is_valid_mulref_sum = (sum_nid >= mr_base && sum_nid < mr_end);
            unsigned int ssa_segno = GET_SEGNO(sbi, sum_nid);
            bool is_valid_ssa_addr = (ssa_segno < MAIN_SEGS(sbi));

            /* 如果是普通 block 地址（inode nid），说明 cache 是旧的 */
            /* 正常的 SSA summary.nid 应该是：SSA block 地址 或 mulref block 地址 */
            if (!is_valid_mulref_sum && !is_valid_ssa_addr && sum_nid != 0) {
                /* cache 值无效，强制从 SSA 读取 */
                pr_warn("[snapfs get_sum] CACHE invalid for blkaddr=%u, sum.nid=%u, "
                        "forcing SSA read (cache may be stale after batch op)\n",
                        blkaddr, sum_nid);
                found_in_cache = false;
                up_read(&SM_I(sbi)->curseg_lock);
                /* 继续到 SSA 读取分支 */
            } else {
                pr_info("[snapfs get_sum] READ from CACHE: blkaddr=%u, segno=%u, blkoff=%u, "
                        "sum.nid=%u, sum.ofs=%u, bitmap_set=%d\n",
                        blkaddr, segno, blkoff,
                        sum_nid,
                        le16_to_cpu(sum->ofs_in_node),
                        bitmap_was_set);
                return 0;
            }
        }
    }

    /* 2. 不在 cache 或被标记为脏 → 查 SSA */
    sum_page = f2fs_get_sum_page(sbi, segno);
    if (IS_ERR(sum_page))
        return PTR_ERR(sum_page);

    sum_blk = (struct f2fs_summary_block *)page_address(sum_page);
    *sum = sum_blk->entries[blkoff];

    /* 调试: 打印从 SSA 读取的 summary */
    pr_info("[snapfs get_sum] READ from SSA: blkaddr=%u, segno=%u, blkoff=%u, "
            "sum.nid=%u, sum.ofs=%u, bitmap_set=%d, cache_synced=%s\n",
            blkaddr, segno, blkoff,
            le32_to_cpu(sum->nid),
            le16_to_cpu(sum->ofs_in_node),
            bitmap_was_set,
            (force_ssa && bitmap_was_set) ? "YES" : "NO");

    snapfs_put_meta_page_auto(sum_page);

    /* === 清除脏标记 + 同步更新 curseg cache === */
    if (force_ssa && smi && smi->dirty_sum_pages_bitmap) {
        bool cache_sync_success = false;

        down_write(&smi->smentry_lock);

        /* 再次检查 dirty bit（double-checked locking） */
        if (test_bit(segno, smi->dirty_sum_pages_bitmap)) {
            /* 清除脏标记 */
            clear_bit(segno, smi->dirty_sum_pages_bitmap);
            smi->dirty_sum_pages_count--;

            /* === 关键修复: 同步更新 curseg cache === */
            /* 确保后续从 curseg cache 读取时也能获取正确数据 */
            down_read(&SM_I(sbi)->curseg_lock);
            for (type = CURSEG_HOT_DATA; type <= CURSEG_COLD_DATA; type++) {
                struct curseg_info *curseg = CURSEG_I(sbi, type);
                if (curseg->segno == segno && curseg->sum_blk) {
                    mutex_lock(&curseg->curseg_mutex);
                    curseg->sum_blk->entries[blkoff] = *sum;
                    mutex_unlock(&curseg->curseg_mutex);
                    cache_sync_success = true;
                    pr_info("[snapfs get_sum] cache synced: segno=%u, blkoff=%u, "
                            "sum.nid=%u, sum.ofs=%u\n",
                            segno, blkoff,
                            le32_to_cpu(sum->nid),
                            le16_to_cpu(sum->ofs_in_node));
                    break;
                }
            }
            up_read(&SM_I(sbi)->curseg_lock);

            /* 如果 cache sync 失败，这是预期行为 - 数据段的 segno 不在 curseg 中 */
            if (!cache_sync_success) {
                pr_debug("[snapfs get_sum] sum page segno=%u not in curseg cache "
                         "(normal for data segments), skipping cache sync\n", segno);
            }
        }
        up_write(&smi->smentry_lock);
    }

    return 0;
}

int f2fs_get_mulref_block(struct f2fs_sb_info *sbi, block_t blkaddr,
                 struct page **out_page,
                 struct f2fs_mulref_block **out_blk)
{
	struct page *page;
    block_t start_addr = sbi->magic_info->mulref_blkaddr;

    // down_write(&sm->curmulref_lock);
    // mutex_lock(&cmr->curmulref_mutex); 
    
    if (!out_blk) {
        f2fs_err(sbi, "f2fs get mulref_block_full: output params are NULL");
        // mutex_unlock(&cmr->curmulref_mutex);
        // up_write(&sm->curmulref_lock);
        return -EINVAL;
    }
	/* sanity */
	if (blkaddr == NULL_ADDR || blkaddr < start_addr){
        pr_info("blkaddr is error\n");
        // mutex_unlock(&cmr->curmulref_mutex);
        // up_write(&sm->curmulref_lock);
		return 1;
    }
    page = f2fs_get_meta_page(sbi, blkaddr);
    if (IS_ERR(page)){
        f2fs_err(sbi, "f2fs get mulref_block: f2fs_get_meta_page failed\n");
        // mutex_unlock(&cmr->curmulref_mutex);
        // up_write(&sm->curmulref_lock);
		return 1;
    }
    *out_blk = (struct f2fs_mulref_block *)page_address(page);
    *out_page = page;
    
    // mutex_unlock(&cmr->curmulref_mutex);
    // up_write(&sm->curmulref_lock);
	return 0;
}

void f2fs_put_mulref_block(struct f2fs_sb_info *sbi,
			   block_t blkaddr,
			   struct f2fs_mulref_block *blk)
{
	struct f2fs_sm_info *sm = SM_I(sbi);
	struct curmulref_info *cmr = &sm->curmulref_blk;
	struct page *page;

	if (!blk)
		return;

	/*
	 * curmulref cached page
	 */
	if (cmr->inited && blkaddr != cmr->blkaddr) {
		page = virt_to_page(blk);
        f2fs_put_page(page, 1);
	}	
}


// f2fs_mulref_remove_nid
int f2fs_mulref_overwrite(struct f2fs_sb_info *sbi,
                          block_t old_blkaddr,
                          nid_t new_nid)
{
    struct f2fs_sm_info *sm = SM_I(sbi);
    struct f2fs_summary old_sum;
    struct f2fs_mulref_block *cur_blk = NULL, *prev_blk = NULL, *head_blk = NULL;
    struct f2fs_mulref_entry *cur_entry = NULL;
    block_t cur_mr_blkaddr, next_mr_blkaddr, prev_mr_blkaddr;
    u16 cur_eidx, next_eidx, prev_eidx;
    u32 cur_next;
    int ret = 0;
    block_t base = sbi->magic_info->mulref_blkaddr;
    bool is_head = false;
    bool clear_mulref_flag = false;
    struct page *head_page = NULL;
    struct page *prev_page = NULL;
    struct page *mulref_page = NULL;
    struct page *cur_page = NULL;
    struct f2fs_summary new_sum;
    unsigned int old_segno, blk_off, entry_segno;
    bool curmulref_locked = false;
    struct curmulref_info *cmr = &SM_I(sbi)->curmulref_blk;
    block_t mr_base, mr_end, ssa_nid;
    block_t entry_data_blkaddr, sit_base;
    bool valid_data_addr, is_mulref_addr;
    block_t expected_mr_blkaddr;


    old_segno = GET_SEGNO(sbi, old_blkaddr);
    blk_off = GET_BLKOFF_FROM_SEG0(sbi, old_blkaddr);
    /* ---------- 1. 读取 old summary ---------- */
    ret = f2fs_get_summary_by_addr(sbi, old_blkaddr, &old_sum);
    if (ret)
        return ret;

    pr_info("[snapfs f2fs_mulref_overwrite] READ sum: blkaddr=%u, segno=%u, blkoff=%u, "
            "sum.nid=%u, sum.ofs=%u, sum.ver=%u\n",
            old_blkaddr, old_segno, blk_off,
            le32_to_cpu(old_sum.nid),
            le16_to_cpu(old_sum.ofs_in_node),
            le16_to_cpu(old_sum.version));

    // pr_info("[snapfs READ] blkaddr=%u, summary says: mr_blkaddr=%u, eidx=%u\n",
    //       old_blkaddr,
    //       le32_to_cpu(old_sum.nid),
    //       le16_to_cpu(old_sum.ofs_in_node));
    
    // pr_info("f2fs mulref overwrite: blk[%u]\n",old_blkaddr);
    down_write(&sm->curmulref_lock);
    mutex_lock(&cmr->curmulref_mutex);
    curmulref_locked = true;

    /* ---------- 2. 定位 mulref block ---------- */
    cur_mr_blkaddr = (block_t)le32_to_cpu(old_sum.nid);
    cur_eidx = le16_to_cpu(old_sum.ofs_in_node);

    head_page = f2fs_get_meta_page(sbi, cur_mr_blkaddr);
    if (IS_ERR(head_page)){
        f2fs_err(sbi, "[snapfs IO]: (overwrite): f2fs_get_meta_page failed\n");
        head_page = NULL;
        ret = -EIO;
        goto out;
    }
    head_blk = (struct f2fs_mulref_block *)page_address(head_page);

    /* 初始化 prev 指针 */
    prev_mr_blkaddr = 0;
    prev_eidx = 0;
    prev_blk = NULL;

    cur_blk = head_blk;
    /* 检查第一个节点是否就是要找的 */
    cur_entry = &cur_blk->mrentries[cur_eidx];

    /* 调试: 打印读取到的 mulref entry 内容 */
    pr_info("[snapfs f2fs_mulref_overwrite] READ mulref entry: "
            "mr_blkaddr=%u, eidx=%u, entry.m_nid=%u, entry.m_ofs=%u, "
            "entry.m_ver=%u, entry.m_count=%u, entry.next=%u\n",
            cur_mr_blkaddr, cur_eidx,
            le32_to_cpu(cur_entry->m_nid),
            le16_to_cpu(cur_entry->m_ofs),
            cur_entry->m_ver,
            cur_entry->m_count,
            le32_to_cpu(cur_entry->next));

    /* === 新增: SSA.nid 有效性检查 === */
    /* 检查 SSA.nid 是否在有效的 mulref block 地址范围内 */
    mr_base = sbi->magic_info->mulref_blkaddr;
    mr_end = mr_base + MAGIC_MAX;
    ssa_nid = (block_t)le32_to_cpu(old_sum.nid);

    if (ssa_nid < mr_base || ssa_nid >= mr_end) {
        /* === 方案2修复: 检查 SIT mulref flag === */
        /* 首先检查 SIT mulref flag */
        if (check_sit_mulref_entry(sbi, old_blkaddr)) {
            /* SIT 标记为 mulref，但 SSA.nid 无效 - 这表明数据结构不一致
             * 可能的原因：
             * 1. 批量操作中途失败，SSA 已更新但 SIT 错误
             * 2. SSA summary 被其他操作覆盖
             * 3. 系统 crash 导致不一致
             */
            f2fs_err(sbi, "[snapfs f2fs_mulref_overwrite] CRITICAL INCONSISTENCY:");
            f2fs_err(sbi, "  SIT marks blkaddr=%u as mulref, but SSA.nid=%u is invalid",
                     old_blkaddr, ssa_nid);
            f2fs_err(sbi, "  Valid mulref range: [%u, %u)", mr_base, mr_end);

            /* 检查 SSA.nid 是否看起来像 SSA block 地址（而不是 inode 或其他） */
            unsigned int ssa_segno = GET_SEGNO(sbi, ssa_nid);
            bool looks_like_ssa = (ssa_segno < MAIN_SEGS(sbi));

            if (looks_like_ssa) {
                f2fs_err(sbi, "  SSA.nid=%u appears to be SSA block address (segno=%u)",
                         ssa_nid, ssa_segno);
                f2fs_err(sbi, "  This may indicate the block was never properly set as mulref");
            }

            ret = -EUCLEAN;  /* 明确标记为数据不一致 */
            goto out;
        }

        /* SIT 未标记为 mulref，说明 SSA.nid 无效是正常的（块不是 mulref）
         * 这不是错误，直接返回 0（不需要覆写） */
        pr_debug("[snapfs f2fs_mulref_overwrite] SSA.nid=%u out of mulref range [%u, %u), "
                 "but SIT does not mark as mulref (blkaddr=%u), ignoring\n",
                 ssa_nid, mr_base, mr_end, old_blkaddr);
        ret = 0;
        goto out;
    }

    /* === 新增: mulref entry.m_nid 有效性检查 === */
    /* 检查 mulref entry 的 m_nid 是否是有效的数据块地址 */
    entry_data_blkaddr = (block_t)le32_to_cpu(cur_entry->m_nid);
    entry_segno = GET_SEGNO(sbi, entry_data_blkaddr);
    sit_base = SIT_I(sbi)->sit_base_addr;

    /* 有效的数据块地址应该: 1) 在 main segs 范围内，或 2) >= sit_base (可能是 SSA 块) */
    valid_data_addr = (entry_segno < MAIN_SEGS(sbi)) || (entry_data_blkaddr >= sit_base);

    /* 额外检查: m_nid 不应该是另一个 mulref block 的地址 */
    is_mulref_addr = (entry_data_blkaddr >= mr_base && entry_data_blkaddr < mr_end);

    /* === 方案3修复: 增强 mulref entry 验证逻辑 === */
    if (!valid_data_addr || is_mulref_addr) {
        f2fs_err(sbi, "[snapfs f2fs_mulref_overwrite] CRITICAL: SIT says mulref but SSA/mulref invalid!");
        f2fs_err(sbi, "  old_blkaddr=%u, SSA.nid=%u, entry.m_nid=%u (segno=%u, valid=%d, is_mulref=%d)",
                 old_blkaddr, ssa_nid, entry_data_blkaddr, entry_segno,
                 valid_data_addr, is_mulref_addr);
        f2fs_err(sbi, "  cur_mr_blkaddr=%u, cur_eidx=%u",
                 cur_mr_blkaddr, cur_eidx);

        /* 检查 SIT mulref flag */
        if (check_sit_mulref_entry(sbi, old_blkaddr)) {
            /* SIT 标记为 mulref，但 SSA/mulref entry 无效 - 严重错误 */
            f2fs_err(sbi, "  SIT confirms mulref but data is corrupted!");
            f2fs_err(sbi, "  This is a CRITICAL inconsistency. DO NOT skip silently!");
            ret = -EUCLEAN;  /* 使用明确的错误码 */
            goto out;
        }

        /* SIT 未标记为 mulref，说明 SSA 可能是旧的 - 忽略此错误 */
        pr_info("[snapfs f2fs_mulref_overwrite] SIT does not mark as mulref, "
                "SSA may be stale, continuing\n");
        ret = 0;
        goto out;
    }

    /* === 验证 SSA summary 与 mulref entry 的一致性 ===
     * 注意: 在批量操作期间，SSA 可能已更新但 mulref entry 尚未写入
     * 这种状态是预期的，不应视为错误
     */
    if (le32_to_cpu(cur_entry->m_nid) != old_blkaddr) {
        block_t entry_nid = le32_to_cpu(cur_entry->m_nid);
        expected_mr_blkaddr = sbi->magic_info->mulref_blkaddr;
        entry_segno = GET_SEGNO(sbi, entry_nid);
        bool valid_block_addr = (entry_segno < MAIN_SEGS(sbi));
        is_mulref_addr = (entry_nid >= expected_mr_blkaddr &&
                              entry_nid < expected_mr_blkaddr + MAGIC_MAX);

        /* 如果 m_nid 是无效值（不是 block 地址也不是 mulref 地址） */
        if (!valid_block_addr && !is_mulref_addr) {
            pr_warn("[snapfs f2fs_mulref_overwrite] invalid m_nid=%u, old_blkaddr=%u, "
                    "cur_mr_blkaddr=%u, cur_eidx=%u, skipping\n",
                    entry_nid, old_blkaddr, cur_mr_blkaddr, cur_eidx);
            ret = 1;  /* 跳过此 entry */
            goto out;
        }

        /* 如果 m_nid 指向另一个 mulref block，这是数据损坏 */
        if (is_mulref_addr) {
            pr_warn("[snapfs f2fs_mulref_overwrite] m_nid=%u points to mulref block, "
                    "data corruption detected, old_blkaddr=%u, cur_mr_blkaddr=%u\n",
                    entry_nid, old_blkaddr, cur_mr_blkaddr);
            ret = -EINVAL;
            goto out;
        }

        /* m_nid 是有效的 block 地址但不等于 old_blkaddr
         * 这是批量操作期间的预期中间状态，打印 debug 后继续执行 */
        pr_debug("[snapfs f2fs_mulref_overwrite] m_nid=%u != old_blkaddr=%u, "
                 "continuing (batch operation in progress?), "
                 "cur_mr_blkaddr=%u, cur_eidx=%u\n",
                 entry_nid, old_blkaddr, cur_mr_blkaddr, cur_eidx);
    }

    if ((nid_t)le32_to_cpu(cur_entry->m_nid) == new_nid) {
        is_head = true;
        goto found_entry;
    }

    // /* 保存 prev 信息 */
    pr_info("[snapfs IO]: is not head? mulref.sum [%u, %u, %u], head sum[%u,%u,%u], new sum nid %u\n",
        cur_mr_blkaddr, cur_eidx, old_sum.version,le32_to_cpu(cur_entry->m_nid),
        le16_to_cpu(cur_entry->m_ofs),cur_entry->m_ver,new_nid);
    
    pr_info("[snapfs READ] entry content: m_nid=%u, m_ofs=%u, m_ver=%u, m_count=%u, next=%u\n",
          le32_to_cpu(cur_entry->m_nid),
          le16_to_cpu(cur_entry->m_ofs),
          cur_entry->m_ver,
          cur_entry->m_count,
          le32_to_cpu(cur_entry->next));
    cur_next = le32_to_cpu(cur_entry->next);
    /* ---------- 3. 查找匹配 new_nid 的 entry ---------- */
    while (1) {
        //
        prev_mr_blkaddr = cur_mr_blkaddr;
        prev_blk = cur_blk;
        prev_eidx = cur_eidx;
        /* 计算下一个 entry 的位置 */
        cur_mr_blkaddr = base + cur_next / MRENTRY_PER_BLOCK;
        cur_eidx = cur_next % MRENTRY_PER_BLOCK;

        /* 获取当前 entry 所在的 block */
        if (cur_mr_blkaddr != prev_mr_blkaddr) {// 跨块处理
            // pr_info("[snapfs IO]: (overwrite) cross blk\n");
            // ret = f2fs_get_mulref_block(sbi, cur_mr_blkaddr,&cur_blk);
 
            if(cur_page){
                snapfs_put_meta_page_auto(cur_page);
                cur_page = NULL;
            }

            cur_page = f2fs_get_meta_page(sbi, cur_mr_blkaddr);
            if (IS_ERR(cur_page)){
                pr_err("[snapfs IO]: (overwrite): f2fs_get_meta_page failed(addr=%u)\n",cur_mr_blkaddr);
                ret = -EIO;
                goto out;
            }
            cur_blk = (struct f2fs_mulref_block *)page_address(cur_page);
            // has_cross_blk = true;
        } else {// 同块处理
            // prev_blk = cur_blk;// 同一个块
        }
        /* 获取当前 entry */  
        //同一个块，但是cur_eidx不一样， 
        cur_entry = &cur_blk->mrentries[cur_eidx];
        cur_next = le32_to_cpu(cur_entry->next);
        /* 检查是否匹配 */
        if ((nid_t)le32_to_cpu(cur_entry->m_nid) == new_nid) {
            pr_info("[snapfs IO]: (overwrite) found, nid[%u], blkaddr %u \n",le32_to_cpu(cur_entry->m_nid),cur_mr_blkaddr);
            /* 找到目标 entry，现在需要更新前驱节点的 next 指针 */
            break;
        }
        // pr_info("not found mulref entry nid[%u] with head\n",le32_to_cpu(cur_entry->m_nid));
        if (!cur_next){
            pr_info("[snapfs IO]: (overwrite) not found\n");
            ret = 1;
            goto out;
        }
    }

found_entry:
    /* ---------- 4. 删除找到的 entry ---------- */
    /* 标记当前 entry 无效并减少引用计数 */
    if (is_head) {
        /* 当前节点就是链表头 */
        // pr_info("[snapfs IO]: (overwrite) found at head, entry_nid[%u], new_nid %u\n",le32_to_cpu(cur_entry->m_nid), new_nid);
        cur_next = le32_to_cpu(cur_entry->next);
        /* 更新 old_sum（链表头变化了） */
        if (cur_next) {
            // 获取下一个entry， head的下一个
            next_mr_blkaddr = base + cur_next / MRENTRY_PER_BLOCK;
            next_eidx = cur_next % MRENTRY_PER_BLOCK;
            if(next_mr_blkaddr == cur_mr_blkaddr){//下一个entry和head同一个块
                cur_entry = &cur_blk->mrentries[next_eidx];
                if(!le32_to_cpu(cur_entry->next)){
                    // 刚好就2个多引用，这时要多变1
                    // pr_info("[snapfs IO]: (overwrite) 走这个分支!!\n");
                    new_sum.nid = cur_entry->m_nid;
                    new_sum.ofs_in_node = cur_entry->m_ofs;
                    new_sum.version = cur_entry->m_ver;
                    // pr_info("head_page=%p locked=%d writeback=%d\n",
                    //      head_page, PageLocked(head_page), PageWriteback(head_page));
                    mulref_mark_invalid(cur_blk, cur_eidx);
                    mulref_mark_invalid(cur_blk, next_eidx);
                    clear_mulref_flag = true;
                    if(cur_mr_blkaddr == cmr->blkaddr){
                        cmr->used_entries--;
                        cmr->used_entries--;
                    }
                }else{
                    // 3个引用以上，去掉head后，还是多引用
                    // 更新head信息
                    new_sum.nid = cpu_to_le32(next_mr_blkaddr);
                    new_sum.ofs_in_node = cpu_to_le16(next_eidx);
                    new_sum.version = cur_entry->m_ver;
                    cur_entry->m_count -= 1;
                    // pr_info("2 head_page=%p locked=%d writeback=%d\n",
                    //      head_page, PageLocked(head_page), PageWriteback(head_page));
                    mulref_mark_invalid(cur_blk, cur_eidx);
                    // 不用清楚多引用块flag
                    if(cur_mr_blkaddr == cmr->blkaddr){
                        cmr->used_entries--;
                    }
                }
                
            }else{// 下一个entry和head不是同一个块   跨块
                prev_mr_blkaddr = cur_mr_blkaddr;
                prev_blk = cur_blk;
                // ret = f2fs_get_mulref_block(sbi, next_mr_blkaddr, &cur_blk);
                mulref_page = f2fs_get_meta_page(sbi, next_mr_blkaddr);
                if (IS_ERR(mulref_page)){
                    pr_err("[snapfs IO]: (overwrite): f2fs_get_meta_page failed\n");
                    ret = -EIO;
                    goto out;
                }
                cur_blk = (struct f2fs_mulref_block *)page_address(mulref_page);

                cur_mr_blkaddr = next_mr_blkaddr;
                cur_entry = &cur_blk->mrentries[next_eidx];
                if(!le32_to_cpu(cur_entry->next)){
                    // 刚好就2个多引用，这时要多变1
                    new_sum.nid = cur_entry->m_nid;
                    new_sum.ofs_in_node = cur_entry->m_ofs;
                    new_sum.version = cur_entry->m_ver;
                    mulref_mark_invalid(prev_blk, cur_eidx);// 前一个块
                    mulref_mark_invalid(cur_blk, next_eidx);// 跨块
                    set_page_dirty(mulref_page);
                    clear_mulref_flag = true;
                    if(prev_mr_blkaddr == cmr->blkaddr){
                        cmr->used_entries--;
                    }
                }else{
                    // 3个引用以上，去掉head后，还是多引用
                    // 更新head信息
                    new_sum.nid = cpu_to_le32(next_mr_blkaddr);
                    new_sum.ofs_in_node = cpu_to_le16(next_eidx);
                    new_sum.version = cur_entry->m_ver;
                    cur_entry->m_count -= 1;
                    mulref_mark_invalid(prev_blk, cur_eidx);// 前一个块
                    set_page_dirty(mulref_page);

                    if(prev_mr_blkaddr == cmr->blkaddr){
                        cmr->used_entries--;
                    }
                }
            }
        }else{
            pr_warn("[snapfs IO]: (overwrite) orphan mulref entry, recovery: "
                    "old_blkaddr=%u, m_nid=%u, m_ofs=%u, "
                    "cur_mr_blkaddr=%u, cur_eidx=%u\n",
                    old_blkaddr, le32_to_cpu(cur_entry->m_nid),
                    le16_to_cpu(cur_entry->m_ofs), cur_mr_blkaddr, cur_eidx);

            /* 清除 mulref entry, 将 SSA 恢复为普通块格式 */
            mulref_mark_invalid(cur_blk, cur_eidx);
            set_page_dirty(cur_blk == head_blk ? head_page :
                          (cur_blk == prev_blk ? prev_page : cur_page));
            clear_mulref_flag = true;
            new_sum.nid = cpu_to_le32(old_blkaddr);
            new_sum.ofs_in_node = cpu_to_le16(blk_off);
            new_sum.version = old_sum.version;
            goto update_summary;
        }
        /* ---------- 5. 更新 summary ---------- */
update_summary:
        {
            struct snapfs_txn txn;
            struct page *sum_page = NULL;
            struct page *sit_page = NULL;
            struct page *flush_pages[] = {
                    head_page,
                    mulref_page,
                    NULL,
                    NULL,
            };

            ret = snapfs_stage_summary_page_change(sbi, old_blkaddr, &new_sum,
                    &sum_page);
            if (ret)
                goto out;
            flush_pages[2] = sum_page;
            if (clear_mulref_flag) {
                ret = snapfs_stage_sit_page_change(sbi, old_blkaddr, false,
                        &sit_page);
                if (ret) {
                    snapfs_put_meta_page_auto(sum_page);
                    sum_page = NULL;
                    goto out;
                }
                flush_pages[3] = sit_page;
            }

            ret = snapfs_redo_begin_overwrite(sbi, &txn);
            if (ret) {
                if (sit_page)
                    snapfs_put_meta_page_auto(sit_page);
                if (sum_page)
                    snapfs_put_meta_page_auto(sum_page);
                goto out;
            }
            snapfs_mark_txn_pages_dirty(flush_pages, ARRAY_SIZE(flush_pages));
            snapfs_require_redo_for_pages(&txn, flush_pages, ARRAY_SIZE(flush_pages));
            snapfs_txn_bind_overwrite_slot(&txn, &old_sum);
            txn.op_type = cpu_to_le32(clear_mulref_flag ?
                    SNAP_REDO_DROP_HEAD_TO_SINGLE : SNAP_REDO_DROP_HEAD_STILL_MR);
            txn.data_blkaddr = cpu_to_le32(old_blkaddr);
            ret = snapfs_redo_stage_mulref_op(&txn,
                    prev_mr_blkaddr ? prev_mr_blkaddr : cur_mr_blkaddr,
                    cur_eidx, false, NULL);
            if (!ret && clear_mulref_flag && next_mr_blkaddr == cur_mr_blkaddr)
                ret = snapfs_redo_stage_mulref_op(&txn, cur_mr_blkaddr,
                        next_eidx, false, NULL);
            if (!ret && !clear_mulref_flag)
                ret = snapfs_redo_stage_mulref_op(&txn, next_mr_blkaddr,
                        next_eidx, true, cur_entry);
            if (!ret)
                ret = snapfs_redo_stage_summary_final(&txn, old_blkaddr, &new_sum);
            if (!ret && clear_mulref_flag)
                ret = snapfs_redo_stage_sit_final(&txn, old_blkaddr, false);
            curmulref_locked = false;
            if (!ret)
                ret = snapfs_redo_commit(&txn);
            if (!ret)
                ret = snapfs_flush_txn_pages(sbi, flush_pages,
                        ARRAY_SIZE(flush_pages));
            if (!ret)
                ret = snapfs_redo_complete(&txn);
            snapfs_redo_end(&txn);
            if (sit_page)
                snapfs_put_meta_page_auto(sit_page);
            if (sum_page)
                snapfs_put_meta_page_auto(sum_page);
            if (ret)
                goto out;
        }

        if(mulref_page && prev_blk != cur_blk){
            snapfs_put_meta_page_auto(mulref_page);
            mulref_page = NULL;
        }

        if(head_page){
            snapfs_put_meta_page_auto(head_page);
            head_page = NULL;
        }
        goto out;
    } else {
        /* 当前节点不是链表头，需要更新前驱节点的 next 指针 */
        if(cur_next){ // 中间点
            struct snapfs_txn txn;

            // 更新前节点
            if(head_blk == prev_blk){
                head_blk->mrentries[le16_to_cpu(old_sum.ofs_in_node)].m_count--;
                head_blk->mrentries[le16_to_cpu(old_sum.ofs_in_node)].next = cpu_to_le32(cur_next);
            }else{
                if(prev_blk != cur_blk){
                    prev_page = f2fs_get_meta_page(sbi, prev_mr_blkaddr);
                    if (IS_ERR(prev_page)){
                        pr_err("[snapfs IO]: (overwrite): f2fs_get_meta_page failed\n");
                        ret = -EIO;
                        goto out;
                    }
                    prev_blk = (struct f2fs_mulref_block *)page_address(prev_page);
                }
                prev_blk->mrentries[prev_eidx].m_count--;
                prev_blk->mrentries[prev_eidx].next = cpu_to_le32(cur_next);
            }

            mulref_mark_invalid(cur_blk, cur_eidx);

            if(cur_mr_blkaddr == cmr->blkaddr){
                cmr->used_entries--;
            }

            {
                struct page *flush_pages[] = {
                        cur_page ? cur_page : head_page,
                        prev_page,
                };

                ret = snapfs_redo_begin_overwrite(sbi, &txn);
                if (ret)
                    goto out;
                snapfs_mark_txn_pages_dirty(flush_pages, ARRAY_SIZE(flush_pages));
                snapfs_require_redo_for_pages(&txn, flush_pages, ARRAY_SIZE(flush_pages));
                snapfs_txn_bind_overwrite_slot(&txn, &old_sum);
                txn.op_type = cpu_to_le32(SNAP_REDO_DROP_MIDDLE);
                txn.data_blkaddr = cpu_to_le32(old_blkaddr);
                ret = snapfs_redo_stage_mulref_op(&txn, cur_mr_blkaddr,
                        cur_eidx, false, NULL);
                if (!ret && prev_page)
                    ret = snapfs_redo_stage_mulref_op(&txn, prev_mr_blkaddr,
                            prev_eidx, true, &prev_blk->mrentries[prev_eidx]);
                if (!ret && head_blk == prev_blk)
                    ret = snapfs_redo_stage_mulref_op(&txn,
                            le32_to_cpu(old_sum.nid), le16_to_cpu(old_sum.ofs_in_node),
                            true, &head_blk->mrentries[le16_to_cpu(old_sum.ofs_in_node)]);
                curmulref_locked = false;
                if (!ret)
                    ret = snapfs_redo_commit(&txn);
                if (!ret)
                    ret = snapfs_flush_txn_pages(sbi, flush_pages,
                            ARRAY_SIZE(flush_pages));
                if (!ret)
                    ret = snapfs_redo_complete(&txn);
                snapfs_redo_end(&txn);
                if (ret)
                    goto out;
            }

            if(head_page){
                snapfs_put_meta_page_auto(head_page);
                head_page = NULL;
            }

            if(prev_page){
                snapfs_put_meta_page_auto(prev_page);
                prev_page = NULL;
            }

            if(cur_page){
                pr_info("[snapfs IO]: (overwrite) release cur_blk\n");
                snapfs_put_meta_page_auto(cur_page);
                cur_page = NULL;
            }
        }else{ // tail 节点
            if(head_blk == prev_blk){
                struct snapfs_txn txn;
                block_t sum_home;
                block_t sit_home;

                //prev如果是head，那就刚好是2个引用
                // 刚好就2个多引用，这时要多变1
                new_sum.nid = head_blk->mrentries[le16_to_cpu(old_sum.ofs_in_node)].m_nid;
                new_sum.ofs_in_node = head_blk->mrentries[le16_to_cpu(old_sum.ofs_in_node)].m_ofs;
                new_sum.version = head_blk->mrentries[le16_to_cpu(old_sum.ofs_in_node)].m_ver;
                mulref_mark_invalid(head_blk, prev_eidx);// 前一个块，head
                mulref_mark_invalid(cur_blk, cur_eidx);// tail

                {
                    struct page *sum_page = NULL;
                    struct page *sit_page = NULL;
                    struct page *flush_pages[] = {
                            head_page,
                            (cur_page && cur_mr_blkaddr != le32_to_cpu(old_sum.nid)) ? cur_page : NULL,
                            NULL,
                            NULL,
                    };

                    ret = snapfs_stage_summary_page_change(sbi, old_blkaddr, &new_sum,
                            &sum_page);
                    if (ret)
                        goto out;
                    flush_pages[2] = sum_page;
                    ret = snapfs_stage_sit_page_change(sbi, old_blkaddr, false,
                            &sit_page);
                    if (ret) {
                        snapfs_put_meta_page_auto(sum_page);
                        goto out;
                    }
                    flush_pages[3] = sit_page;

                    ret = snapfs_redo_begin_overwrite(sbi, &txn);
                    if (ret) {
                        snapfs_put_meta_page_auto(sit_page);
                        snapfs_put_meta_page_auto(sum_page);
                        goto out;
                    }
                    snapfs_mark_txn_pages_dirty(flush_pages, ARRAY_SIZE(flush_pages));
                    snapfs_require_redo_for_pages(&txn, flush_pages, ARRAY_SIZE(flush_pages));
                    snapfs_txn_bind_overwrite_slot(&txn, &old_sum);
                    txn.op_type = cpu_to_le32(SNAP_REDO_DROP_TAIL_TO_SINGLE);
                    txn.data_blkaddr = cpu_to_le32(old_blkaddr);
                    ret = snapfs_redo_stage_mulref_op(&txn,
                            le32_to_cpu(old_sum.nid),
                            le16_to_cpu(old_sum.ofs_in_node),
                            false, NULL);
                    if (!ret)
                        ret = snapfs_redo_stage_mulref_op(&txn, cur_mr_blkaddr,
                                cur_eidx, false, NULL);
                    if (!ret)
                        ret = snapfs_redo_stage_summary_final(&txn, old_blkaddr, &new_sum);
                    if (!ret)
                        ret = snapfs_redo_stage_sit_final(&txn, old_blkaddr, false);
                    curmulref_locked = false;
                    if (!ret)
                        ret = snapfs_redo_commit(&txn);
                    if (!ret)
                        ret = snapfs_flush_txn_pages(sbi, flush_pages,
                                ARRAY_SIZE(flush_pages));
                    if (!ret)
                        ret = snapfs_redo_complete(&txn);
                    snapfs_redo_end(&txn);
                    snapfs_put_meta_page_auto(sit_page);
                    snapfs_put_meta_page_auto(sum_page);
                    if (ret)
                        goto out;
                }
            }else{
                struct snapfs_txn txn;

                head_blk->mrentries[le16_to_cpu(old_sum.ofs_in_node)].m_count--;
                if(prev_blk != cur_blk){
                    prev_page = f2fs_get_meta_page(sbi, prev_mr_blkaddr);
                    if (IS_ERR(prev_page)){
                        pr_err("[snapfs IO]: (overwrite): f2fs_get_meta_page failed\n");
                        ret = -EIO;
                        goto out;
                    }
                    prev_blk = (struct f2fs_mulref_block *)page_address(prev_page);
                }
                prev_blk->mrentries[prev_eidx].m_count--;
                prev_blk->mrentries[prev_eidx].next = 0;
                mulref_mark_invalid(cur_blk, cur_eidx);

                {
                    struct page *flush_pages[] = {
                            cur_page ? cur_page : head_page,
                            prev_page,
                            head_page,
                    };

                    ret = snapfs_redo_begin_overwrite(sbi, &txn);
                    if (ret)
                        goto out;
                    snapfs_mark_txn_pages_dirty(flush_pages, ARRAY_SIZE(flush_pages));
                    snapfs_require_redo_for_pages(&txn, flush_pages, ARRAY_SIZE(flush_pages));
                    snapfs_txn_bind_overwrite_slot(&txn, &old_sum);
                    txn.op_type = cpu_to_le32(SNAP_REDO_DROP_TAIL_STILL_MR);
                    txn.data_blkaddr = cpu_to_le32(old_blkaddr);
                    ret = snapfs_redo_stage_mulref_op(&txn, cur_mr_blkaddr,
                            cur_eidx, false, NULL);
                    if (!ret && prev_page)
                        ret = snapfs_redo_stage_mulref_op(&txn, prev_mr_blkaddr,
                            prev_eidx, true, &prev_blk->mrentries[prev_eidx]);
                    if (!ret)
                        ret = snapfs_redo_stage_mulref_op(&txn,
                            le32_to_cpu(old_sum.nid), le16_to_cpu(old_sum.ofs_in_node),
                            true, &head_blk->mrentries[le16_to_cpu(old_sum.ofs_in_node)]);
                    curmulref_locked = false;
                    if (!ret)
                        ret = snapfs_redo_commit(&txn);
                    if (!ret)
                        ret = snapfs_flush_txn_pages(sbi, flush_pages,
                                ARRAY_SIZE(flush_pages));
                    if (!ret)
                        ret = snapfs_redo_complete(&txn);
                    snapfs_redo_end(&txn);
                    if (ret)
                        goto out;
                }
            }

            if(head_page){
                snapfs_put_meta_page_auto(head_page);
                head_page = NULL;
            }

            if(prev_page){
                snapfs_put_meta_page_auto(prev_page);
                prev_page = NULL;
            }

            if(cur_page){
                pr_info("[snapfs IO]: (overwrite) release cur_blk\n");
                snapfs_put_meta_page_auto(cur_page);
                cur_page = NULL;
            }
        }
        /* 标记当前节点无效 */
    }
    
out:
    // pr_info("over write eeeeeeeee\n");
    if (curmulref_locked) {
        mutex_unlock(&cmr->curmulref_mutex);
        up_write(&sm->curmulref_lock);
        curmulref_locked = false;
    }
    if(head_page){
        snapfs_put_meta_page_auto(head_page);
        head_page = NULL;
    }
    if(prev_page){
        snapfs_put_meta_page_auto(prev_page);
        prev_page = NULL;
    }
    if(cur_page){
        pr_info("[snapfs IO]: (overwrite) release cur_blk\n");
        snapfs_put_meta_page_auto(cur_page);
        cur_page = NULL;
    }
    return ret;
}

void f2fs_mulref_replace_block(struct f2fs_sb_info *sbi, block_t old_addr, block_t new_addr, struct f2fs_summary *old_sum)
{
    struct sit_mulref_info *smi = SIT_MR_I(sbi);
    struct sit_mulref_entry *me;
    struct sit_mulref_entry *new_me;
    unsigned int segno, blkoff;
    unsigned short old_offset;
    // struct f2fs_summary old_sum;
    // block_t mulref_blk_addr;
    int ret = 0;
    pr_info("replace ++++++++++\n");
    // 判断旧地址是否有效
    f2fs_bug_on(sbi, old_addr == NULL_ADDR);
    ret = f2fs_get_summary_by_addr(sbi, old_addr, old_sum);
    if (ret){
        pr_info("get old_sum failed\n");
        return ;
    }

    // 获取多引用块所在段号
    segno = GET_SEGNO(sbi, old_addr);
    blkoff = GET_BLKOFF_FROM_SEG0(sbi, old_addr);

    // 获取多引用块的相关信息
    down_write(&smi->smentry_lock);
    me = &smi->smentries[segno];
    if (unlikely(!me->mblocks)) {
        pr_err("No mulref block for segno: %u\n", segno);
        up_write(&smi->smentry_lock);
        return;
    }
    old_offset = blkoff;
    // 如果old_addr对应的块是无效的，直接返回
    if (!f2fs_test_bit(old_offset, (char *)me->mvalid_map)) {
    // if (!test_bit(old_offset, (unsigned long *)me->mvalid_map)) {
        pr_warn("Old block %u is not a valid mulref block.\n", old_addr);
        up_write(&smi->smentry_lock);
        return;
    }
    // 清除 old_addr 对应的多引用标志位
    f2fs_clear_bit(old_offset, (char *)me->mvalid_map);
    // clear_bit(old_offset, (unsigned long *)me->mvalid_map);

    // 设置 new_addr 对应的多引用标志位
    if(GET_SEGNO(sbi, old_addr) != GET_SEGNO(sbi, new_addr)){// 这里表明跨段处理了
        new_me = &smi->smentries[GET_SEGNO(sbi, new_addr)];
        f2fs_set_bit(GET_BLKOFF_FROM_SEG0(sbi, new_addr), (char *)new_me->mvalid_map);
        // 旧块多引用块数减1
        me->mblocks = cpu_to_le16(le16_to_cpu(me->mblocks) - 1);
        me->dirty = true;
        // 新块加1
        new_me->mblocks = cpu_to_le16(le16_to_cpu(new_me->mblocks) + 1);
        new_me->dirty = true;
    }else{
        // set_bit(GET_BLKOFF_FROM_SEG0(sbi, new_addr), (unsigned long *)me->mvalid_map);
        f2fs_set_bit(GET_BLKOFF_FROM_SEG0(sbi, new_addr), (char *)me->mvalid_map);
        me->dirty = true;
    }
    // 更新 m_mtime 时间戳. todo
    // update_segment_mtime(sbi, new_addr,0);

    up_write(&smi->smentry_lock);
}

void f2fs_dump_nonzero_sit_mulref_entries_simple(struct f2fs_sb_info *sbi)
{
    struct sit_mulref_info *smi = SIT_MR_I(sbi);
    struct sit_mulref_entry *entry;
    unsigned int segno;
    unsigned int total_segments = MAIN_SEGS(sbi);
    unsigned int nonzero_count = 0;
    int i;
    int has_nonzero;
    int bit_count;
    
    if (!smi || !smi->smentries)
        return;
    
    pr_info("=== QUICK DUMP: Nonzero SIT_MULREF Entries ===\n");
    
    down_read(&smi->smentry_lock);
    
    for (segno = 0; segno < total_segments; segno++) {
        entry = &smi->smentries[segno];
        
        // 快速检查位图
        has_nonzero = 0;
        for (i = 0; i < SIT_VBLOCK_MAP_SIZE; i++) {
            if (entry->mvalid_map[i] != 0) {
                has_nonzero = 1;
                break;
            }
        }
        
        if (has_nonzero) {
            nonzero_count++;
            
            // 计算1的位数
            bit_count = 0;
            for (i = 0; i < SIT_VBLOCK_MAP_SIZE; i++) {
                bit_count += hweight8(entry->mvalid_map[i]);
            }
            
            // pr_info("Entry %u: mblocks=%u, 1-bits=%d, mtime=0x%016llx%s\n",
            //         segno,
            //         le16_to_cpu(entry->mblocks),
            //         bit_count,
            //         le64_to_cpu(entry->m_mtime),
            //         entry->dirty ? " [DIRTY]" : "");
        }
    }
    
    up_read(&smi->smentry_lock);
    
    pr_info("Total: %u/%u entries have non-zero bitmap\n",
            nonzero_count, total_segments);
}

/*
 * ============================================================================
 * Mulref Compact Thread - 整理分散的 mulref entries
 * ============================================================================
 */

#define DEF_MULREF_MIN_SLEEP_TIME	30000	/* 30 seconds */
#define DEF_MULREF_MAX_SLEEP_TIME	60000	/* 60 seconds */
#define DEF_MULREF_NO_WORK_SLEEP	120000	/* 2 minutes */
#define DEF_MULREF_USAGE_THRESHOLD	90	/* warn when 90% used */
#define DEF_MULREF_COMPACT_THRESHOLD	30	/* compact when 30% fragmented */

/*
 * 统计 mulref 区域的使用情况
 */
static void mulref_collect_stats(struct f2fs_sb_info *sbi,
				 struct f2fs_mulref_compact_kthread *mt)
{
	struct f2fs_sm_info *sm = SM_I(sbi);
	block_t start_addr = sbi->magic_info->mulref_blkaddr;
	block_t end_addr = sm->ssa_blkaddr;
	unsigned int total_blocks = end_addr - start_addr;
	unsigned int used_blocks = 0;
	unsigned int total_entries = 0;
	unsigned int used_entries = 0;
	unsigned int i, j;
	struct page *page;
	struct f2fs_mulref_block *blk;

	for (i = 0; i < total_blocks; i++) {
		u16 valid_in_block = 0;

		page = f2fs_get_meta_page(sbi, start_addr + i);
		if (IS_ERR(page))
			continue;

		blk = (struct f2fs_mulref_block *)page_address(page);

		/* 统计这个块中的有效 entry */
		for (j = 0; j < MRENTRY_PER_BLOCK; j++) {
			if (f2fs_test_bit(j, (char *)blk->multi_bitmap))
				valid_in_block++;
		}

		if (valid_in_block > 0)
			used_blocks++;

		used_entries += valid_in_block;
		total_entries += MRENTRY_PER_BLOCK;

		f2fs_put_page(page, 1);
	}

	mt->total_blocks = total_blocks;
	mt->used_blocks = used_blocks;
	mt->total_entries = total_entries;
	mt->used_entries = used_entries;
}

/*
 * 获取 mulref 统计信息（供外部调用）
 */
int f2fs_mulref_get_stats(struct f2fs_sb_info *sbi, unsigned int *used,
			  unsigned int *total, unsigned int *usage_percent)
{
	struct f2fs_mulref_compact_kthread *mt;

	if (!SM_I(sbi))
		return -EINVAL;

	mt = sbi->mulref_compact_thread;
	if (!mt)
		return -EINVAL;

	if (used)
		*used = mt->used_entries;
	if (total)
		*total = mt->total_entries;
	if (usage_percent && mt->total_entries > 0)
		*usage_percent = (mt->used_entries * 100) / mt->total_entries;

	return 0;
}

/*
 * 计算碎片率
 * 碎片率 = (实际使用的块数 - 理想块数) / 实际使用的块数 * 100
 */
static unsigned int calc_fragmentation(struct f2fs_mulref_compact_kthread *mt)
{
	unsigned int ideal_blocks;

	if (mt->used_blocks == 0 || mt->used_entries == 0)
		return 0;

	/* 理想情况：所有 entry 紧凑存放需要的最少块数 */
	ideal_blocks = (mt->used_entries + MRENTRY_PER_BLOCK - 1) / MRENTRY_PER_BLOCK;

	if (mt->used_blocks <= ideal_blocks)
		return 0;

	return ((mt->used_blocks - ideal_blocks) * 100) / mt->used_blocks;
}

/*
 * 检查是否需要整理
 */
static bool need_mulref_compact(struct f2fs_sb_info *sbi,
				struct f2fs_mulref_compact_kthread *mt)
{
	unsigned int frag_rate;
	unsigned int usage_percent;

	/* 收集最新统计 */
	mulref_collect_stats(sbi, mt);

	/* 检查使用率 */
	if (mt->total_entries > 0) {
		usage_percent = (mt->used_entries * 100) / mt->total_entries;
		if (usage_percent >= mt->usage_threshold) {
			pr_warn("[mulref compact]: WARNING! usage=%u%% (threshold=%u%%)\n",
				usage_percent, mt->usage_threshold);
		}
	}

	/* 紧急模式直接返回需要整理 */
	if (mt->urgent) {
		pr_info("[mulref compact]: urgent mode triggered\n");
		return true;
	}

	/* 检查碎片率 */
	frag_rate = calc_fragmentation(mt);
	if (frag_rate >= mt->compact_threshold) {
		pr_info("[mulref compact]: frag_rate=%u%% >= threshold=%u%%, need compact\n",
			frag_rate, mt->compact_threshold);
		return true;
	}

	return false;
}

/*
 * 找到一个有空闲位置的目标块
 * 返回块地址，如果没找到返回 0
 */
static block_t find_dst_block(struct f2fs_sb_info *sbi, block_t start,
			      block_t end, block_t exclude)
{
	block_t addr;
	struct page *page;
	struct f2fs_mulref_block *blk;

	for (addr = start; addr < end; addr++) {
		u16 valid_count;

		if (addr == exclude)
			continue;

		page = f2fs_get_meta_page(sbi, addr);
		if (IS_ERR(page))
			continue;

		blk = (struct f2fs_mulref_block *)page_address(page);
		valid_count = le16_to_cpu(blk->v_mrentrys);
		f2fs_put_page(page, 1);

		/* 找到一个未满的块 */
		if (valid_count < MRENTRY_PER_BLOCK)
			return addr;
	}

	return 0;
}

/*
 * 将源块中的有效 entry 迁移到目标块
 * 注意：这里不更新 summary，因为 mulref entry 的位置变化
 *       不影响数据块的 summary（summary 指向链表头）
 *
 * 返回迁移的 entry 数量
 */
static int migrate_entries(struct f2fs_sb_info *sbi,
			   block_t src_addr, block_t dst_addr)
{
	struct f2fs_sm_info *sm = SM_I(sbi);
	struct page *src_page, *dst_page;
	struct f2fs_mulref_block *src_blk, *dst_blk;
	int migrated = 0;
	u16 src_idx, dst_idx;

	if (src_addr == dst_addr)
		return 0;

	down_write(&sm->curmulref_lock);
	src_page = f2fs_get_meta_page(sbi, src_addr);
	if (IS_ERR(src_page)) {
		up_write(&sm->curmulref_lock);
		return 0;
	}

	dst_page = f2fs_get_meta_page(sbi, dst_addr);
	if (IS_ERR(dst_page)) {
		snapfs_put_meta_page_auto(src_page);
		up_write(&sm->curmulref_lock);
		return 0;
	}

	src_blk = (struct f2fs_mulref_block *)page_address(src_page);
	dst_blk = (struct f2fs_mulref_block *)page_address(dst_page);

	dst_idx = 0;
	for (src_idx = 0; src_idx < MRENTRY_PER_BLOCK; src_idx++) {
		/* 跳过无效 entry */
		if (!f2fs_test_bit(src_idx, (char *)src_blk->multi_bitmap))
			continue;

		/* 在目标块找空闲位 */
		while (dst_idx < MRENTRY_PER_BLOCK &&
		       f2fs_test_bit(dst_idx, (char *)dst_blk->multi_bitmap)) {
			dst_idx++;
		}

		if (dst_idx >= MRENTRY_PER_BLOCK)
			break;  /* 目标块已满 */

		/* 复制 entry */
		memcpy(&dst_blk->mrentries[dst_idx],
		       &src_blk->mrentries[src_idx],
		       sizeof(struct f2fs_mulref_entry));

		/* 更新 bitmap */
		f2fs_set_bit(dst_idx, (char *)dst_blk->multi_bitmap);
		f2fs_clear_bit(src_idx, (char *)src_blk->multi_bitmap);

		/* 更新计数 */
		dst_blk->v_mrentrys = cpu_to_le16(le16_to_cpu(dst_blk->v_mrentrys) + 1);
		if (le16_to_cpu(src_blk->v_mrentrys) > 0)
			src_blk->v_mrentrys = cpu_to_le16(le16_to_cpu(src_blk->v_mrentrys) - 1);

		migrated++;
		dst_idx++;
	}

	if (migrated > 0) {
		set_page_dirty(src_page);
		set_page_dirty(dst_page);
	}

	up_write(&sm->curmulref_lock);

	if (migrated > 0) {
		if (snapfs_flush_locked_meta_page(sbi, src_page))
			migrated = 0;
		if (migrated > 0 && snapfs_flush_locked_meta_page(sbi, dst_page))
			migrated = 0;
	}

	snapfs_put_meta_page_auto(src_page);
	snapfs_put_meta_page_auto(dst_page);

	return migrated;
}

/*
 * 执行整理操作
 * 策略：从后向前扫描，将有效 entry 迁移到前面的块中
 */
static int do_mulref_compact(struct f2fs_sb_info *sbi)
{
	struct f2fs_sm_info *sm = SM_I(sbi);
	struct f2fs_mulref_compact_kthread *mt = sbi->mulref_compact_thread;
	block_t start_addr = sbi->magic_info->mulref_blkaddr;
	block_t end_addr = sm->ssa_blkaddr;
	block_t src_addr, dst_addr;
	int total_migrated = 0;
	int ret;
	struct page *page;
	struct f2fs_mulref_block *blk;

	pr_info("[mulref compact]: starting compaction, range [%u, %u)\n",
		start_addr, end_addr);
	pr_info("[mulref compact]: before: used_blocks=%u, used_entries=%u, frag=%u%%\n",
		mt->used_blocks, mt->used_entries, calc_fragmentation(mt));

	dst_addr = start_addr;

	/* 从后向前扫描源块 */
	for (src_addr = end_addr - 1; src_addr > dst_addr; src_addr--) {
		u16 valid_count;

		/* 检查源块是否有有效 entry */
		page = f2fs_get_meta_page(sbi, src_addr);
		if (IS_ERR(page))
			continue;

		blk = (struct f2fs_mulref_block *)page_address(page);
		valid_count = le16_to_cpu(blk->v_mrentrys);
		f2fs_put_page(page, 1);

		if (valid_count == 0)
			continue;

		/* 找一个未满的目标块 */
		dst_addr = find_dst_block(sbi, dst_addr, src_addr, src_addr);
		if (dst_addr == 0 || dst_addr >= src_addr)
			break;

		/* 迁移 */
		ret = migrate_entries(sbi, src_addr, dst_addr);
		if (ret > 0) {
			total_migrated += ret;
			if (SNAPFS_DEBUG)
				pr_info("[mulref compact]: migrated %d entries from blk %u to %u\n",
					ret, src_addr, dst_addr);
		}

		/* 让出 CPU */
		cond_resched();

		/* 检查是否应该停止 */
		if (kthread_should_stop())
			break;
	}

	mt->compacted_entries += total_migrated;

	/* 重新收集统计 */
	mulref_collect_stats(sbi, mt);

	pr_info("[mulref compact]: done, migrated %d entries\n", total_migrated);
	pr_info("[mulref compact]: after: used_blocks=%u, used_entries=%u, frag=%u%%\n",
		mt->used_blocks, mt->used_entries, calc_fragmentation(mt));

	return total_migrated;
}

/*
 * mulref 整理线程主函数
 */
static int mulref_compact_thread_func(void *data)
{
	struct f2fs_sb_info *sbi = data;
	struct f2fs_mulref_compact_kthread *mt = sbi->mulref_compact_thread;
	wait_queue_head_t *wq = &mt->mulref_wait_queue;
	unsigned int wait_ms;

	set_freezable();

	/* 启动时先收集一次统计 */
	mulref_collect_stats(sbi, mt);
	pr_info("[mulref compact]: initial stats: total_blocks=%u, used_blocks=%u, "
		"total_entries=%u, used_entries=%u\n",
		mt->total_blocks, mt->used_blocks,
		mt->total_entries, mt->used_entries);

	do {
		wait_ms = mt->no_work_sleep_time;

		/* 等待唤醒或超时 */
		wait_event_interruptible_timeout(*wq,
			kthread_should_stop() || freezing(current) || mt->urgent,
			msecs_to_jiffies(wait_ms));

		if (kthread_should_stop())
			break;

		if (try_to_freeze())
			continue;

		/* 检查文件系统状态 */
		if (unlikely(f2fs_cp_error(sbi))) {
			pr_err("[mulref compact]: CP error, stopping\n");
			break;
		}

		if (f2fs_readonly(sbi->sb))
			continue;

		/* 判断是否需要整理 */
		if (!need_mulref_compact(sbi, mt)) {
			mt->urgent = false;
			continue;
		}

		/* 执行整理 */
		do_mulref_compact(sbi);

		/* 重置紧急标志 */
		mt->urgent = false;

	} while (!kthread_should_stop());

	return 0;
}

/*
 * 启动 mulref 整理线程
 */
int f2fs_start_mulref_compact_thread(struct f2fs_sb_info *sbi)
{
	struct f2fs_mulref_compact_kthread *mt;
	dev_t dev = sbi->sb->s_bdev->bd_dev;
	int err = 0;

	/* 检查 mulref 区域是否存在 */
	if (!sbi->magic_info || sbi->magic_info->mulref_blkaddr == 0) {
		pr_info("[mulref compact]: no mulref area, skip thread creation\n");
		return 0;
	}

	mt = f2fs_kzalloc(sbi, sizeof(struct f2fs_mulref_compact_kthread), GFP_KERNEL);
	if (!mt) {
		err = -ENOMEM;
		goto out;
	}

	/* 初始化参数 */
	mt->min_sleep_time = DEF_MULREF_MIN_SLEEP_TIME;
	mt->max_sleep_time = DEF_MULREF_MAX_SLEEP_TIME;
	mt->no_work_sleep_time = DEF_MULREF_NO_WORK_SLEEP;
	mt->usage_threshold = DEF_MULREF_USAGE_THRESHOLD;
	mt->compact_threshold = DEF_MULREF_COMPACT_THRESHOLD;

	/* 初始化统计 */
	mt->total_blocks = 0;
	mt->used_blocks = 0;
	mt->total_entries = 0;
	mt->used_entries = 0;
	mt->compacted_entries = 0;

	/* 初始化状态 */
	mt->urgent = false;

	init_waitqueue_head(&mt->mulref_wait_queue);

	sbi->mulref_compact_thread = mt;

	/* 创建内核线程 */
	mt->f2fs_mulref_task = kthread_run(mulref_compact_thread_func, sbi,
					   "f2fs_mulref-%u:%u",
					   MAJOR(dev), MINOR(dev));
	if (IS_ERR(mt->f2fs_mulref_task)) {
		err = PTR_ERR(mt->f2fs_mulref_task);
		kfree(mt);
		sbi->mulref_compact_thread = NULL;
		goto out;
	}

	pr_info("[mulref compact]: thread started for device %u:%u\n",
		MAJOR(dev), MINOR(dev));

out:
	return err;
}

/*
 * 停止 mulref 整理线程
 */
void f2fs_stop_mulref_compact_thread(struct f2fs_sb_info *sbi)
{
	struct f2fs_mulref_compact_kthread *mt = sbi->mulref_compact_thread;

	if (!mt)
		return;

	if (mt->f2fs_mulref_task) {
		kthread_stop(mt->f2fs_mulref_task);
		mt->f2fs_mulref_task = NULL;
	}

	pr_info("[mulref compact]: thread stopped, total compacted entries=%u\n",
		mt->compacted_entries);

	kfree(mt);
	sbi->mulref_compact_thread = NULL;
}

/*
 * 唤醒 mulref 整理线程
 */
void f2fs_wakeup_mulref_compact_thread(struct f2fs_sb_info *sbi, bool urgent)
{
	struct f2fs_mulref_compact_kthread *mt = sbi->mulref_compact_thread;

	if (!mt || !mt->f2fs_mulref_task)
		return;

	if (urgent)
		mt->urgent = true;

	wake_up_interruptible(&mt->mulref_wait_queue);
}

/*
 * Hop range adjustment thread
 */
static int hop_range_adjust_thread(void *data)
{
	struct f2fs_sb_info *sbi = data;
	struct f2fs_magic_info *mi = sbi->magic_info;
	struct f2fs_hop_range_kthread *ht = sbi->hop_range_thread;
	u32 used, load_percent, old_range, new_range;

	set_freezable();

	do {
		wait_event_interruptible_timeout(ht->hop_wait_queue,
			kthread_should_stop(),
			msecs_to_jiffies(ht->sleep_time));

		if (kthread_should_stop())
			break;

		if (try_to_freeze())
			continue;

		/* Calculate load percentage */
		used = atomic_read(&mi->used_entries);
		load_percent = (used * 100) / MAGIC_ENTRY_NR;
		old_range = mi->hop_range;
		new_range = old_range;

		/* Adjust hop_range based on load */
		if (load_percent >= 80) {
			new_range = HOP_RANGE_HIGH;
		} else if (load_percent >= 50) {
			new_range = HOP_RANGE_MED;
		} else {
			new_range = HOP_RANGE_INIT;
		}

		if (new_range != old_range) {
			mi->hop_range = new_range;
			pr_info("[snapfs hop_range]: adjusted %u -> %u (load=%u%%, used=%u/%u)\n",
				old_range, new_range, load_percent, used, MAGIC_ENTRY_NR);
		}

	} while (!kthread_should_stop());

	return 0;
}

/*
 * Start hop range adjustment thread
 */
int f2fs_start_hop_range_thread(struct f2fs_sb_info *sbi)
{
	struct f2fs_hop_range_kthread *ht;
	struct task_struct *task;

	ht = kzalloc(sizeof(struct f2fs_hop_range_kthread), GFP_KERNEL);
	if (!ht)
		return -ENOMEM;

	init_waitqueue_head(&ht->hop_wait_queue);
	ht->sleep_time = HOP_RANGE_ADJUST_INTERVAL;

	sbi->hop_range_thread = ht;

	task = kthread_run(hop_range_adjust_thread, sbi, "f2fs_hop_range");
	if (IS_ERR(task)) {
		kfree(ht);
		sbi->hop_range_thread = NULL;
		return PTR_ERR(task);
	}

	ht->f2fs_hop_task = task;

	pr_info("[snapfs hop_range]: thread started, check interval=%ums\n",
		ht->sleep_time);

	return 0;
}

/*
 * Stop hop range adjustment thread
 */
void f2fs_stop_hop_range_thread(struct f2fs_sb_info *sbi)
{
	struct f2fs_hop_range_kthread *ht = sbi->hop_range_thread;

	if (!ht)
		return;

	if (ht->f2fs_hop_task) {
		kthread_stop(ht->f2fs_hop_task);
		ht->f2fs_hop_task = NULL;
	}

	pr_info("[snapfs hop_range]: thread stopped\n");

	kfree(ht);
	sbi->hop_range_thread = NULL;
}
