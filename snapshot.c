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

#include "f2fs.h"
#include "node.h"
#include "segment.h"
#include "snapshot.h"
#include "iostat.h"
#include <trace/events/f2fs.h>


bool is_used_for_snap(struct f2fs_sb_info *sbi, u16 flag){
	// 
	return true;
}
// usage:
// if (S_ISDIR(dn->inode->i_mode))
// 	new_ni.s_flag = alloc_magic_flag(sbi);
u16 alloc_magic_flag_from_reclaim(struct f2fs_sb_info *sbi)//快、无阻塞、无扫描
{
	struct magic_mgr *mgr = sbi->magic_mgr;
	u16 flag;
	u16 magic_count = le16_to_cpu(sbi->ckpt->magic_count);

	spin_lock(&mgr->lock);
	flag = find_next_bit(mgr->free, magic_count + 1, 1);
	if (flag <= magic_count) {
		clear_bit(flag, mgr->free);
		set_bit(flag, mgr->used);
		spin_unlock(&mgr->lock);
		return flag;
	}
	spin_unlock(&mgr->lock);
	return 0;
}

u16 alloc_magic_flag_force(struct f2fs_sb_info *sbi)//快、无阻塞、无扫描
{
	struct magic_mgr *mgr = sbi->magic_mgr;
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	struct nat_entry *ne;
	u16 stolen = 0;
	mutex_lock(&mgr->force_lock);

	/* ===== Phase 1: 再尝试一次 free 池 ===== */
	spin_lock(&mgr->lock);
	stolen = find_next_bit(mgr->free, MAGIC_MAX + 1, 1);
	if (stolen <= MAGIC_MAX) {
		clear_bit(stolen, mgr->free);
		set_bit(stolen, mgr->used);
		spin_unlock(&mgr->lock);
		mutex_unlock(&mgr->force_lock);
		return stolen;
	}
	spin_unlock(&mgr->lock);

	/* ===== Phase 2: Force steal from NAT ===== */
	down_write(&nm_i->nat_tree_lock);
	/*
	 * 注意：
	 * 这里假设你能遍历 NAT cache。
	 * 如果是 xarray / radix tree，请替换为对应遍历方式。
	 */
	list_for_each_entry(ne, &nm_i->nat_entries, list) {
		u16 flag = ne->ni.s_flag;
		if (!flag)
			continue;

		if (is_used_for_snap(sbi, flag))
			continue;

		/* ===== 真正的 steal ===== */
		ne->ni.s_flag = 0;
		set_nat_flag(ne, IS_DIRTY, true);
		stolen = flag;
		break;
	}

	up_write(&nm_i->nat_tree_lock);

	if (stolen) {
		spin_lock(&mgr->lock);
		set_bit(stolen, mgr->used);
		spin_unlock(&mgr->lock);
	}

	mutex_unlock(&mgr->force_lock);
	return stolen;
	return 0;
}

void magic_do_reclaim(struct f2fs_sb_info *sbi)
{
	struct magic_mgr *mgr = sbi->magic_mgr;
	u16 flag;

	spin_lock(&mgr->lock);

	for (flag = 1; flag <= MAGIC_MAX; flag++) {
		if (test_bit(flag, mgr->used) &&
		    !is_used_for_snap(sbi, flag)) {
			clear_bit(flag, mgr->used);
			set_bit(flag, mgr->free);
		}
	}

	atomic_set(&mgr->need_scan, 0);
	spin_unlock(&mgr->lock);
}

int magic_reclaim_thread(void *data)
{
	struct f2fs_sb_info *sbi = data;
	struct magic_mgr *mgr = sbi->magic_mgr;

	set_freezable();

	while (!kthread_should_stop()) {
		wait_event_freezable_timeout(
			mgr->wq,
			kthread_should_stop() ||
			!bitmap_empty(mgr->free, MAGIC_MAX + 1) ||
			atomic_read(&mgr->need_scan),
			msecs_to_jiffies(30000)
		);

		if (kthread_should_stop())
			break;

		magic_do_reclaim(sbi);
	}

	return 0;
}
// 在 f2fs_fill_super() 成功后：
// sbi->magic_mgr = kzalloc(sizeof(struct magic_mgr), GFP_KERNEL);
// spin_lock_init(&sbi->magic_mgr->lock);
// init_waitqueue_head(&sbi->magic_mgr->wq);
// atomic_set(&sbi->magic_mgr->need_scan, 1);

// sbi->magic_mgr->thread =
// 	kthread_run(magic_reclaim_thread, sbi, "f2fs_magic");



// mulref
// int alloc_mulref_entry(struct f2fs_sb_info *sbi,
// 		       struct f2fs_mulref_entry **out)
// {
// 	struct mulref_mgr *mgr = sbi->mulref_mgr;
// 	struct f2fs_mulref_block *blk;
// 	int idx;

// 	blk = read_mulref_block(mgr->cur_blk);

// 	idx = find_first_zero_bit(blk->multi_bitmap, MRENTRY_PER_BLOCK);
// 	if (idx < MRENTRY_PER_BLOCK) {
// 		set_bit(idx, blk->multi_bitmap);
// 		*out = &blk->mrentries[idx];
// 		return 0;
// 	}

// 	/* 当前块满了，换新块（已有逻辑） */
// 	return -ENOSPC;
// }

// bool mulref_entry_is_invalid(struct f2fs_sb_info *sbi,
// 			     struct f2fs_mulref_entry *e)
// {
// 	struct inode *inode;

// 	if (e->m_count == 0)
// 		return true;

// 	inode = f2fs_iget(sbi->sb, le32_to_cpu(e->m_nid));
// 	if (IS_ERR(inode))
// 		return true;

// 	if (inode->i_version != e->m_ver) {
// 		iput(inode);
// 		return true;
// 	}

// 	iput(inode);
// 	return false;
// }



// void mulref_do_reclaim(struct f2fs_sb_info *sbi)
// {
// 	block_t blkaddr;
// 	struct f2fs_mulref_block *blk;
// 	int i;

// 	for_each_mulref_block(sbi, blkaddr) {

// 		blk = read_mulref_block(blkaddr);

// 		for (i = 0; i < MRENTRY_PER_BLOCK; i++) {

// 			if (!test_bit(i, blk->multi_bitmap))
// 				continue;

// 			if (!mulref_entry_is_invalid(sbi, &blk->mrentries[i]))
// 				continue;

// 			/* 回收 entry */
// 			clear_bit(i, blk->multi_bitmap);
// 			memset(&blk->mrentries[i], 0,
// 			       sizeof(struct f2fs_mulref_entry));

// 			if (blk->next_free_mrentry > i)
// 				blk->next_free_mrentry = i;
// 		}

// 		mark_mulref_block_dirty(blk);
// 	}
// }


// int mulref_reclaim_thread(void *data)
// {
// 	struct f2fs_sb_info *sbi = data;
// 	struct mulref_mgr *mgr = sbi->mulref_mgr;

// 	set_freezable();

// 	while (!kthread_should_stop()) {
// 		wait_event_freezable_timeout(
// 			mgr->wq,
// 			kthread_should_stop() ||
// 			atomic_read(&mgr->need_scan),
// 			msecs_to_jiffies(30000)
// 		);

// 		if (kthread_should_stop())
// 			break;

// 		atomic_set(&mgr->need_scan, 0);
// 		mulref_do_reclaim(sbi);
// 	}

// 	return 0;
// }

// 什么时候触发 need_scan（非常重要）
// 1. inode 删除
// atomic_set(&mgr->need_scan, 1);
// wake_up(&mgr->wq);
// 2. truncate / unlink 多引用对象
// 3. alloc 失败时（没有 free entry）



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

static inline block_t magic_entry_to_blkaddr(
        struct f2fs_sb_info *sbi, u32 entry_id)
{
    return sbi->magic_info->magic_blkaddr +
           (entry_id / MGENTRY_PER_BLOCK);
}

static inline u32 magic_entry_to_offset(u32 entry_id)
{
    return entry_id % MGENTRY_PER_BLOCK;
}


int f2fs_magic_lookup_or_alloc(struct f2fs_sb_info *sbi,
        u32 src_ino,
        u32 *ret_entry_id,
        struct f2fs_magic_entry **ret_entry,
        struct page **ret_page)
{
    u32 h1 = magic_hash1(src_ino) % MAGIC_ENTRY_NR;
    u32 h2 = magic_hash2(src_ino) % MAGIC_ENTRY_NR;
    u32 i;
    unsigned long flags;
    if (!sbi->magic_info) {
        pr_err("magic_info is NULL!\n");
        return -ENOENT;
    }
    // 加锁保护整个查找/分配过程
    mutex_lock(&sbi->magic_info->mutex);
    for (i = 0; i < MAGIC_ENTRY_NR; i++) {
        u32 entry_id = (h1 + i * h2) % MAGIC_ENTRY_NR;
        block_t blkaddr;
        u32 off;
        struct page *page;
        struct f2fs_magic_block *mb;
        struct f2fs_magic_entry *me;
        blkaddr = magic_entry_to_blkaddr(sbi, entry_id);
        off     = magic_entry_to_offset(entry_id);

        page = f2fs_get_meta_page(sbi, blkaddr);
        if (IS_ERR(page)){
            pr_info("  f2fs_get_meta_page failed: %ld\n", PTR_ERR(page));
            mutex_unlock(&sbi->magic_info->mutex);
            return PTR_ERR(page);
        }
        mb = (struct f2fs_magic_block *)page_address(page);
        /* bitmap 判断 */
        if (!test_bit(off,(unsigned long *)(mb->multi_bitmap))) {
            /* 空槽：可以直接使用 */
            pr_info("Create new_snap addr/off[%u,%u]\n"
                    ,blkaddr, off);
            *ret_entry_id = entry_id;
            *ret_entry = &mb->mgentries[off];
            *ret_page = page;
            mutex_unlock(&sbi->magic_info->mutex);
            return 0;
        }
        me = &mb->mgentries[off];
        if (le32_to_cpu(me->src_ino) == src_ino) {
            /* 命中已有映射 */
            pr_info("read or update magic with addr/off[%u,%u]\n"
                    ,blkaddr, off);
            *ret_entry_id = entry_id;
            *ret_entry = me;
            *ret_page = page;
            mutex_unlock(&sbi->magic_info->mutex);
            return 0;
        }
        /* 冲突：继续 probing */
        f2fs_put_page(page, 1);
    }
    mutex_unlock(&sbi->magic_info->mutex);
    return -ENOSPC;  /* 所有 slot 都被占满 */
}

int f2fs_magic_lookup(struct f2fs_sb_info *sbi, u32 src_ino)
{
    u32 h1 = magic_hash1(src_ino) % MAGIC_ENTRY_NR;
    u32 h2 = magic_hash2(src_ino) % MAGIC_ENTRY_NR;
    u32 i;
    u32 ret_entry_id;
    struct f2fs_magic_entry *ret_entry;
    if (!sbi->magic_info) {
        pr_err("magic_info is NULL!\n");
        return -ENOENT;
    }
    // 加锁保护整个查找/分配过程
    mutex_lock(&sbi->magic_info->mutex);
    for (i = 0; i < MAGIC_ENTRY_NR; i++) {
        u32 entry_id = (h1 + i * h2) % MAGIC_ENTRY_NR;
        block_t blkaddr;
        u32 off;
        struct page *page;
        struct f2fs_magic_block *mb;
        struct f2fs_magic_entry *me;
        blkaddr = magic_entry_to_blkaddr(sbi, entry_id);
        off     = magic_entry_to_offset(entry_id);

        page = f2fs_get_meta_page(sbi, blkaddr);
        if (IS_ERR(page)){
            pr_info("  f2fs_get_meta_page failed: %ld\n", PTR_ERR(page));
            mutex_unlock(&sbi->magic_info->mutex);
            return PTR_ERR(page);
        }
        mb = (struct f2fs_magic_block *)page_address(page);
        /* bitmap 判断 */
        if (test_bit(off,(unsigned long *)(mb->multi_bitmap))) {
            me = &mb->mgentries[off];
            if (le32_to_cpu(me->src_ino) == src_ino) {
                /* 命中已有映射 */
                pr_info("[snapfs dump]: find mgentry, addr/off[%u,%u] with id[%u]\n"
                        ,blkaddr, off, entry_id);
                mutex_unlock(&sbi->magic_info->mutex);
                f2fs_put_page(page, 1);
                return 0;
            }
        }
        /* 冲突：继续 probing */
        f2fs_put_page(page, 1);
    }
    mutex_unlock(&sbi->magic_info->mutex);
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

int f2fs_magic_lookup_or_alloc_hopscotch(
        struct f2fs_sb_info *sbi,
        u32 src_ino,
        u32 *ret_entry_id,
        struct f2fs_magic_entry **ret_entry,
        struct page **ret_page)
{
    u32 home = magic_home(src_ino);
    u32 i;

    /* ---------- 1. 查询阶段：只扫 HOP_RANGE ---------- */
    for (i = 0; i < HOP_RANGE; i++) {
        u32 eid = (home + i) % MAGIC_ENTRY_NR;
        block_t blk = magic_entry_to_blkaddr(sbi, eid);
        u32 off = magic_entry_to_offset(eid);
        struct page *page;
        struct f2fs_magic_block *mb;
        struct f2fs_magic_entry *me;

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
    u32 free = home;
    struct page *free_page = NULL;

    for (i = 0; i < MAGIC_ENTRY_NR; i++) {
        u32 eid = (home + i) % MAGIC_ENTRY_NR;
        block_t blk = magic_entry_to_blkaddr(sbi, eid);
        u32 off = magic_entry_to_offset(eid);
        struct page *page;
        struct f2fs_magic_block *mb;

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
    while (hop_distance(home, free, MAGIC_ENTRY_NR) >= HOP_RANGE) {
        bool moved = false;
        u32 j;

        for (j = HOP_RANGE - 1; j > 0; j--) {
            u32 cand = (free + MAGIC_ENTRY_NR - j) % MAGIC_ENTRY_NR;
            block_t blk = magic_entry_to_blkaddr(sbi, cand);
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

            if (hop_distance(cand_home, free, MAGIC_ENTRY_NR) < HOP_RANGE) {
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
    *ret_entry_id = free;
    *ret_page = free_page;
    *ret_entry =
        &((struct f2fs_magic_block *)
            page_address(free_page))
            ->mgentries[magic_entry_to_offset(free)];

    return 0;
}


/* 
//假设我们要插入或更新一个 src_ino 对应的 snap_ino：
struct page *page;
struct f2fs_magic_entry *me;
u32 entry_id;
int err;

err = f2fs_magic_lookup_or_alloc(sbi, src_ino, &entry_id, &me, &page);
if (err) {
    printk("magic table full!\n");
    return err;
}

// 此时 me 指向可用 entry，page 已加载 

// 1. 更新 entry 数据 
me->src_ino  = cpu_to_le32(src_ino);
me->snap_ino = cpu_to_le32(snap_ino);
me->next     = 0;
me->count    = 1;

// 2. 更新 bitmap：标记该 slot 已使用 
{
    struct f2fs_magic_block *mb = (struct f2fs_magic_block *)page_address(page);
    u32 off = entry_id % MGENTRY_PER_BLOCK;
    set_bit(off, mb->multi_bitmap);
}

// 3. 标记 page dirty，写回磁盘
set_page_dirty(page);
f2fs_put_page(page, 1);
*/




// 如果只是想查找，不插入：
/*
struct page *page;
struct f2fs_magic_entry *me;
u32 entry_id;

int found = f2fs_magic_lookup_or_alloc(sbi, src_ino, &entry_id, &me, &page);
if (found == 0 && le32_to_cpu(me->src_ino) == src_ino) {
    // 找到已有映射
    printk("Found entry at entry_id=%u\n", entry_id);
} else {
    // 未找到或者冲突未解决
}
*/