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


typedef struct StacksnapNode {
    nid_t	i_ino;  // 存储字符
    struct StacksnapNode* next;  // 指向下一个节点
} StacksnapNode;

// 栈结构体
typedef struct Stack_snap {
    StacksnapNode* top;  // 栈顶指针
} Stack_snap;

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
        // pr_info("栈元素: ino[%lu]\n", temp->i_ino);
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
            pr_info("update magic with addr/off[%u,%u]\n"
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

int f2fs_magic_lookup(struct f2fs_sb_info *sbi, u32 src_ino,
        u32 *ret_entry_id, struct f2fs_magic_entry *ret_entry)
{
    u32 h1 = magic_hash1(src_ino) % MAGIC_ENTRY_NR;
    u32 h2 = magic_hash2(src_ino) % MAGIC_ENTRY_NR;
    u32 i;
    // u32 ret_entry_id;
    // struct f2fs_magic_entry *ret_entry;
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
                *ret_entry_id = entry_id;
                memcpy(ret_entry, me, sizeof(*me));
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

bool is_snapshot_inode(struct inode *inode, 
    struct f2fs_magic_entry *me, u32 *entry_id)
{
    struct f2fs_sb_info *sbi = NULL;
    struct f2fs_magic_entry tmp_me;
    memset(&tmp_me, 0, sizeof(tmp_me));
	u32 tmp_entry_id = 0;

    sbi = F2FS_I_SB(inode);
	if (f2fs_magic_lookup(sbi, inode->i_ino, &tmp_entry_id, &tmp_me)) {// 未找到或者冲突未解决
		pr_info("[snapfs dump]: not Found at entry_id\n");
        return false;
	}
    memcpy(me, &tmp_me, sizeof(tmp_me));
    *entry_id = tmp_entry_id;
    return true;
}

// me.count & 0x80：取最高位
// me.count & 0x7F：取低 7 位


int f2fs_cow(struct inode *src_inode,
             struct inode *snap_inode,
             struct inode *son_inode,
             struct inode *new_inode){


    return 0;
}


int f2fs_snapshot_cow(struct inode *inode)
{
    // 判断这个inode是否需要最做cow处理
    struct f2fs_magic_entry tmp_me;
    memset(&tmp_me, 0, sizeof(tmp_me));
    u32 entry_id;
    struct inode *snap_inode = NULL;
    struct inode *tmp_inode = NULL;
    struct inode *pra_inode = NULL;
    struct inode *son_inode = NULL;
    struct inode *new_inode = NULL;
    struct f2fs_sb_info *sbi = sbi = F2FS_I_SB(inode);
    struct super_block *sb = inode->i_sb;
    int i;
    u8 snap_count = 0;
    int ret;
    struct dentry *parent_dentry, *dentry;
    Stack_snap stack;
    nid_t  pra_ino, son_ino, snap_ino;
    // 先判断这个inode是不是快照inode, 
    // 常规文件，创建时就设置了数据块多引用，
    // 不用执行cow，后续更新引用关系即可

    // inode 是快照inode
    // if (S_ISDIR(inode)){
    //     snap_count = tmp_me.count;
    //     pr_info("[%u] is snapshot inode, snap_count[%u]\n",inode->i_ino, snap_count);
    //     for(i = 0 ;i < snap_count; i++){
    //         // todo. 多个快照版本的处理
    //         snap_inode = f2fs_iget(sbi->sb, le32_to_cpu(tmp_me.snap_ino));
    //         ret = f2fs_cow(inode, snap_inode, );
    //         if(ret){
    //             pr_info("inode self cow failed\n");
    //             return 1;
    //         }
    //         // 执行cow
    //     }
    // }
    if(!is_snapshot_inode(inode, &tmp_me, &entry_id)){
        // 如果不是，就往上找父目录的快照情况
        // 找到后直接让其准备cow，在cow中判断是否已经触发过
        // 要遍历到根目录寻找所有的快照目录,找到一个就去处理一个
        memset(&tmp_me, 0, sizeof(tmp_me));
        entry_id = 0;
        tmp_inode = inode;

        snap_initStack(&stack);
        snap_push(&stack, tmp_inode->i_ino);
        while (tmp_inode) {
            dentry = d_find_any_alias(tmp_inode);  // 获取 inode 对应的 dentry
            if (!dentry) {
                pr_err("[snapfs cow]: get dentry failed with inode %lu\n", tmp_inode->i_ino);
                break;
            }
            parent_dentry = dget_parent(dentry);
            pra_inode = parent_dentry->d_inode;
            snap_push(&stack, parent_dentry->d_inode->i_ino);
            if(is_snapshot_inode(pra_inode, &tmp_me, &entry_id)){
                snap_inode = f2fs_iget(sb, le32_to_cpu(tmp_me.snap_ino));
                // 获取push压栈的目录路径
                while (!snap_isEmpty(&stack)) {
                    ret = snap_pop2(&stack, &pra_ino, &son_ino);
                    if(ret) {
                        pr_info("cow stack is done\n");
                        break;
                    }
                    pra_ino = snap_pop(&stack);
                    pra_inode = f2fs_iget(sb, pra_ino); 
                    son_inode = f2fs_iget(sb, son_ino);
                    parent_dentry = d_find_any_alias(pra_inode);
                    dentry = d_find_any_alias(son_inode);
                    ret = f2fs_cow(pra_inode, snap_inode, son_inode, new_inode);
                    if(ret){
                        pr_info("parent cow failed\n");
                        return 1;
                    }
                    snap_inode = new_inode;
                    // if(S_ISREG(son_inode)){
                    //     break;
                    // }
                }
            }
            if(parent_dentry == sb->s_root){
                break;
            }
            tmp_inode = parent_dentry->d_inode;
        }
    }
    return 0;
}
