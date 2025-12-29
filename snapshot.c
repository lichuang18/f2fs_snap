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

#include "f2fs.h"
#include "node.h"
#include "segment.h"
#include "snapshot.h"
#include "iostat.h"
#include <trace/events/f2fs.h>

void update_f2fs_inode(struct f2fs_inode *src_fi,struct f2fs_inode *new_fi){
	int idx = 0;
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
	
	for (idx = 0; idx < 5; idx++) {
		new_fi->i_nid[idx] = src_fi->i_nid[idx];
	}
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
	if (snap_inode->i_blocks > 0) {
		unsigned int valid_blocks = snap_inode->i_blocks / (F2FS_BLKSIZE >> 9);
		f2fs_i_blocks_write(snap_inode, valid_blocks, true, true);
	}
}

static void __add_sum_entry(struct f2fs_sb_info *sbi, int type,
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


int f2fs_update_summary(struct f2fs_sb_info *sbi, block_t blkaddr,
                       struct f2fs_summary *new_sum, unsigned int old_segno,
                       unsigned int offset)
{
    struct curseg_info *curseg;
    int type = DATA;
    unsigned int old_type;
    for (old_type = CURSEG_HOT_DATA; old_type <= CURSEG_COLD_DATA; old_type++) {
        struct curseg_info *ci = CURSEG_I(sbi, old_type);
        if (ci->segno == old_segno) {
            curseg = ci;
            break;
        }
    }
    // 和f2fs_allocate_data_block一样的锁顺序
    if(curseg){
        pr_info("[snapfs debug]: summary with curseg\n");
        down_read(&SM_I(sbi)->curseg_lock);
        mutex_lock(&curseg->curseg_mutex);
        // 更新
        // pr_info("update sum: nid[%u],ofs[%u],ver[%u]\n",
        //     le32_to_cpu(new_sum->nid),new_sum->ofs_in_node,new_sum->version);
        __update_sum_entry(sbi, type, offset, new_sum);
        // 标记脏

        mutex_unlock(&curseg->curseg_mutex);
        up_read(&SM_I(sbi)->curseg_lock);
    } else{
        pr_info("summary to update not in curseg\n");
        return 1;
    }
    
    return 0;
}
int f2fs_update_summary_without_lock(struct f2fs_sb_info *sbi, block_t blkaddr,
                       struct f2fs_summary *new_sum, unsigned int old_segno,
                       unsigned int offset)
{
    struct curseg_info *curseg;
    int type = DATA;
    unsigned int old_type;
    for (old_type = CURSEG_HOT_DATA; old_type <= CURSEG_COLD_DATA; old_type++) {
        struct curseg_info *ci = CURSEG_I(sbi, old_type);
        if (ci->segno == old_segno) {
            curseg = ci;
            break;
        }
    }
    // 和f2fs_allocate_data_block一样的锁顺序
    if(curseg){
        pr_info("[snapfs debug]: summary with curseg\n");
        // 更新
        // pr_info("update sum: nid[%u],ofs[%u],ver[%u]\n",
            // le32_to_cpu(new_sum->nid),new_sum->ofs_in_node,new_sum->version);
        __update_sum_entry(sbi, type, offset, new_sum);
        // 标记脏
    } else{
        pr_info("summary to update not in curseg\n");
        return 1;
    }
    
    return 0;
}


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

static int curmulref_rotate_block(struct f2fs_sb_info *sbi)
{
    struct curmulref_info *cmr = &SM_I(sbi)->curmulref_blk;
    block_t new_blkaddr;

    /* 当前函数一定在 curmulref_mutex 保护下被调用 */
    /* 1. 分配新的 mulref block */
    new_blkaddr = cmr->blkaddr + 1;
    if (new_blkaddr == NULL_ADDR)
        return -ENOSPC;
    /*
     * 2. 提交旧 block
     *    注意：这里只是标记 dirty，不强制 writeback
     */
    if (cmr->page) {
        set_page_dirty(cmr->page);
        f2fs_put_page(cmr->page, 1);
    }

    /* 3. 切换 runtime 当前 block */
    cmr->blkaddr = new_blkaddr;
    cmr->page = f2fs_get_meta_page(sbi, new_blkaddr);
    if (!cmr->page)
        return -EIO;

    cmr->blk = (struct f2fs_mulref_block *)page_address(cmr->page);
    /*
     * 4. 记录到 ckpt（只是记录，真正写盘在 checkpoint）
     */
    sbi->ckpt->cur_mulref_blk = new_blkaddr - (sbi->magic_info->mulref_blkaddr);

    return 0;
}

int curmulref_alloc_entry(struct f2fs_sb_info *sbi, u16 *eidx)
{
	struct curmulref_info *cmr = &SM_I(sbi)->curmulref_blk;
    
	struct f2fs_mulref_block *blk;
	u16 idx = 0;
    int err = 0;
    
	mutex_lock(&cmr->curmulref_mutex);
    
    // pr_info("start debug: curmulref_alloc_entry 1\n");

	if (!cmr->inited) {
		mutex_unlock(&cmr->curmulref_mutex);
		return -EINVAL;
	}

    // 检查当前 block 是否已满
    // if (cmr->used_entries >= MRENTRY_PER_BLOCK) {
    //     f2fs_info(sbi, "Curmulref block %u is full (%u/%u), switching",
    //               cmr->blkaddr, cmr->used_entries, MRENTRY_PER_BLOCK);
    //     return change_curmulref_blk(sbi);
    // }

retry_find:
	blk = cmr->blk;
	idx = find_next_zero_bit((unsigned long *)blk->multi_bitmap,
				 MRENTRY_PER_BLOCK,
				 cmr->next_free_entry);
    // pr_info("start debug: curmulref_alloc_entry tp1 [%u]\n",idx);
	if (idx >= MRENTRY_PER_BLOCK) {
        pr_info("change mulref block\n");
        err = curmulref_rotate_block(sbi);
        if (err)
            goto out_unlock;
        goto retry_find;
	}
	set_bit(idx, (unsigned long *)blk->multi_bitmap);
    // pr_info("start debug: curmulref_alloc_entry tp2 [%u]\n",idx);
	memset(&blk->mrentries[idx], 0,
	       sizeof(struct f2fs_mulref_entry));
	cmr->used_entries++;
	cmr->next_free_entry = idx + 1;

    blk->v_mrentrys++;
    blk->next_free_mrentry = cmr->next_free_entry;

    // pr_info("start debug: curmulref_alloc_entry tp3 [%u]\n",err);
	
    set_page_dirty(cmr->page);
	*eidx = idx;

out_unlock:
    mutex_unlock(&cmr->curmulref_mutex);
	return err;
}



/**
 * check_sit_mulref_entry - 检查指定块地址是否被标记为多引用
 * @sbi: F2FS超级块信息
 * @blkaddr: 要检查的块地址
 * 
 * 返回: true - 该块被标记为多引用
 *       false - 该块未被标记为多引用，或发生错误
 */
bool check_sit_mulref_entry(struct f2fs_sb_info *sbi, block_t blkaddr)
{
	struct sit_mulref_info *smi = SIT_MR_I(sbi);
	struct sit_mulref_entry *me;
	unsigned int segno;
	unsigned int blkoff;
	bool result = false;

	/* 1. 安全检查 */
	if (!smi || !smi->smentries) {
		pr_info("check_sit_mulref_entry: smi is NULL or smentries is NULL");
		return false;
	}

	/* 2. 计算段号和块偏移 */
	segno = GET_SEGNO(sbi, blkaddr);
	blkoff = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);

	/* 3. 验证段号是否有效 */
	if (segno >= le32_to_cpu(F2FS_RAW_SUPER(sbi)->segment_count_ssa)) {
		pr_info("check_sit_mulref_entry: invalid segno %u for blkaddr %u",
			segno, blkaddr);
		return false;
	}

	/* 4. 加读锁保护并发访问 */
	down_read(&smi->smentry_lock);

	/* 5. 获取对应的段多引用条目 */
	me = &smi->smentries[segno];

	/* 6. 检查bitmap中对应的位是否被设置 */
	result = test_bit(blkoff, (unsigned long *)me->mvalid_map);

	/* 7. 调试信息（可选） */
#ifdef CONFIG_F2FS_DEBUG
	if (result) {
		f2fs_debug(sbi, "blkaddr %u (segno %u, blkoff %u) is marked as multi-referenced",
			   blkaddr, segno, blkoff);
	}
#endif

	/* 8. 释放读锁 */
	up_read(&smi->smentry_lock);

	return result;
}


// set = true ：标记为多引用
// set = false ：取消多引用（为回收逻辑留接口） 
void update_sit_mulref_entry(struct f2fs_sb_info *sbi,
			     block_t blkaddr,
			     bool set)
{
	struct sit_mulref_info *smi = SIT_MR_I(sbi);
	struct sit_mulref_entry *me;
	unsigned int segno;
	unsigned int blkoff;
	bool old;

	if (!smi)
		return;

	segno  = GET_SEGNO(sbi, blkaddr);
	blkoff = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);

	if (segno >= le32_to_cpu(F2FS_RAW_SUPER(sbi)->segment_count_ssa))
		return;

	down_write(&smi->smentry_lock);

	me = &smi->smentries[segno];

	/* 原状态 */
	old = test_bit(blkoff, (unsigned long *)me->mvalid_map);

	if (set) {//设置多引用
		if (!old) { //如果原来是0，就设置为1，然后blk数量+1，dirty
			__set_bit(blkoff,
				(unsigned long *)me->mvalid_map);
			me->mblocks++;
			me->dirty = true;
		}
	} else {// 取消多引用设置
		if (old) {// 如果原来是1，就设置为0，然后blk数量-1，同样dirty
			__clear_bit(blkoff,
				(unsigned long *)me->mvalid_map);
			if (me->mblocks > 0)
				me->mblocks--;
			me->dirty = true;
		}
	}

	if (me->dirty)
        me->m_mtime = cpu_to_le64(get_mtime(sbi, false));
		// me->m_mtime = cpu_to_le64(ktime_get_real_seconds());

	up_write(&smi->smentry_lock);
}

static inline void mulref_mark_invalid(struct f2fs_mulref_block *blk, u16 idx)
{
	/* already invalid */
	if (!test_bit(idx, (unsigned long *)blk->multi_bitmap))
		return;

	clear_bit(idx, (unsigned long *)blk->multi_bitmap);

	if (blk->v_mrentrys > 0)
		blk->v_mrentrys--;
	// if (idx < blk->next_free_mrentry)
	// 	blk->next_free_mrentry = idx;
}


// mulref
int f2fs_alloc_mulref_entry(struct f2fs_sb_info *sbi,
			    block_t *blkaddr, nid_t ino)
{
    struct f2fs_sm_info *sm = SM_I(sbi);
	struct curmulref_info *cmr = &sm->curmulref_blk;
	int ret;
    struct f2fs_summary sum;
    struct f2fs_summary old_sum;
    struct page *sum_page;
    struct page *mulref_page = NULL;
    struct page *mulref_page2 = NULL;
    struct page *mulref_page3 = NULL;
    struct page *mulref_page_tmp = NULL;
    struct f2fs_mulref_block *blk, *blk2, *blk3;
    block_t old_blkaddr = *blkaddr;
    bool is_mulref = check_sit_mulref_entry(sbi, old_blkaddr);
    u16 eidx_tmp = 0;
    u16 eidx1 = 0, eidx2 = 0, eidx3 = 0;
    block_t blkaddr1 = 0;
    block_t blkaddr2 = 0;
    block_t blkaddr3 = 0;
    block_t blkaddr_tmp = 0;
    u32 tmp_next = 0;
    struct curseg_info *old_curseg = NULL;
    unsigned int old_type;
    unsigned int old_segno, blk_off;
    struct f2fs_summary_block *sum_blk;
    struct f2fs_mulref_entry *mgentry, *mgentry2, *mgentry3, *mgentry_tmp;
    block_t start_addr = sbi->magic_info->mulref_blkaddr;
    bool need_put = false;
    bool need_put3 = false;
    if(!is_mulref){
        down_write(&sm->curmulref_lock);
        blkaddr1 = cmr->blkaddr;
        ret = curmulref_alloc_entry(sbi, &eidx_tmp);
        if (ret) {
            pr_info("alloc failed\n");
            up_write(&sm->curmulref_lock);
            return ret;
        }
        eidx1 = eidx_tmp;

        blkaddr2 = cmr->blkaddr; //上面分配函数可能触发块的切换，如果没切换那更好
        /* 2. 分配第二个 entry，对应传入的 ino */
        ret = curmulref_alloc_entry(sbi, &eidx_tmp);
        if (ret) {
            pr_info("alloc second entry failed\n");
            up_write(&sm->curmulref_lock);
            return ret;
        }
        eidx2 = eidx_tmp;
    }else{
        down_write(&sm->curmulref_lock);
        blkaddr1 = cmr->blkaddr;
        ret = curmulref_alloc_entry(sbi, &eidx_tmp);
        if (ret) {
            pr_info("alloc failed2\n");
            up_write(&sm->curmulref_lock);
            return ret;
        }
        eidx1 = eidx_tmp;
    }
    // common
    old_segno = GET_SEGNO(sbi, old_blkaddr);
    blk_off = GET_BLKOFF_FROM_SEG0(sbi, old_blkaddr);

    for (old_type = CURSEG_HOT_DATA; old_type <= CURSEG_COLD_DATA; old_type++) {
        struct curseg_info *ci = CURSEG_I(sbi, old_type);
        if (ci->segno == old_segno) {
            old_curseg = ci;
            break;
        }
    }
    if (old_curseg) {
        sum_blk = old_curseg->sum_blk;
        if (!sum_blk) {
            pr_err("sum_blk is NULL\n");
        }
        old_sum = sum_blk->entries[blk_off];
        // old_nid = le32_to_cpu(old_sum.nid);
        // old_ofs_in_node = le16_to_cpu(old_sum.ofs_in_node);
        // old_version = old_sum.version;
    } else {
        // 2) 不属于任何 curseg，说明是“封存”的旧 segment，
        // 这时 SSA 上的 summary 应该已经写好了，再用 f2fs_get_sum_page()。
        sum_page = f2fs_get_sum_page(sbi, old_segno);
        if (!IS_ERR(sum_page)) {
            sum_blk = (struct f2fs_summary_block *)page_address(sum_page);
            old_sum = sum_blk->entries[blk_off];	
            f2fs_put_page(sum_page, 1);
        }
    }
    if(!is_mulref){
        // maybe 加锁
        if (blkaddr1 == blkaddr2) {
            mulref_page = cmr->page;
            if (!mulref_page){
                up_write(&sm->curmulref_lock);
                return -EIO;
            }
            get_page(mulref_page);
        } else { // 跨块处理的情况
            mulref_page = f2fs_get_meta_page(sbi, blkaddr1);
        }
        blk = (struct f2fs_mulref_block *)page_address(mulref_page);
        mgentry = &blk->mrentries[eidx1];
        mgentry->m_nid = old_sum.nid;
        mgentry->m_ofs = old_sum.ofs_in_node;
        mgentry->m_ver = old_sum.version;
        mgentry->m_count += 2;
        mgentry->next = cpu_to_le32((blkaddr2 - start_addr) * MRENTRY_PER_BLOCK + eidx2);
        sum.nid = blkaddr1;
        sum.ofs_in_node = eidx1;
        sum.version = old_sum.version;	
        pr_info("cmr->blkaddr [%u]\n",cmr->blkaddr);
       
        pr_info("[snapfs debug]: old nid[%u],ofs[%u],ver[%u]\n",old_sum.nid
            ,old_sum.ofs_in_node, old_sum.version);
        pr_info("[snapfs debug]: new nid[%u],ofs[%u],ver[%u]\n",blkaddr1,eidx1,old_sum.version);
        // pr_info("next: [%u]\n",(blkaddr2 - start_addr) * MRENTRY_PER_BLOCK + eidx2);
        ret = f2fs_update_summary(sbi, old_blkaddr,&sum,old_segno,blk_off);
        if(ret){
            pr_info("[snapfs debug]: update summary failed\n");
        }else{
            pr_info("[snapfs debug]: update summary success!\n");
        }  

        // __add sum entry(sbi, DATA, &old_sum);
        mulref_page2 = cmr->page;//可能是同一个page

        if(mulref_page != mulref_page2){
            get_page(mulref_page2);
        }
        if (!mulref_page2){
            up_write(&sm->curmulref_lock);
            set_page_dirty(mulref_page);
            f2fs_put_page(mulref_page, 1);
            return -EIO;
        }
        blk2 = (struct f2fs_mulref_block *)page_address(mulref_page2);
        mgentry2 = &blk2->mrentries[eidx2];
        mgentry2->m_nid = ino;
        mgentry2->m_ofs = cpu_to_le16(old_sum.ofs_in_node);
        mgentry2->m_ver = old_sum.version;
        mgentry2->m_count = mgentry->m_count;
        mgentry2->next = 0;
        set_page_dirty(mulref_page);
        
        if(mulref_page != mulref_page2){
            f2fs_put_page(mulref_page, 1);
            f2fs_put_page(mulref_page2, 1);
        }
        f2fs_put_page(mulref_page, 1);  

        up_write(&sm->curmulref_lock);
    }else{ // 已经是多引用块，也就是多版本快照的处理
        // 分配一个就行，就是 eidx1和blkaddr1
        mulref_page = cmr->page; // 分配的数据块信息， 对应blkaddr1
        get_page(mulref_page);
        blk = (struct f2fs_mulref_block *)page_address(mulref_page);
        mgentry = &blk->mrentries[eidx1];

        blkaddr2 = le32_to_cpu(old_sum.nid);// head 地址
        eidx2 = le16_to_cpu(old_sum.ofs_in_node);
        if (blkaddr2 == blkaddr1) { //head地址和新分配的地址一致
            mulref_page2 = cmr->page;
            if (!mulref_page2){
                if(need_put){
                    put_page(mulref_page);
                }
                up_write(&sm->curmulref_lock);
                return -EIO;
            }
        } else { // 跨块处理的情况
            mulref_page2 = f2fs_get_meta_page(sbi, blkaddr2);// head
        }
        blk2 = (struct f2fs_mulref_block *)page_address(mulref_page2);
        mgentry2 = &blk2->mrentries[eidx2];// head
        mgentry2->m_count += 1; 

        mgentry->m_nid = ino;
        mgentry->m_ofs = mgentry2->m_ofs;
        mgentry->m_ver = mgentry2->m_ver;
        mgentry->m_count = mgentry2->m_count;
        mgentry->next = 0;

        // 更新前节点的next
        tmp_next = le32_to_cpu(mgentry2->next);
        mgentry_tmp = mgentry2;
        while(1){
            // next计算规则, 计算是第几个entry
            blkaddr3 = tmp_next / MRENTRY_PER_BLOCK + start_addr; 
            eidx3 = tmp_next % MRENTRY_PER_BLOCK;
            //head?
            // mgentry_tmp->next = (blkaddr_tmp - start_addr) * MRENTRY_PER_BLOCK + eidx_tmp;
            // mgentry_tmp->m_count = mgentry2->m_count;
            if (blkaddr3 == blkaddr2) { // head地址和新分配的地址一致
                mulref_page3 = mulref_page2;
                need_put3 = true;
            }else if (blkaddr3 == blkaddr_tmp){ // 和上一个tmp blk一致
                // mulref_page3 保持不变
            } else { // 跨块处理的情况
                if(mulref_page3 && mulref_page3 != mulref_page2){//且不等于head
                    set_page_dirty(mulref_page3);
                    f2fs_put_page(mulref_page3, 1);
                    mulref_page3 = NULL;
                }
                mulref_page3 = f2fs_get_meta_page(sbi, blkaddr3);//head next
            }
            blk3 = (struct f2fs_mulref_block *)page_address(mulref_page3);
            mgentry3 = &blk->mrentries[eidx3];
            tmp_next = le32_to_cpu(mgentry3->next);
            if(tmp_next == 0){
                // 分配一个就行，就是eidx1和blkaddr1
                mgentry3->next = cpu_to_le32((blkaddr1 - start_addr) * MRENTRY_PER_BLOCK + eidx1);
                break;
            }
            blkaddr_tmp = blkaddr3;
            eidx_tmp = eidx3;
            mgentry_tmp = mgentry3;

            // mgentry_tmp->next = (blkaddr_tmp - start_addr) * MRENTRY_PER_BLOCK + eidx_tmp;
            // mgentry_tmp->m_count = mgentry2->m_count;  
        }

        // while最后一次循环，page3没释放
        if(mulref_page3 && mulref_page3 != mulref_page2 && mulref_page3 != mulref_page){
            set_page_dirty(mulref_page3);
            f2fs_put_page(mulref_page3, 1);
            mulref_page3 = NULL;
        }

        if(mulref_page2 != mulref_page){
            set_page_dirty(mulref_page2);
            f2fs_put_page(mulref_page2, 1);
            f2fs_put_page(mulref_page, 1);
        }else{
            set_page_dirty(mulref_page);
            put_page(mulref_page);
        }

        up_write(&sm->curmulref_lock);
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
        u32 src_ino, u32 snap_ino)//,
        // u32 *ret_entry_id,
        // struct f2fs_magic_entry **ret_entry,
        // struct page **ret_page)
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
        blkaddr = magic_entry_to_blkaddr(sbi, entry_id);
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
            // *ret_entry_id = entry_id;
            // *ret_entry = &mb->mgentries[off];
            // *ret_page = page;
            goto out;
        }
        
        if (le32_to_cpu(me->src_ino) == src_ino) {
            /* 命中已有映射 */
            pr_info("update magic with addr/off[%u,%u]\n"
                    ,blkaddr, off);
            // *ret_entry_id = entry_id;
            // *ret_entry = me;
            // *ret_page = page;
            blkaddr2 = blkaddr;
            if(me->count == 1){
                for(j = 1; j < MAGIC_ENTRY_NR; j++){
                    mb2 = mb;
                    if(off >= MGENTRY_PER_BLOCK - 1){
                        blkaddr2 += 1;
                        page2 = f2fs_get_meta_page(sbi, blkaddr2);
                        if (IS_ERR(page2)){
                            pr_info("  f2fs_get_meta_page failed: %ld\n", PTR_ERR(page2));
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
                me->next = cpu_to_le32(off2 + blkaddr2 * MGENTRY_PER_BLOCK);
                me2 = &mb2->mgentries[off2];
                me2->src_ino = cpu_to_le32(src_ino);
                me2->snap_ino = cpu_to_le32(snap_ino);
                me2->count = me->count;
                me2->next = 0;
                me2->c_time = current_time(snap_inode);
            }else if(me->count > 1){
                me->count += 1;
                tmp_next = le32_to_cpu(me->next);
                while(tmp_next){
                    tmp_blkaddr = magic_entry_to_blkaddr(sbi, tmp_next);
                    tmp_off     = magic_entry_to_offset(tmp_next);
                    if(tmp_blkaddr == blkaddr){
                        tmp_me = &mb->mgentries[tmp_off];
                        if(!tmp_me->next){
                            //wanmei 找到tail了
                            blkaddr3 = tmp_blkaddr;
                            for(j = 1; j < MAGIC_ENTRY_NR; j++){
                                mb3 = mb;
                                if(tmp_off >= MGENTRY_PER_BLOCK - 1){
                                    blkaddr3 += 1;
                                    page3 = f2fs_get_meta_page(sbi, blkaddr3);
                                    if (IS_ERR(page3)){
                                        pr_info("  f2fs_get_meta_page failed: %ld\n", PTR_ERR(page3));
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
                            tmp_me->next = tmp_off + blkaddr3 * MGENTRY_PER_BLOCK;
                            me3->src_ino = cpu_to_le32(src_ino);
                            me3->snap_ino = cpu_to_le32(snap_ino);
                            me3->count = me->count;
                            me3->next = 0;
                            me3->c_time = current_time(snap_inode);
                            break; 
                        }else{
                            tmp_next = tmp_me->next;
                        }
                    }else{// 跨块处理
                        tmp_page = f2fs_get_meta_page(sbi, tmp_blkaddr);
                        if (IS_ERR(tmp_page)){
                            pr_info("  f2fs_get_meta_page failed: %ld\n", PTR_ERR(tmp_page));
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
                                        pr_info("  f2fs_get_meta_page failed: %ld\n", PTR_ERR(page3));
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
                            tmp_me->next = tmp_off + blkaddr3 * MGENTRY_PER_BLOCK;
                            off2 = (off + 1) % MGENTRY_PER_BLOCK;
                            me3->src_ino = cpu_to_le32(src_ino);
                            me3->snap_ino = cpu_to_le32(snap_ino);
                            me3->count = me->count;
                            me3->next = 0;
                            me3->c_time = current_time(snap_inode);
                            break; 
                        }else{
                            tmp_next = tmp_me->next;
                            f2fs_put_page(tmp_page, 1);
                        }
                    }
                } 
            }
            set_page_dirty(page2);
            f2fs_put_page(page2, 1);
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
        blkaddr = magic_entry_to_blkaddr(sbi, entry_id);
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
            if (le32_to_cpu(me->src_ino) == src_ino) {
                /* 命中已有映射 */
                pr_info("[snapfs f2fs_magic_lookup]: find mgentry, addr/off[%u,%u] with id[%u]\n"
                        ,blkaddr, off, entry_id);       
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
    /* ---------- 1. 查询阶段：只扫 HOP_RANGE ---------- */
    for (i = 0; i < HOP_RANGE; i++) {
        eid = (home + i) % MAGIC_ENTRY_NR;
        blk = magic_entry_to_blkaddr(sbi, eid);
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
        blk = magic_entry_to_blkaddr(sbi, eid);
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
	u32 tmp_entry_id = 0;
    memset(&tmp_me, 0, sizeof(tmp_me));
    sbi = F2FS_I_SB(inode);
    struct dentry *dentry = NULL;
    dentry = d_find_any_alias(inode);
    if(dentry) dput(dentry);
    // pr_info("file[%s]\n",dentry->d_name.name);
	if (f2fs_magic_lookup(sbi, inode->i_ino, &tmp_entry_id, &tmp_me)) {// 未找到或者冲突未解决
		// pr_info("[%u] is not snapshot\n", inode->i_ino);
        return false;
	}
    memcpy(me, &tmp_me, sizeof(tmp_me));
    *entry_id = tmp_entry_id;
    // pr_info("[%u] is snapshot: \n",inode->i_ino);
    return true;
}

int set_mulref_entry(struct f2fs_sb_info *sbi, block_t blkaddr, nid_t ino){ //, struct page *ipage

    int ret;
    block_t local_blk = blkaddr;
    ret = f2fs_alloc_mulref_entry(sbi, &local_blk, ino);
    if(!ret){
        pr_info("[snapfs set mulref entry]: set success! blk[%u]\n",blkaddr);
        // bool is_mulref = check_sit_mulref_entry(sbi, blkaddr);
        // if(!is_mulref){
        //     pr_info("woaini you are false\n");
        // }else{
        //     pr_info("wofuck you are true\n");
        // }
        update_sit_mulref_entry(sbi, blkaddr, 1);
        // bool is_mulref2 = check_sit_mulref_entry(sbi, blkaddr);
        // if(is_mulref2){
        //     pr_info("woaini you are true\n");
        // }else{
        //     pr_info("wofuck you are false\n");
        // }
    }else{
        pr_info("set mulref flag failed! blk[%u]\n",blkaddr);
        return ret;
    }
    return 0;
}



int f2fs_set_mulref_blocks(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	loff_t isize;
	pgoff_t lblk, max_lblk;
	unsigned int blkbits;
	struct f2fs_inode *fi;
    struct page *ipage;
    struct page *dn_ipage;
    nid_t nid = 0;
    block_t blkaddr = 0;
    struct direct_node *dn;

    struct page *indirect_page;
    struct indirect_node *indirect;

    struct page *indirect_page2;
    struct indirect_node *indirect2;

    long in_dn = 0;
    long in_dn2 = 0;
    long off_in_dn = 0;
    long off_in_dn2 = 0;
    
    int ret = 0;

    if(S_ISDIR(inode->i_mode)){
        if (f2fs_has_inline_dentry(inode)){
            pr_info("cow inode is inline dir\n");
            return 0;
        }
    }else if(S_ISREG(inode->i_mode)){
        if (f2fs_has_inline_data(inode)){
            pr_info("cow inode is inline data\n");
            return 0;
        }
    }

    if(S_ISREG(inode->i_mode))
        pr_info("[snapfs debug]: f2fs_set mulref blocks [noninline data]\n");

    const long direct_index = ADDRS_PER_INODE(inode);
	const long direct_blks = ADDRS_PER_BLOCK(inode);
    const long level1_blks = direct_index + direct_blks;
    const long level2_blks = level1_blks + direct_blks;
    const long level3_blks = level2_blks + direct_blks * direct_blks;
    const long level4_blks = level3_blks + direct_blks * direct_blks;
    const long level5_blks = level4_blks + direct_blks * direct_blks * direct_blks;
    const long double_dir_blk = direct_blks * direct_blks;
    
	isize = i_size_read(inode);
	blkbits = inode->i_blkbits;
	if (isize == 0) {
		pr_info("inode %lu: empty file\n", inode->i_ino);
		return 1;
	}
	max_lblk = (isize + (1ULL << blkbits) - 1) >> blkbits;
    ipage = f2fs_get_node_page(sbi, inode->i_ino);
    if (IS_ERR(ipage)) {
        pr_err("[snapfs setmulref]: get src_page[%lu] failed\n", inode->i_ino);
        return 1;
    }
    fi = F2FS_INODE(ipage);
	for (lblk = 0; lblk < max_lblk; lblk++) {
        if(lblk <= direct_index){
            if (__is_valid_data_blkaddr(fi->i_addr[lblk])) {
                // 开始set mulref flag
                ret = set_mulref_entry(sbi, fi->i_addr[lblk], inode->i_ino);
                if(ret){
                    pr_info("set mulref flag failed![direct_index]\n");
                    goto out;
                    // return ret;
                }
            }
            continue;
        }else if(lblk <= level1_blks){
            nid = fi->i_nid[0];
            if(nid == 0) continue; 
            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) {
                pr_err("[snapfs setmulref]: get dn_ipage failed[%d < direct_index]\n", lblk);
                goto out;
            }
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[lblk - direct_index]);
            if (__is_valid_data_blkaddr(blkaddr)) {
                // 开始set mulref flag
                ret = set_mulref_entry(sbi, blkaddr, inode->i_ino);
                if(ret){
                    pr_info("set mulref flag failed![level1_blks]\n");
                    f2fs_put_page(dn_ipage, 1);
                    goto out;
                    // return ret;
                }
            }
            f2fs_put_page(dn_ipage, 1);
        }else if(lblk <= level2_blks){
            nid = fi->i_nid[1];
            if(nid == 0) continue; 
            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) {
                pr_err("[snapfs setmulref]: get dn_ipage failed[%d < level2_blks]\n", lblk);
                goto out;
            }
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[lblk - level1_blks]);
            if (__is_valid_data_blkaddr(blkaddr)) {
                // 开始set mulref flag
                ret = set_mulref_entry(sbi, blkaddr, inode->i_ino);
                if(ret){
                    pr_info("set mulref flag failed![level2_blks]\n");
                    f2fs_put_page(dn_ipage, 1);
                    goto out;
                    // return ret;
                }
            }
            f2fs_put_page(dn_ipage, 1);
        }else if(lblk <= level3_blks){
            nid = fi->i_nid[2];
            if(nid == 0) break; 
            indirect_page = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(indirect_page)){
                pr_err("[snapfs setmulref]: get indirect_page failed[%d < level3_blks]\n", lblk);
                goto out;
                // return PTR_ERR(indirect_page);
            }
            in_dn = (lblk - level2_blks) / direct_blks;
            off_in_dn = (lblk - level2_blks) % direct_blks;
            indirect = (struct indirect_node *)page_address(dn_ipage);
            nid = le32_to_cpu(indirect->nid[in_dn]);
            if(nid == 0) break; 
            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) {
                pr_err("[snapfs setmulref]: get dn_ipage failed[%d < level3_blks]\n", lblk);
                f2fs_put_page(indirect_page, 1);
                goto out;
            }
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[off_in_dn]);
            if (__is_valid_data_blkaddr(blkaddr)) {
                // 开始set mulref flag
                ret = set_mulref_entry(sbi, blkaddr, inode->i_ino);
                if(ret){
                    pr_info("set mulref flag failed![level3_blks]\n");
                    f2fs_put_page(dn_ipage, 1);
                    f2fs_put_page(indirect_page, 1);
                    goto out;
                    // return ret;
                }
            }
            f2fs_put_page(dn_ipage, 1);
            f2fs_put_page(indirect_page, 1);
        }else if(lblk <= level4_blks){
            nid = fi->i_nid[3];
            if(nid == 0) break; 
            indirect_page = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(indirect_page)){
                pr_err("[snapfs setmulref]: get indirect_page failed[%d < level4_blks]\n", lblk);
                goto out;
                // return PTR_ERR(indirect_page);
            }
            in_dn = (lblk - level3_blks) / direct_blks;
            off_in_dn = (lblk - level3_blks) % direct_blks;
            indirect = (struct indirect_node *)page_address(indirect_page);
            nid = le32_to_cpu(indirect->nid[in_dn]);
            if(nid == 0) break; 
            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) {
                pr_err("[snapfs setmulref]: get dn_ipage failed[%d < level3_blks]\n", lblk);
                f2fs_put_page(indirect_page, 1);
                goto out;
            }
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[off_in_dn]);
            if (__is_valid_data_blkaddr(blkaddr)) {
                // 开始set mulref flag
                ret = set_mulref_entry(sbi, blkaddr, inode->i_ino);
                if(ret){
                    pr_info("set mulref flag failed![level4_blks]\n");
                    f2fs_put_page(dn_ipage, 1);
                    f2fs_put_page(indirect_page, 1);
                    goto out;
                    // return ret;
                }
            }
            f2fs_put_page(dn_ipage, 1);
            f2fs_put_page(indirect_page, 1);
        }else if(lblk <= level5_blks){
            nid = fi->i_nid[4];
            if(nid == 0) break; 
            indirect_page = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(indirect_page)){
                pr_err("[snapfs setmulref]: get indirect_page failed[%d < level5_blks]\n", lblk);
                goto out;
                // return PTR_ERR(indirect_page);
            }
            in_dn = (lblk - level3_blks) / double_dir_blk;
            off_in_dn = (lblk - level3_blks) % double_dir_blk;
            indirect = (struct indirect_node *)page_address(indirect_page);
            nid = le32_to_cpu(indirect->nid[in_dn]);
            if(nid == 0) break; 
            indirect_page2 = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(indirect_page2)){
                pr_err("[snapfs setmulref]: get indirect_page2 failed[%d < level5_blks]\n", lblk);
                f2fs_put_page(indirect_page, 1);
                goto out;
                // return PTR_ERR(indirect_page);
            }
            in_dn2 = in_dn / direct_blks;
            off_in_dn2 = off_in_dn % direct_blks;
            indirect2 = (struct indirect_node *)page_address(indirect_page2);
            nid = le32_to_cpu(indirect2->nid[in_dn2]);
            if(nid == 0) break; 
            dn_ipage = f2fs_get_node_page(sbi, nid);
            if (IS_ERR(dn_ipage)) {
                pr_err("[snapfs setmulref]: get dn_ipage failed[%d < level3_blks]\n", lblk);
                f2fs_put_page(indirect_page, 1);
                f2fs_put_page(indirect_page2, 1);
                goto out;
            }
            dn = (struct direct_node *)page_address(dn_ipage);
            blkaddr = le32_to_cpu(dn->addr[off_in_dn2]);
            if (__is_valid_data_blkaddr(blkaddr)) {
                // 开始set mulref flag
                ret = set_mulref_entry(sbi, blkaddr, inode->i_ino);
                if(ret){
                    pr_info("set mulref flag failed![level5_blks]\n");
                    f2fs_put_page(dn_ipage, 1);
                    f2fs_put_page(indirect_page, 1);
                    f2fs_put_page(indirect_page2, 1);
                    goto out;
                    // return ret;
                }
            }
            f2fs_put_page(dn_ipage, 1);
            f2fs_put_page(indirect_page, 1);
            f2fs_put_page(indirect_page2, 1);
        }
    }
out:
    f2fs_put_page(ipage, 1);
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
             struct inode **new_inode){
    // 判断name of son_inode是否已经存在snap_inode下
    struct dentry *snap_dentry, *son_dentry, *new_dentry;
	struct f2fs_dir_entry *de;
    struct page *page;
    struct super_block *sb = pra_inode->i_sb;
    struct inode *tmp_inode = NULL;
    umode_t mode;
    int ret = 0;
    struct qstr *d_name;
    struct f2fs_sb_info *sbi = F2FS_I_SB(pra_inode);
    nid_t ino;
    struct page *son_ipage = NULL, *new_ipage = NULL, *new_dpage = NULL;
    void *page_addr;
	void *inline_dentry, *inline_dentry2; // inline数据
    char *filename;
    struct f2fs_inode *son_fi, *new_fi;
    struct fscrypt_str dot = FSTR_INIT(".", 1);
	struct fscrypt_str dotdot = FSTR_INIT("..", 2);
	struct f2fs_dentry_ptr d;
    size_t idx = 0;
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

    son_dentry = d_find_any_alias(son_inode);
    if (!son_dentry)
		goto next_free;
    
    snap_dentry = d_find_any_alias(snap_inode);
    if (!snap_dentry)
		goto next_free;

    // dget(son_dentry);
    // dget(snap_dentry);
    d_name = &son_dentry->d_name;
    de = f2fs_find_entry(snap_inode, d_name, &page);
    if(de){
        // 快照目录下对应的数据COW过, 那两个目录下的inode就不相等
        tmp_inode = f2fs_iget(sb, le32_to_cpu(de->ino));
        if (IS_ERR(tmp_inode)) {
            ret = PTR_ERR(tmp_inode);
            tmp_inode = NULL;
            goto next_free;
        }
        if((le32_to_cpu(de->ino) != son_inode->i_ino) && (tmp_inode->i_size == son_inode->i_size)){
            pr_info("[snapfs f2fs_cow]: file[%s] of snap[%lu] had cowed!!!\n",
                    son_dentry->d_name.name, snap_inode->i_ino);
            *new_inode = tmp_inode;
            if (tmp_inode) {
                iput(tmp_inode);
                tmp_inode = NULL;
            } 
            goto out_success;
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
            pr_err("[snapfs f2fs_cow]: failed to create new inode: %d\n", ret);
            goto next_free;
        }
        if (!test_opt(sbi, DISABLE_EXT_IDENTIFY))
            snapfs_set_file_temperature(sbi, tmp_inode, d_name->name);
        /* 3. 初始化 inode 元数据 */
        snapfs_set_compress_inode(sbi, tmp_inode, d_name->name);
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
        filename = son_dentry->d_name.name;
        new_dentry = lookup_one_len(filename, snap_dentry, strlen(filename));
        f2fs_lock_op(sbi);
        /* 4. 在 snap_inode 下创建目录项 link */
        ret = f2fs_add_link(new_dentry, tmp_inode);
        if (ret) {
            f2fs_unlock_op(sbi);
              
            pr_err("[snapfs f2fs_cow]: failed to add link: %d\n", ret);
            goto next_free;
        }
        f2fs_unlock_op(sbi);
        f2fs_alloc_nid_done(sbi, ino);
	    d_instantiate_new(new_dentry, tmp_inode);

        pr_info("[snapfs f2fs_cow]: dentry[%s/%u] found in [%s/%u], new[%s/%u]\n", 
            d_name->name, le32_to_cpu(de->ino), 
            d_find_any_alias(snap_inode)->d_name.name, snap_inode->i_ino,
            new_dentry->d_name.name, tmp_inode->i_ino);

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
                pr_info("[snapfs f2fs_cow]: subdir(%lu) with inline\n", son_inode->i_ino);
                set_inode_flag(tmp_inode, FI_INLINE_DENTRY);
                son_ipage = f2fs_get_node_page(sbi, son_inode->i_ino);
                if (IS_ERR(son_ipage)) {
                    pr_err("[snapfs f2fs_cow]: get src_page[%lu] failed\n", son_inode->i_ino);
                    goto next_free;
                }
                new_ipage = f2fs_get_node_page(sbi, snap_inode->i_ino);
                if (IS_ERR(new_ipage)) {
                    pr_err("[snapfs f2fs_cow]: get snap page[%lu] failed\n", snap_inode->i_ino);
                    f2fs_put_page(new_ipage, 1);
                    goto next_free;
                }
                inline_dentry = inline_data_addr(son_inode, son_ipage);
                inline_dentry2 = inline_data_addr(tmp_inode, new_ipage);
                f2fs_truncate_inline_inode(tmp_inode, new_ipage, 0);
                memcpy(inline_dentry2, inline_dentry, MAX_INLINE_DATA(son_inode));
                // 更新.和..
                make_dentry_ptr_inline(snap_inode, &d, inline_dentry2);
                /* update dirent of "." */
                f2fs_update_dentry(snap_inode->i_ino, snap_inode->i_mode, &d, &dot, 0, 0);
                /* update dirent of ".." */
                f2fs_update_dentry(snap_inode->i_ino, snap_inode->i_mode, &d, &dotdot, 0, 1);
                tmp_inode->i_size = son_inode->i_size;
                set_page_dirty(new_ipage);
                f2fs_put_page(new_ipage, 1);
                f2fs_put_page(son_ipage, 1);
            } else{
                pr_info("[snapfs f2fs_cow]: subdir(%lu) without inline\n", son_inode->i_ino);
            
                son_ipage = f2fs_get_node_page(sbi, son_inode->i_ino);
                if (IS_ERR(son_ipage)) {
                    pr_err("[snapfs mk_snap]: failed to get src page[%lu]\n", son_inode->i_ino);
                    goto next_free;
                }
                new_ipage = f2fs_get_node_page(sbi, tmp_inode->i_ino);
                if (IS_ERR(new_ipage)) {
                    pr_err("[snapfs mk_snap]: failed to get snap page[%lu]\n", tmp_inode->i_ino);
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
                        pr_info("[snapfs mk_snap]: convert inline failed\n");
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
                new_dpage = f2fs_get_lock_data_page(tmp_inode, 0, false);
                page_addr = page_address(new_dpage);
                make_dentry_ptr_block(tmp_inode, &d, page_addr);
                f2fs_update_dentry(tmp_inode->i_ino, tmp_inode->i_mode, &d, &dot, 0, 0);
                f2fs_update_dentry(tmp_inode->i_ino, tmp_inode->i_mode, &d, &dotdot, 0, 1);
                f2fs_put_page(new_dpage, 1);
            }
        }else if(S_ISREG(son_inode->i_mode)){
            if(f2fs_has_inline_data(son_inode)){
                pr_info("[snapfs f2fs_cow]: subfile(%lu) with inline\n", son_inode->i_ino);
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
                pr_info("[snapfs f2fs_cow]: subfile(%lu) without inline\n", son_inode->i_ino);
                // set_inode_flag(tmp_inode, FI_INLINE_DATA);
                son_ipage = f2fs_get_node_page(sbi, son_inode->i_ino);
                if (IS_ERR(son_ipage)) {
                    pr_err("[snapfs f2fs_cow]: failed to get src page[%lu]\n", son_inode->i_ino);
                    goto next_free;
                }
                new_ipage = f2fs_get_node_page(sbi, tmp_inode->i_ino);
                if (IS_ERR(new_ipage)) {
                    pr_err("[snapfs f2fs_cow]: failed to get snap page[%lu]\n", tmp_inode->i_ino);
                    f2fs_put_page(son_ipage, 1);
                    goto next_free;
                }
                if (f2fs_has_inline_data(tmp_inode)) {
                    inline_dentry = inline_data_addr(tmp_inode, new_ipage);
                    ret = f2fs_snap_inline_to_dirdata(tmp_inode, inline_dentry, new_ipage);
                    if(ret){
                        f2fs_put_page(son_ipage, 1);
                        f2fs_put_page(new_ipage, 1);
                        pr_info("[snapfs f2fs_cow]: convert inline failed\n");
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
        if (tmp_inode) {
            iput(tmp_inode);
            tmp_inode = NULL;
        }
        goto out_success; 
    }else{
        goto next_free;
    }

out_success:    
    ret = f2fs_set_mulref_blocks(*new_inode);
    
next_free:
    if (son_dentry)
        dput(son_dentry);
    if (snap_dentry)
        dput(snap_dentry);
    
    if (new_dentry) {
        dput(new_dentry);
    }
    if (page)
        f2fs_put_page(page, 1);
    return ret;
}


int f2fs_snapshot_cow(struct inode *inode)
{
    // 判断这个inode是否需要最做cow处理
    struct f2fs_magic_entry tmp_me;
    u32 entry_id;
    struct inode *snap_inode = NULL;
    struct inode *tmp_inode = NULL;
    struct inode *pra_inode = NULL;
    struct inode *son_inode = NULL;
    struct inode *new_inode = NULL;
    struct inode *tmp2_inode = NULL;

    struct f2fs_sb_info *sbi = sbi = F2FS_I_SB(inode);
    struct super_block *sb = inode->i_sb;
    // u8 snap_count = 0;
    int ret;
    struct dentry *parent_dentry = NULL, *dentry = NULL;
    Stack_snap stack;
    nid_t  pra_ino, son_ino;//, snap_ino;
    pr_info("f2fs snapshot cow start debug check must [%u]!\n",inode->i_ino);
    memset(&tmp_me, 0, sizeof(tmp_me));
    // 先判断这个inode是不是快照inode, 
    // 不用执行cow，后续更新引用关系即可
    // pr_info("snapshot cow\n");
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
            if(dentry) dput(dentry);
            dentry = d_find_any_alias(tmp_inode);  // 获取 inode 对应的 dentry
            if (!dentry) {
                pr_err("[snapfs cow]: get dentry failed with inode %lu\n", tmp_inode->i_ino);
                break;
            }
            if(parent_dentry) dput(parent_dentry);
            parent_dentry = dget_parent(dentry);
            pra_inode = parent_dentry->d_inode;
            snap_push(&stack, parent_dentry->d_inode->i_ino);
            if(is_snapshot_inode(pra_inode, &tmp_me, &entry_id)){
                if(timespec64_compare(&(tmp_me.c_time), &(inode->i_ctime)) < 0){
                    // 新文件或者创建快照后修改文件 都直接返回，不需要做cow
                    pr_info("It is snap, but file is newfile\n");
                    goto out;
                }
                pr_info("[snapfs f2fs_snapshot_cow]: prafile(%u) is snap-(%u)\n",
                    tmp_me.src_ino, tmp_me.snap_ino);
                snap_inode = f2fs_iget(sb, le32_to_cpu(tmp_me.snap_ino));
                tmp2_inode = snap_inode;
                // 获取push压栈的目录路径
                while (!snap_isEmpty(&stack)) {    
                                   
                    ret = snap_pop2(&stack, &pra_ino, &son_ino);
                    if(ret) {
                        // pr_info("cow stack is done\n");
                        break;
                    }
                    pra_ino = snap_pop(&stack);
                    pra_inode = f2fs_iget(sb, pra_ino);//tmp_pra_inode
                    son_inode = f2fs_iget(sb, son_ino);
                    parent_dentry = d_find_any_alias(pra_inode);
                    dentry = d_find_any_alias(son_inode);
                    ret = f2fs_cow(pra_inode, tmp2_inode, son_inode, &new_inode);
                    if(ret){
                        pr_info("parent cow failed\n");
                        goto success;
                    }
                    tmp2_inode = new_inode;
                }
            } 
            if(parent_dentry == sb->s_root){// 找到根了
                ret = 1;
                goto success;
            }
            tmp_inode = parent_dentry->d_inode;
        }
    }
    
success:
    if (pra_inode)
        iput(pra_inode);
    if (son_inode)
        iput(son_inode);
    if (snap_inode)
        iput(snap_inode);
    if (tmp2_inode && tmp2_inode != snap_inode) {
        iput(tmp2_inode);
        tmp2_inode = NULL;
    }

out:
    if (parent_dentry)
        dput(parent_dentry);
    if (dentry)
        dput(dentry);
    pr_info("f2fs snapshot cow check or cow over[%d]\n",ret);
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

	if (test_bit(blkoff, (unsigned long *)me->mvalid_map)) {
		up_read(&smi->smentry_lock);
		return true;
	}
	up_read(&smi->smentry_lock);
	return false;
}

static int f2fs_get_summary_by_addr(struct f2fs_sb_info *sbi,
                                    block_t blkaddr,
                                    struct f2fs_summary *sum)
{
    unsigned int segno = GET_SEGNO(sbi, blkaddr);
    unsigned int blkoff = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);
    unsigned int type;
    struct curseg_info *curseg;
    struct f2fs_summary_block *sum_blk;
    struct page *sum_page;

    /* 1. 先查 curseg cache */
    for (type = CURSEG_HOT_DATA; type <= CURSEG_COLD_DATA; type++) {
        curseg = CURSEG_I(sbi, type);
        if (curseg->segno == segno && curseg->sum_blk) {
            *sum = curseg->sum_blk->entries[blkoff];
            return 0;
        }
    }
    /* 2. 不在 cache → 查 SSA */
    sum_page = f2fs_get_sum_page(sbi, segno);
    if (IS_ERR(sum_page))
        return PTR_ERR(sum_page);

    sum_blk = (struct f2fs_summary_block *)page_address(sum_page);
    *sum = sum_blk->entries[blkoff];
    f2fs_put_page(sum_page, 1);
    return 0;
}

int f2fs_get_mulref_block(struct f2fs_sb_info *sbi, block_t blkaddr,
                 struct page **out_page, struct f2fs_mulref_block **out_blk)
{
	struct f2fs_sm_info *sm = SM_I(sbi);
	struct curmulref_info *cmr = &sm->curmulref_blk;
	struct page *page;
    block_t start_addr = sbi->magic_info->mulref_blkaddr;
    if (out_blk)
        *out_blk = NULL;
    if (out_page) *out_page = NULL;

    if (!out_page || !out_blk) {
        f2fs_err(sbi, "f2fs get mulref_block_full: output params are NULL");
        return -EINVAL;
    }
	/* sanity */
	if (blkaddr == NULL_ADDR || blkaddr < start_addr){
        pr_info("blkaddr is error\n");
		return 1;
    }
	/*c
	 * Fast path:
	 * current active mulref block
	 */
	if (cmr->inited && blkaddr == cmr->blkaddr) {
		if (unlikely(!cmr->page || !cmr->blk)){
			f2fs_err(sbi, "f2fs get mulref_block: cmr inited but page/blk is NULL\n");
            return -EIO;
        }
        get_page(cmr->page);
        // *out_page = cmr->page;
        *out_page = NULL;
        *out_blk = cmr->blk;
		return 0;
	}
	/*
	 * Slow path:
	 * read from meta area
	 */
	page = f2fs_get_meta_page(sbi,  blkaddr);
	if (IS_ERR(page)){
        f2fs_err(sbi, "f2fs get mulref_block: f2fs_get_meta_page failed\n");
		return 1;
    }
    *out_page = page;
    *out_blk = (struct f2fs_mulref_block *)page_address(page);
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
	if (cmr->inited && blkaddr == cmr->blkaddr) {
		page = cmr->page;
	} else {
		page = virt_to_page(blk);
	}

	f2fs_put_page(page, 1);
}


// f2fs_mulref_remove_nid
int f2fs_mulref_overwrite(struct f2fs_sb_info *sbi,
                          block_t old_blkaddr,
                          nid_t new_nid)
{
    struct f2fs_summary old_sum;
    struct f2fs_mulref_block *cur_blk = NULL, *prev_blk = NULL, *head_blk = NULL;
    struct f2fs_mulref_block *next_blk = NULL;
    struct f2fs_mulref_entry *cur_entry = NULL;
    struct f2fs_mulref_entry *prev_entry = NULL;
    block_t cur_mr_blkaddr, next_mr_blkaddr, prev_mr_blkaddr;
    u16 cur_eidx, next_eidx, prev_eidx;
    // u32 next;
    u32 cur_next, prev_next;
    int ret = 0;
    block_t base = sbi->magic_info->mulref_blkaddr;
    bool is_head = false;
    bool has_cross_blk = false;
    struct page *head_page = NULL;
    struct page *mulref_page = NULL;
    struct page *cur_page = NULL;
    struct f2fs_summary new_sum;
    unsigned int old_segno, blk_off;

    old_segno = GET_SEGNO(sbi, old_blkaddr);
    blk_off = GET_BLKOFF_FROM_SEG0(sbi, old_blkaddr);
    /* ---------- 1. 读取 old summary ---------- */
    ret = f2fs_get_summary_by_addr(sbi, old_blkaddr, &old_sum);
    if (ret)
        return ret;
    // pr_info("f2fs mulref overwrite: blk[%u]\n",old_blkaddr);
    /* ---------- 2. 定位 mulref block ---------- */
    cur_mr_blkaddr = (block_t)le32_to_cpu(old_sum.nid);
    cur_eidx = le32_to_cpu(old_sum.ofs_in_node);

    pr_info("ori_sum: (overwrite)nid[%u],ofs[%u],ver[%u]\n",le32_to_cpu(old_sum.nid)
         ,old_sum.ofs_in_node, old_sum.version);

    
     /* 获取第一个 block */
    ret = f2fs_get_mulref_block(sbi, cur_mr_blkaddr, &head_page, &head_blk);
    if (ret) {
        pr_info("f2fs get mulref block failed!\n");
        return -EIO;
    }

    /* 初始化 prev 指针 */
    prev_mr_blkaddr = 0;
    prev_eidx = 0;
    prev_blk = NULL;
    prev_next = 0;

    cur_blk = head_blk;
    /* 检查第一个节点是否就是要找的 */
    cur_entry = &cur_blk->mrentries[cur_eidx];
    
    if ((nid_t)le32_to_cpu(cur_entry->m_nid) == new_nid) {
        is_head = true;
        goto found_entry;
    }

    // /* 保存 prev 信息 */
    pr_info("prepare enter while %u\n",new_nid);
    cur_next = le32_to_cpu(cur_entry->next);
    /* ---------- 3. 查找匹配 new_nid 的 entry ---------- */
    while (1) {
        //
        prev_mr_blkaddr = cur_mr_blkaddr;
        prev_blk = cur_blk;
        prev_eidx = cur_eidx;
        prev_next = cur_next;
        prev_entry = cur_entry;
        /* 计算下一个 entry 的位置 */
        cur_mr_blkaddr = base + cur_next / MRENTRY_PER_BLOCK;
        cur_eidx = cur_next % MRENTRY_PER_BLOCK;

        /* 获取当前 entry 所在的 block */
        if (cur_mr_blkaddr != prev_mr_blkaddr) {// 跨块处理
            pr_info("cross blk\n");
            ret = f2fs_get_mulref_block(sbi, cur_mr_blkaddr,&cur_page,&cur_blk);
            if (ret) {
                pr_info("failed to get mulref block %u\n", cur_mr_blkaddr);
                ret = -EIO;
                goto out;
            }
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
            pr_info("found mulref entry nid[%u]\n",le32_to_cpu(cur_entry->m_nid));
            /* 找到目标 entry，现在需要更新前驱节点的 next 指针 */
            break;
        }
        // pr_info("not found mulref entry nid[%u] with head\n",le32_to_cpu(cur_entry->m_nid));
        if (!cur_next){
            pr_info("not found\n");
            ret = 1;
            goto out;
        }
        next_mr_blkaddr = base + cur_next / MRENTRY_PER_BLOCK;
        next_eidx = cur_next % MRENTRY_PER_BLOCK;
        // 前两个跨块的entry都没有命中，第三个entry也跨块
        // 这时就没必要保留那么多的块信息了，释放最早的块信息
        // 因为即使更新，也只会发生在后面的块之间
        if((next_mr_blkaddr != cur_mr_blkaddr)){// 要开始跨块了
            // 非head，跨3个块
            if(prev_mr_blkaddr != (block_t)le32_to_cpu(old_sum.nid)){
                // head blk保留， 非head blk才删除
                if(mulref_page != cur_page){
                    f2fs_put_page(mulref_page, 1);
                    mulref_page = NULL;
                }
            }
            mulref_page = cur_page;
            continue;
        }    
    }

found_entry:
    /* ---------- 4. 删除找到的 entry ---------- */
    /* 标记当前 entry 无效并减少引用计数 */
    if (is_head) {
        /* 当前节点就是链表头 */
        mulref_page = NULL;
        cur_page = NULL;

        pr_info("found at head, entry_nid[%u], new_nid %u\n",le32_to_cpu(cur_entry->m_nid), new_nid);
        cur_next = le32_to_cpu(cur_entry->next);
        /* 更新 old_sum（链表头变化了） */
        if (cur_next) {
            next_mr_blkaddr = base + cur_next / MRENTRY_PER_BLOCK;
            next_eidx = cur_next % MRENTRY_PER_BLOCK;
            if(next_mr_blkaddr == cur_mr_blkaddr){//同一个mulref块
                // prev_mr_blkaddr = cur_mr_blkaddr;
                // prev_blk = cur_blk;
                // prev_eidx = cur_eidx;
                // prev_next = cur_next;
                cur_entry = &cur_blk->mrentries[next_eidx];
                if(!le32_to_cpu(cur_entry->next)){
                    // 刚好就2个多引用，这时要多变1
                    pr_info("走这个分支!!\n");
                    new_sum.nid = cur_entry->m_nid;
                    new_sum.ofs_in_node = cur_entry->m_ofs;
                    new_sum.version = cur_entry->m_ver;
                    mulref_mark_invalid(cur_blk, cur_next);
                    mulref_mark_invalid(cur_blk, next_eidx);
                    // 清除多引用块flag
                    update_sit_mulref_entry(sbi, old_blkaddr, false);
                }else{
                    // 3个引用以上，去掉head后，还是多引用
                    // 更新head信息
                    new_sum.nid = next_mr_blkaddr;
                    new_sum.ofs_in_node = next_eidx;
                    new_sum.version = cur_entry->m_ver;
                    cur_entry->m_count -= 1;
                    mulref_mark_invalid(cur_blk, cur_next);
                    // 不用清楚多引用块flag
                }
                
            }else{// head 垮块处理
                // prev_mr_blkaddr = cur_mr_blkaddr;
                prev_blk = cur_blk;
                // prev_eidx = cur_eidx;
                // prev_next = cur_next;
                ret = f2fs_get_mulref_block(sbi, next_mr_blkaddr, &mulref_page, &cur_blk);
                if (ret) {
                    pr_info("f2fs get mulref block failed-next_mr_blkaddr!\n");
                    return -EIO;
                }
                cur_entry = &cur_blk->mrentries[next_eidx];
                if(!le32_to_cpu(cur_entry->next)){
                    // 刚好就2个多引用，这时要多变1
                    new_sum.nid = cur_entry->m_nid;
                    new_sum.ofs_in_node = cur_entry->m_ofs;
                    new_sum.version = cur_entry->m_ver;
                    mulref_mark_invalid(prev_blk, cur_eidx);// 前一个块
                    mulref_mark_invalid(cur_blk, next_eidx);// 跨块
                    // 清除多引用块flag
                    update_sit_mulref_entry(sbi, old_blkaddr, false);
                }else{
                    // 3个引用以上，去掉head后，还是多引用
                    // 更新head信息
                    new_sum.nid = next_mr_blkaddr;
                    new_sum.ofs_in_node = next_eidx;
                    new_sum.version = cur_entry->m_ver;
                    cur_entry->m_count -= 1;
                    mulref_mark_invalid(prev_blk, cur_eidx);// 前一个块
                }
                
            }
        }else{
            pr_info("orphan mulref entry, error\n");
        } 
        /* ---------- 5. 更新 summary ---------- */
        /* 注意：这里需要加锁，因为 summary 可能在 curseg 中 */
        /* 暂时注释掉，实际使用时需要实现 f2fs_set_summary 的加锁版本 */
        /* f2fs_set_summary(sbi, old_blkaddr, &old_sum); */
               
        ret = f2fs_update_summary_without_lock(sbi, old_blkaddr,&new_sum,old_segno,blk_off);
        // __update_sum_entry(sbi, DATA, blk_off, &new_sum);

        if(ret){
            pr_info("[snapfs debug]: (overwrite)update summary failed\n");
        }else{
            pr_info("[snapfs debug]: (overwrite)update summary success!\n");    
        }
        if(head_page){
            pr_info("release head page\n");
            set_page_dirty(head_page);
            f2fs_put_page(head_page, 1);
        }
        if(mulref_page && mulref_page != head_page){
            pr_info("release mulref page\n");
            set_page_dirty(mulref_page);
            f2fs_put_page(mulref_page, 1);
        }
        return ret;
    } else {
        /* 当前节点不是链表头，需要更新前驱节点的 next 指针 */
        if(cur_next){ // 中间点
            // 更新前节点
            if(head_blk == prev_blk){
                head_blk->mrentries[le32_to_cpu(old_sum.ofs_in_node)].m_count--;
                head_blk->mrentries[le32_to_cpu(old_sum.ofs_in_node)].next = cpu_to_le32(cur_next);
            }else{
                prev_blk->mrentries[prev_eidx].m_count--;
                prev_blk->mrentries[prev_eidx].next = cpu_to_le32(cur_next);
            }
            
            next_mr_blkaddr = base + cur_next / MRENTRY_PER_BLOCK;
            next_eidx = cur_next % MRENTRY_PER_BLOCK;

            if (cur_mr_blkaddr != next_mr_blkaddr) {
                // 跨块处理
                if((mulref_page != cur_page) && (mulref_page != head_page)){
                    set_page_dirty(mulref_page);//释放前一个块
                    f2fs_put_page(mulref_page, 1);
                    mulref_page = NULL;
                }
                mulref_page = cur_page;
                prev_mr_blkaddr = cur_mr_blkaddr;
                prev_blk = cur_blk;
                prev_eidx = cur_eidx;
                // prev_next = cur_next;
                // prev_entry = cur_entry;
                ret = f2fs_get_mulref_block(sbi, next_mr_blkaddr,&cur_page,&cur_blk);
                if (ret) {
                    pr_info("failed to get mulref block2 %u\n", next_mr_blkaddr);
                    ret = -EIO;
                    cur_page = NULL;
                    goto out;
                }
            }
            cur_blk->mrentries[next_eidx].m_count = head_blk->mrentries[le32_to_cpu(old_sum.ofs_in_node)].m_count;
            mulref_mark_invalid(prev_blk, prev_eidx);

            if(head_page){
                pr_info("release head page\n");
                set_page_dirty(head_page);
                f2fs_put_page(head_page, 1);
            }
            if(mulref_page && mulref_page != head_page){
                pr_info("release mulref page\n");
                set_page_dirty(mulref_page);
                f2fs_put_page(mulref_page, 1);
            }
            if(cur_page && cur_page != head_page && cur_page != mulref_page){
                pr_info("release cur page\n");
                set_page_dirty(cur_page);
                f2fs_put_page(cur_page, 1);
            }
        }else{ // tail 节点
            if(head_blk == prev_blk){
                //prev如果是head，那就刚好是2个引用
                // 刚好就2个多引用，这时要多变1
                new_sum.nid = head_blk->mrentries[le32_to_cpu(old_sum.ofs_in_node)].m_nid;
                new_sum.ofs_in_node = head_blk->mrentries[le32_to_cpu(old_sum.ofs_in_node)].m_ofs;
                new_sum.version = head_blk->mrentries[le32_to_cpu(old_sum.ofs_in_node)].m_ver;
                mulref_mark_invalid(head_blk, prev_eidx);// 前一个块，head
                mulref_mark_invalid(cur_blk, next_eidx);// tail
                // 清除多引用块flag
                update_sit_mulref_entry(sbi, old_blkaddr, false);

                ret = f2fs_update_summary_without_lock(sbi, old_blkaddr,&new_sum,old_segno,blk_off);
                // __update_sum_entry(sbi, DATA, blk_off, &new_sum);
                if(ret){
                    pr_info("[snapfs debug]: (overwrite)update summary failed(non head)\n");
                }else{
                    pr_info("[snapfs debug]: (overwrite)update summary success!(non head)\n");
                }    
            }
            
            head_blk->mrentries[le32_to_cpu(old_sum.ofs_in_node)].m_count--;
            prev_blk->mrentries[prev_eidx].m_count--;
            prev_blk->mrentries[prev_eidx].next = 0;
            mulref_mark_invalid(cur_blk, cur_eidx);

            if(head_page){
                pr_info("release head page\n");
                set_page_dirty(head_page);
                f2fs_put_page(head_page, 1);
            }
            if(mulref_page && mulref_page != head_page){
                pr_info("release mulref page\n");
                set_page_dirty(mulref_page);
                f2fs_put_page(mulref_page, 1);
            }
            if(cur_page && cur_page != head_page && cur_page != mulref_page){
                pr_info("release cur page\n");
                set_page_dirty(cur_page);
                f2fs_put_page(cur_page, 1);
            }
        }
        /* 标记当前节点无效 */
    }
    
out:
    /* ---------- 6. 清理资源 ---------- */
    // if(head_page){
    //     pr_info("release head page\n");
    //     set_page_dirty(head_page);
    //     f2fs_put_page(head_page, 1);
    // }
    // if(mulref_page && mulref_page != head_page){
    //     pr_info("release mulref page\n");
    //     set_page_dirty(mulref_page);
    //     f2fs_put_page(mulref_page, 1);
    // }
    // if(cur_page && cur_page != head_page && cur_page != mulref_page){
    //     pr_info("release cur page\n");
    //     set_page_dirty(cur_page);
    //     f2fs_put_page(cur_page, 1);
    // }
    return ret;
}

void f2fs_mulref_replace_block(struct f2fs_sb_info *sbi, block_t old_addr, block_t new_addr, struct f2fs_summary *old_sum)
{
    struct sit_mulref_info *smi = SIT_MR_I(sbi);
    struct sit_mulref_entry *me;
    unsigned int segno, blkoff;
    unsigned short old_offset;
    // struct f2fs_summary old_sum;
    // block_t mulref_blk_addr;
    int ret = 0;

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
    if (!test_bit(old_offset, (unsigned long *)me->mvalid_map)) {
        pr_warn("Old block %u is not a valid mulref block.\n", old_addr);
        up_write(&smi->smentry_lock);
        return;
    }

    // 清除 old_addr 对应的多引用标志位
    clear_bit(old_offset, (unsigned long *)me->mvalid_map);
    // 设置 new_addr 对应的多引用标志位
    set_bit(GET_BLKOFF_FROM_SEG0(sbi, new_addr), (unsigned long *)me->mvalid_map);

    // 更新 m_mtime 时间戳. todo
    // update_segment_mtime(sbi, new_addr,0);

    up_write(&smi->smentry_lock);
}


