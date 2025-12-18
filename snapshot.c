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
        u32 src_ino,
        u32 *ret_entry_id,
        struct f2fs_magic_entry **ret_entry,
        struct page **ret_page)
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
    if (!sbi->magic_info) {
        pr_err("magic_info is NULL!\n");
        return -ENOENT;
    }
    // 加锁保护整个查找/分配过程
    mutex_lock(&sbi->magic_info->mutex);
    for (i = 0; i < MAGIC_ENTRY_NR; i++) {
        entry_id = (h1 + i * h2) % MAGIC_ENTRY_NR;
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
    mutex_lock(&sbi->magic_info->mutex);
    for (i = 0; i < MAGIC_ENTRY_NR; i++) {
        entry_id = (h1 + i * h2) % MAGIC_ENTRY_NR;
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
	if (f2fs_magic_lookup(sbi, inode->i_ino, &tmp_entry_id, &tmp_me)) {// 未找到或者冲突未解决
		pr_info("[snapfs dump]: not Found at entry_id\n");
        return false;
	}
    memcpy(me, &tmp_me, sizeof(tmp_me));
    *entry_id = tmp_entry_id;
    return true;
}


// /mnt/df/dir/*  快照df /mnt/snap/dir/*
// 原始df/dir、dir/* 就是pra_inode/son_inodes
// 快照snap/dir、dir/* 就是snap_inode/new_inode
// 两个dir inode不同
// 函数作用: 创建新的inode，共享旧数据块引用，即生成new_inode

        // new_dentry = lookup_one_len(d_name->name, snap_dentry, strlen(d_name->name));
        // if (IS_ERR(new_dentry)) {
        //     ret = PTR_ERR(new_dentry);
        //     new_dentry = NULL;
        //     pr_info("[snapfs f2fs_cow]: lookup_one_len failed!!!\n");
        // }
        // // 添加目录项
        // // 在snap_inode下创建一个新的inode，mode保持和被快照目录下的inode一致
        // mode = snap_inode->i_mode;

        // if(S_ISDIR(son_inode->i_mode)){
        //     ret = vfs_mkdir(mnt_user_ns(parent_path), snap_inode, new_dentry, mode);
        // }else if(S_ISREG(son_inode->i_mode)){
        //     ret = vfs_create(mnt_user_ns(parent_path), snap_inode, new_dentry, mode, true);
        // }

        // tmp_inode = new_dentry->d_inode;
        // if(!tmp_inode){
        //     pr_info("[snapfs f2fs_cow]: tmp_inode failed!!!\n");
        //     ret = -1;
        //     goto next_free;
        // }

int f2fs_cow(struct inode *pra_inode,
             struct inode *snap_inode,
             struct inode *son_inode,
             struct inode **new_inode){
    // 判断name of son_inode是否已经存在snap_inode下
    struct dentry *snap_dentry, *son_dentry;
	struct f2fs_dir_entry *de;
    struct page *page;
    struct super_block *sb = pra_inode->i_sb;
    struct inode *tmp_inode = NULL;
    umode_t mode;
    int ret = 0;
    struct qstr *d_name;
    struct f2fs_sb_info *sbi = F2FS_I_SB(pra_inode);
    nid_t ino;
    struct page *son_ipage, *new_ipage;
    struct page *new_dpage;
    void *page_addr;
	void *inline_dentry; // inline数据
	void *inline_dentry2;

    struct f2fs_inode *son_fi;
    struct f2fs_inode *new_fi;
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

    dget(son_dentry);
    dget(snap_dentry);
    d_name = &son_dentry->d_name;
    de = f2fs_find_entry(snap_inode, d_name, &page);
    if(de){
        pr_info("[snapfs f2fs_cow]: dentry[%s] found in [%lu]\n", d_name->name, snap_inode->i_ino);
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
        f2fs_lock_op(sbi);
        /* 4. 在 snap_inode 下创建目录项 link */
        ret = f2fs_add_link(snap_dentry, tmp_inode);
        if (ret) {
            f2fs_unlock_op(sbi);
            pr_err("[snapfs f2fs_cow]: failed to add link: %d\n", ret);
            goto next_free;
        }
        f2fs_unlock_op(sbi);
        f2fs_alloc_nid_done(sbi, ino);
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
        if (f2fs_has_inline_dentry(son_inode)) {
            if(S_ISDIR(son_inode->i_mode)){
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
            }else if(S_ISREG(son_inode->i_mode)){
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
            }
        } else{ // non inline process
            if(S_ISDIR(son_inode->i_mode)){
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
                new_fi->i_mode = son_fi->i_mode;
                new_fi->i_advise = son_fi->i_advise;
                new_fi->i_inline = son_fi->i_inline;
                new_fi->i_uid = son_fi->i_uid;
                new_fi->i_gid = son_fi->i_gid;
                new_fi->i_size = son_fi->i_size;
                new_fi->i_blocks = son_fi->i_blocks;  // 这个很重要！
                new_fi->i_atime = son_fi->i_atime;
                new_fi->i_ctime = son_fi->i_ctime;
                new_fi->i_mtime = son_fi->i_mtime;
                new_fi->i_atime_nsec = son_fi->i_atime_nsec;
                new_fi->i_ctime_nsec = son_fi->i_ctime_nsec;
                new_fi->i_mtime_nsec = son_fi->i_mtime_nsec;
                new_fi->i_generation = son_fi->i_generation;
                new_fi->i_current_depth = son_fi->i_current_depth;
                new_fi->i_flags = son_fi->i_flags;
                new_fi->i_namelen = son_fi->i_namelen;
                tmp_inode->i_size = le64_to_cpu(son_fi->i_size);
                tmp_inode->i_blocks = le64_to_cpu(son_fi->i_blocks);
                // 复制文件名（如果存在）
                if (son_fi->i_namelen > 0 && son_fi->i_namelen <= F2FS_NAME_LEN) {
                    memcpy(new_fi->i_name, son_fi->i_name, son_fi->i_namelen);
                    new_fi->i_namelen = son_fi->i_namelen;
                }
                new_fi->i_dir_level = son_fi->i_dir_level;
                // 复制extent信息
                memcpy(&new_fi->i_ext, &son_fi->i_ext, sizeof(struct f2fs_extent));
                
                for (idx = 0; idx < 5; idx++) {
                    new_fi->i_nid[idx] = son_fi->i_nid[idx];
                }
                if (tmp_inode->i_blocks > 0) {
                    unsigned int valid_blocks = tmp_inode->i_blocks / (F2FS_BLKSIZE >> 9);
                    f2fs_i_blocks_write(tmp_inode, valid_blocks, true, true);
                }
                memcpy(new_fi->i_addr, son_fi->i_addr, sizeof(son_fi->i_addr));
                
                tmp_inode->i_mode = son_inode->i_mode;
                tmp_inode->i_opflags = son_inode->i_opflags;
                tmp_inode->i_uid = son_inode->i_uid;
                tmp_inode->i_gid = son_inode->i_gid;
                tmp_inode->i_flags = son_inode->i_flags;
                if (S_ISCHR(son_inode->i_mode) || S_ISBLK(son_inode->i_mode)) {
                    tmp_inode->i_rdev = son_inode->i_rdev;
                }
                tmp_inode->i_atime = son_inode->i_atime;
                tmp_inode->i_mtime = son_inode->i_mtime;
                tmp_inode->i_ctime = son_inode->i_ctime;
                tmp_inode->i_blkbits = son_inode->i_blkbits;
                tmp_inode->i_write_hint = son_inode->i_write_hint;
                tmp_inode->i_bytes = son_inode->i_bytes;
                tmp_inode->i_version = son_inode->i_version;
                tmp_inode->i_sequence = son_inode->i_sequence;
                tmp_inode->i_generation = son_inode->i_generation;
                tmp_inode->dirtied_when = son_inode->dirtied_when;
                tmp_inode->dirtied_time_when = son_inode->dirtied_time_when;
                set_page_dirty(new_ipage);
                f2fs_put_page(son_ipage, 1);
                f2fs_put_page(new_ipage, 1);
                new_dpage = f2fs_get_lock_data_page(tmp_inode, 0, false);
                page_addr = page_address(new_dpage);
                make_dentry_ptr_block(tmp_inode, &d, page_addr);
                f2fs_update_dentry(tmp_inode->i_ino, tmp_inode->i_mode, &d, &dot, 0, 0);
                f2fs_update_dentry(tmp_inode->i_ino, tmp_inode->i_mode, &d, &dotdot, 0, 1);
                f2fs_put_page(new_dpage, 1);
            } else if(S_ISREG(son_inode->i_mode)){
                pr_info("[snapfs f2fs_cow]: subfile(%lu) without inline\n", son_inode->i_ino);
                set_inode_flag(tmp_inode, FI_INLINE_DATA);
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
                if (f2fs_has_inline_dentry(tmp_inode)) {
                    inline_dentry = inline_data_addr(tmp_inode, new_ipage);
                    // 执行convert， 主要是删除inline数据区域和清除inline flag
                    // f2fs_snap_inline_to_dirdata
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
                new_fi->i_mode = son_fi->i_mode;
                new_fi->i_advise = son_fi->i_advise;
                new_fi->i_inline = son_fi->i_inline;
                new_fi->i_uid = son_fi->i_uid;
                new_fi->i_gid = son_fi->i_gid;
                new_fi->i_size = son_fi->i_size;
                new_fi->i_blocks = son_fi->i_blocks;  // 这个很重要！
                new_fi->i_atime = son_fi->i_atime;
                new_fi->i_ctime = son_fi->i_ctime;
                new_fi->i_mtime = son_fi->i_mtime;
                new_fi->i_atime_nsec = son_fi->i_atime_nsec;
                new_fi->i_ctime_nsec = son_fi->i_ctime_nsec;
                new_fi->i_mtime_nsec = son_fi->i_mtime_nsec;
                new_fi->i_generation = son_fi->i_generation;
                new_fi->i_current_depth = son_fi->i_current_depth;
                new_fi->i_flags = son_fi->i_flags;
                new_fi->i_namelen = son_fi->i_namelen;
                tmp_inode->i_size = le64_to_cpu(son_fi->i_size);
                tmp_inode->i_blocks = le64_to_cpu(son_fi->i_blocks);
                // 复制文件名（如果存在）
                if (son_fi->i_namelen > 0 && son_fi->i_namelen <= F2FS_NAME_LEN) {
                    memcpy(new_fi->i_name, son_fi->i_name, son_fi->i_namelen);
                    new_fi->i_namelen = son_fi->i_namelen;
                }
                new_fi->i_dir_level = son_fi->i_dir_level;
                // 复制extent信息
                memcpy(&new_fi->i_ext, &son_fi->i_ext, sizeof(struct f2fs_extent));
                
                for (idx = 0; idx < 5; idx++) {
                    new_fi->i_nid[idx] = son_fi->i_nid[idx];
                }
                if (tmp_inode->i_blocks > 0) {
                    unsigned int valid_blocks = tmp_inode->i_blocks / (F2FS_BLKSIZE >> 9);
                    f2fs_i_blocks_write(tmp_inode, valid_blocks, true, true);
                }
                memcpy(new_fi->i_addr, son_fi->i_addr, sizeof(son_fi->i_addr));
                
                tmp_inode->i_mode = son_inode->i_mode;
                tmp_inode->i_opflags = son_inode->i_opflags;
                tmp_inode->i_uid = son_inode->i_uid;
                tmp_inode->i_gid = son_inode->i_gid;
                tmp_inode->i_flags = son_inode->i_flags;
                if (S_ISCHR(son_inode->i_mode) || S_ISBLK(son_inode->i_mode)) {
                    tmp_inode->i_rdev = son_inode->i_rdev;
                }
                tmp_inode->i_atime = son_inode->i_atime;
                tmp_inode->i_mtime = son_inode->i_mtime;
                tmp_inode->i_ctime = son_inode->i_ctime;
                tmp_inode->i_blkbits = son_inode->i_blkbits;
                tmp_inode->i_write_hint = son_inode->i_write_hint;
                tmp_inode->i_bytes = son_inode->i_bytes;
                tmp_inode->i_version = son_inode->i_version;
                tmp_inode->i_sequence = son_inode->i_sequence;
                tmp_inode->i_generation = son_inode->i_generation;
                tmp_inode->dirtied_when = son_inode->dirtied_when;
                tmp_inode->dirtied_time_when = son_inode->dirtied_time_when;
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
        }
        f2fs_mark_inode_dirty_sync(snap_inode, true);
        f2fs_mark_inode_dirty_sync(tmp_inode, true);
        *new_inode = tmp_inode;
        goto out_success; 
    }

out_success:
    ret = 0;

next_free:
    if (son_dentry)
        dput(son_dentry);
    if (snap_dentry)
        dput(snap_dentry);
    if (tmp_inode) {
        iput(tmp_inode);
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
    struct f2fs_sb_info *sbi = sbi = F2FS_I_SB(inode);
    struct super_block *sb = inode->i_sb;
    // u8 snap_count = 0;
    int ret;
    struct dentry *parent_dentry, *dentry;
    Stack_snap stack;
    nid_t  pra_ino, son_ino;//, snap_ino;

    memset(&tmp_me, 0, sizeof(tmp_me));
    // 先判断这个inode是不是快照inode, 
    // 不用执行cow，后续更新引用关系即可
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
                    ret = f2fs_cow(pra_inode, snap_inode, son_inode, &new_inode);
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
