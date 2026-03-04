Context                                                                  
                  
     用户反馈 snapshot.c 中 f2fs_set_mulref_blocks() 在 20GB 文件 CoW
     时耗时约 1.94s，瓶颈来自遍历方式而非并发能力。当前实现按 lblk
     逐块扫描并频繁 f2fs_get_node_page()/f2fs_put_page()，导致 node page
     访问次数过高。用户明确约束：
     1. 必须严格按文件 i_size 对应的实际块数处理（不能盲扫整层 1018）。
     2. 在调用 set_mulref_entry() 前释放当前 node page，避免 page
     持有对下游路径产生干扰。
     3. 不引入多线程，保持串行与现有锁模型。

     Recommended approach

     1) 仅重构 f2fs_set_mulref_blocks() 的遍历策略

     关键修改文件：
     - /home/lch/workspace/f2fs_snap/snapshot.c

     关键位置：
     - f2fs_set_mulref_blocks：snapshot.c:2543 起
     - 热点调用 set_mulref_entry：snapshot.c:2620, 2664, 2702, 2763, 2818,
      2889
     - 错误返回点：snapshot.c:2903-2909

     改为“node-by-node”遍历，而非“lblk-by-lblk”：
     - 先计算 max_lblk 后维护 remaining = max_lblk。
     - 每一层只处理 min(remaining, layer_capacity)。
     - 按层（direct / i_nid[0] / i_nid[1] / indirect /
     double-indirect）分段推进并递减 remaining，remaining==0 立即结束。

     2) 统一采用两阶段处理，保证先放页再 set

     在每个 node 页（inode page/direct node/indirect 子 direct
     node）上执行：
     - Phase A（collect）：持页状态下仅提取有效 blkaddr 到临时数组，不调用
      set_mulref_entry。
     - 立即 f2fs_put_page(...) 释放页。
     - Phase B（apply）：逐项调用 set_mulref_entry(...)。

     这样满足用户“调用 set 前释放 page”的约束，同时不改变下层锁语义。

     3) 临时缓冲区采用一次性 kmalloc 复用

     在函数入口分配、出口统一释放：
     - block_t *blk_buf = kmalloc_array(ADDRS_PER_BLOCK(inode),
     sizeof(block_t), GFP_NOFS);
     - 可选配套 nid_t *nid_buf（若某些层需要按条目标注 owner nid）。

     采用 kmalloc 的原因：
     - ADDRS_PER_BLOCK=1018，单个 block_t[1018] 约
     4KB；若放栈上再叠加局部变量与调用深度，内核栈压力偏高。
     - 一次分配复用避免反复 alloc/free，热路径更稳定。
     - GFP_NOFS 更契合文件系统路径分配语义。

     4) 保持语义不变的最小改动边界

     - 不修改 set_mulref_entry() 和 f2fs_alloc_mulref_entry() 的内部逻辑。
     - 不增加并发，不改变现有锁模型。
     - 仅调整 f2fs_set_mulref_blocks() 内部循环结构、page
     生命周期与错误返回。

     5) 修正错误码返回

     当前函数尾部固定 return 0，会吞掉中途错误；改为返回 ret，并保持 goto
     out 清理路径完整。

     Verification

     1. 编译校验
     - make

     2. 功能回归
     - 使用现有快照创建流程触发 CoW（test_ioctl/test
     ...），确认功能与旧实现一致。
     - 覆盖小文件、跨 direct 边界文件、跨 indirect
     边界文件、大文件（20GB）场景。

     3. 正确性检查
     - 确认每层处理块数不超过 remaining。
     - 确认所有 set_mulref_entry() 调用点前已释放对应 node page。
     - 确认错误路径下 page 与 kmalloc 缓冲均释放，无泄漏。
     - 确认失败时返回非 0 错误码（不再被固定 return 0 覆盖）。

     4. 性能对比
     - 对 20GB 文件测量 CoW 时延；预期 f2fs_get_node_page
     调用次数显著下降，整体耗时明显优于 1.94s。
