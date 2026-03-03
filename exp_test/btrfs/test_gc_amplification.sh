#!/bin/bash
# Btrfs + NVMe GC 放大量化测试脚本
# 目标：让 SSD 进入需要 GC 的状态，然后测量快照的写放大

set -e

# ==================== 配置 ====================
NVME_DEV="/dev/nvme1n1"           # 修改为你的 NVMe 设备
TEST_PART="${NVME_DEV}"         # 测试分区
MOUNT_POINT="/mnt/btrfs_test"     # 挂载点
TEST_DIR="${MOUNT_POINT}/test_data"
SNAP_DIR="${MOUNT_POINT}/snapshots"

# FIO 配置
FIO_SIZE="900G"                   # 写入量：900GB（留 100GB 空间）
FIO_SEQ_BS="1M"                   # 顺序填充块大小
FIO_BS="4k"                       # 块大小
FIO_IODEPTH=32                    # 并发深度

# 是否使用 blktrace（如果遇到权限问题可设为 false）
USE_BLKTRACE=false

# ==================== 检查环境 ====================
check_prereqs() {
    echo "检查依赖..."

    for cmd in nvme fio btrfs bc jq; do
        if ! command -v $cmd &> /dev/null; then
            echo "缺少: $cmd，请安装"
            exit 1
        fi
    done

    if [[ ! -b $NVME_DEV ]]; then
        echo "错误: $NVME_DEV 不存在"
        exit 1
    fi

    echo "✓ 所有依赖已就绪"
}

# ==================== 获取 SMART 指标 ====================
get_smart_metrics() {
    local output=$(nvme smart-log $NVME_DEV)
    echo "$output" | jq -r '
        {
            data_units_written: (.data_units_written | tonumber),
            data_units_read: (.data_units_read | tonumber),
            media_errors: (.media_errors | tonumber),
            available_spare: (.available_spare | tonumber),
            percentage_used: (.percentage_used | tonumber)
        }
    '
}

print_smart() {
    local metrics="$1"
    echo "---------- SMART 指标 ----------"
    echo "主机写入: $(echo $metrics | jq -r '.data_units_written') units (1 unit = 512 KB)"
    echo "主机读取: $(echo $metrics | jq -r '.data_units_read') units"
    echo "媒体错误: $(echo $metrics | jq -r '.media_errors')"
    echo "备用块: $(echo $metrics | jq -r '.available_spare')%"
    echo "使用率: $(echo $metrics | jq -r '.percentage_used')%"
    echo "------------------------------"
}

# ==================== 准备测试环境 ====================
prepare_test_env() {
    echo "准备测试环境..."

    # 卸载可能存在的挂载
    if mountpoint -q $MOUNT_POINT 2>/dev/null; then
        umount $MOUNT_POINT
    fi

    # 如果分区不存在，创建分区（使用整个磁盘）
    # if [[ ! -b $TEST_PART ]]; then
    #     echo "创建分区..."
    #     echo "wipefs -a $NVME_DEV"  # 清除分区表
    #     wipefs -a $NVME_DEV
    #     echo "创建新分区..."
    #     (echo o; echo n; echo p; echo 1; echo ; echo ; echo w) | fdisk $NVME_DEV
    #     partprobe $NVME_DEV
    #     sleep 2
    # fi

    # 创建文件系统
    echo "创建 Btrfs 文件系统..."
    mkfs.btrfs -f -L "btrfs_gc_test" $TEST_PART

    # 挂载
    echo "挂载文件系统..."
    mkdir -p $MOUNT_POINT
    mount $TEST_PART $MOUNT_POINT

    # 创建测试目录
    mkdir -p $TEST_DIR $SNAP_DIR

    # 禁用 Btrfs 的 discard，避免干扰 SSD 内部 GC 行为
    mount -o remount,nodiscard $MOUNT_POINT

    # 开放 SSD 预留空间测试（如果支持）
    echo "获取 SSD 容量信息..."
    nvme id-ctrl $NVME_DEV | grep -i "unproc" || true

    echo "✓ 测试环境准备完成"
}

# ==================== 阶段1：顺序填满 + 随机覆盖（触发 GC 的核心） ====================
fill_drive() {
    echo ""
    echo "========== 阶段1: 填满 SSD + 随机覆盖（制造无效块触发 GC） =========="

    local before_metrics=$(get_smart_metrics)
    print_smart "$before_metrics"

    local write_before=$(echo $before_metrics | jq -r '.data_units_written')
    local time_before=$(date +%s)

    echo "步骤1: 顺序写入 700GB 数据（留足够空间给 COW 操作）..."

    fio --name=seq_fill \
        --directory=$TEST_DIR \
        --rw=write \
        --bs=$FIO_SEQ_BS \
        --size=700G \
        --ioengine=libaio \
        --iodepth=$FIO_IODEPTH \
        --direct=1 \
        --numjobs=1 \
        --group_reporting \
        --time_based=0 \
        --norandommap \
        --randrepeat=0

    echo ""
    echo "步骤2: 随机覆盖写入，制造无效块（触发 GC 的关键步骤）..."
    # 随机写比顺序写更容易制造页级无效块
    # Btrfs COW 机制：每次随机写都需要分配新块
    # 所以需要预留足够空间给 COW 操作
    local rand_rounds=3
    local rand_size=100G  # 每轮只覆盖 100G，留空间给 COW

    for r in $(seq 1 $rand_rounds); do
        echo "  随机覆盖第 $r/$rand_rounds 轮（覆盖范围：100G）..."
        # 随机覆盖，Btrfs 会 COW 分配新块
        # 这会消耗预留空间
        fio --name=rand_overwrite \
            --filename=$TEST_DIR/seq_fill.0.0 \
            --rw=randwrite \
            --bs=4k \
            --iodepth=32 \
            --ioengine=libaio \
            --direct=1 \
            --size=$rand_size \
            --offset=0 \
            --group_reporting \
            --refill_buffers \
            --time_based=0

        # 每轮之间稍作停顿，观察空间变化
        sleep 2
        echo "  当前空间使用:"
        df -h /mnt/btrfs_test | tail -1
    done

    local time_after=$(date +%s)
    local after_metrics=$(get_smart_metrics)
    local write_after=$(echo $after_metrics | jq -r '.data_units_written')

    print_smart "$after_metrics"

    local write_delta=$((write_after - write_before))
    local write_mb=$((write_delta / 2048))
    local duration=$((time_after - time_before))

    echo "填满阶段统计:"
    echo "  写入增量: $write_delta units (约 $write_mb MB)"
    echo "  耗时: $duration 秒"
    echo "  吞吐: $((write_mb / duration)) MB/s"
}

# ==================== 阶段2：制造无效块（模拟删除操作） ====================
invalidate_blocks() {
    echo ""
    echo "========== 阶段2: 制造无效块（为 GC 创造条件） =========="

    echo "删除部分文件（制造无效块）..."
    find $TEST_DIR -type f | head -n 100000 | xargs rm -f

    # 重要：不要 trim！我们要让 SSD 内部有脏块
    echo "注意: 未执行 TRIM，让 SSD 内部保留无效块"
}

# ==================== 阶段3：执行快照并测量写放大 ====================
run_snapshot_gc_test() {
    echo ""
    echo "========== 阶段3: 快照 + GC 放大测试 =========="

    # 多次循环测试
    local iterations=5

    # 检查 blktrace 是否可用
    if [[ "$USE_BLKTRACE" == "true" ]]; then
        # 简单测试 blktrace 是否能启动
        blktrace -d $TEST_PART -o /tmp/blktrace_test -n 1 >/dev/null 2>&1 &
        sleep 1
        killall blktrace 2>/dev/null || true
        if [[ ! -f /tmp/blktrace_test.blktrace.0 ]]; then
            echo "警告: blktrace 无法正常工作（权限问题），已禁用 blktrace"
            USE_BLKTRACE=false
        fi
        rm -f /tmp/blktrace_test.blktrace.* 2>/dev/null || true
    fi

    if [[ "$USE_BLKTRACE" == "true" ]]; then
        echo "使用 blktrace 记录块层 I/O"
    else
        echo "注意: blktrace 已禁用，仅使用 SMART 数据计算写放大"
        echo "      (无法区分主机写入和 SSD GC 写入)"
    fi
    echo ""

    for i in $(seq 1 $iterations); do
        echo ""
        echo "--- 迭代 $i / $iterations ---"

        local blktrace_dir=""
        if [[ "$USE_BLKTRACE" == "true" ]]; then
            # 启动本轮 blktrace 监控
            blktrace_dir=$(start_round_blktrace $i)
            echo "blktrace 监控目录: $blktrace_dir"
            sleep 1
        fi

        # 记录快照前状态
        # 等待 SMART 更新（SSD 可能不会实时更新 SMART 统计）
        sleep 3
        local before=$(get_smart_metrics)
        local writes_before=$(echo $before | jq -r '.data_units_written')

        echo "快照前 SMART:"
        echo "  写入: $writes_before units"

        # 记录时间
        local start_time=$(date +%s.%N)

        # 执行快照
        echo "执行快照..."
        local snap_name="snap_${i}_$(date +%s)"
        btrfs subvolume snapshot $MOUNT_POINT ${SNAP_DIR}/${snap_name}

        # 在快照上执行一些写入操作（可能触发 SSD 写放大/GC）
        echo "在快照上执行写入操作..."
        find ${SNAP_DIR}/${snap_name}/test_data -type f | head -n 100 | xargs -I {} sh -c 'dd if=/dev/zero of={} bs=4k count=1 conv=notrunc 2>/dev/null' || true

        local end_time=$(date +%s.%N)
        local snap_duration=$(echo "$end_time - $start_time" | bc)

        local blktrace_mb=0
        if [[ "$USE_BLKTRACE" == "true" && -n "$blktrace_dir" ]]; then
            # 停止本轮 blktrace
            local final_blktrace_dir=$(stop_round_blktrace "$blktrace_dir")

            # 分析 blktrace 写入量（块层写入）
            local blktrace_sectors=$(analyze_blktrace_writes "$final_blktrace_dir")
            local blktrace_bytes=$((blktrace_sectors * 512))
            local blktrace_kb=$((blktrace_bytes / 1024))
            blktrace_mb=$((blktrace_kb / 1024))

            echo "块层 (blktrace) 写入: $blktrace_bytes bytes (≈ $blktrace_mb MB)"
        else
            echo "块层写入: 未记录 (blktrace 已禁用)"
        fi

        # 记录快照后状态
        # 等待 SMART 更新（SSD GC 可能需要时间完成）
        sleep 5
        local after=$(get_smart_metrics)
        local writes_after=$(echo $after | jq -r '.data_units_written')

        local write_delta=$((writes_after - writes_before))

        echo "快照后 SMART:"
        echo "  写入: $writes_after units (+$write_delta)"

        # 计算
        local write_kb=$((write_delta / 2))  # 1 unit = 512 KB (Samsung NVMe)
        local write_mb=$((write_kb / 1024))

        echo "快照统计:"
        echo "  耗时: $snap_duration 秒"
        if [[ "$USE_BLKTRACE" == "true" && $blktrace_mb -gt 0 ]]; then
            echo "  块层写入 (blktrace): $blktrace_mb MB"
        fi
        echo "  SMART 写入增量: $write_delta units (≈ $write_mb MB)"

        # 写放大计算
        if [[ $write_delta -gt 0 && "$USE_BLKTRACE" == "true" && $blktrace_mb -gt 0 ]]; then
            # WA = SMART 写入 / 块层写入
            local wa_ratio=$(echo "scale=2; $write_mb / $blktrace_mb" | bc)
            echo "  写放大分析:"
            echo "    块层写入 (主机请求): $blktrace_mb MB"
            echo "    SMART 写入 (NAND 实际): $write_mb MB"
            echo "    写放大倍数 (WA): $wa_ratio 倍"
            echo "  注意: WA > 1 表示触发了 SSD GC 或其他写放大"
        elif [[ $write_delta -gt 0 ]]; then
            # SMART 有写入，但 blktrace 没记录到
            echo "  写放大分析:"
            echo "    SMART 层面写入量 = $write_mb MB"
            if [[ "$USE_BLKTRACE" == "true" ]]; then
                echo "  警告: blktrace 未捕获到块层写入，无法计算精确 WA"
            else
                echo "  (仅测量 SSD 总写入，未区分主机写入和 GC 写入)"
            fi
        else
            echo "  ⚠ 未检测到显著写入，GC 未触发"
        fi

        # 等待下一次迭代，让 SSD 有时间完成可能的 GC
        sleep 5
    done
}

# ==================== 使用 blktrace 监控 ====================
start_blktrace() {
    echo "启动 blktrace 监控..."
    local trace_dir="/tmp/blktrace_$(date +%s)"
    mkdir -p $trace_dir

    blktrace -d $TEST_PART -o $trace_dir/trace &
    echo $! > /tmp/blktrace.pid
    echo "blktrace PID: $(cat /tmp/blktrace.pid)"
    echo $trace_dir
}

stop_blktrace() {
    if [[ -f /tmp/blktrace.pid ]]; then
        echo "停止 blktrace..."
        kill $(cat /tmp/blktrace.pid) 2>/dev/null || true
        rm -f /tmp/blktrace.pid
        # 等待 blktrace 写完数据
        sleep 1
    fi
}

# ==================== 分析 blktrace 写入量 ====================
analyze_blktrace_writes() {
    local trace_dir="$1"

    if [[ ! -f "$trace_dir/trace.blktrace.0" ]]; then
        echo "0"
        return
    fi

    # 使用 blkparse 统计写入字节数
    # W = Write operation
    # $9 = 字节数 (512 字节扇区数)
    local sectors=$(blkparse -i $trace_dir/trace.blktrace.* -d -o - 2>/dev/null | \
        grep " W " | awk '{sum += $9} END {print sum}')

    # 如果没有数据，返回 0
    [[ -z "$sectors" ]] && sectors=0
    [[ "$sectors" == "0" ]] && echo "0" || echo "$sectors"
}

# ==================== 使用 blktrace 监控（单轮测试） ====================
start_round_blktrace() {
    local round_dir="/tmp/blktrace_round_$(date +%s)_$1"
    mkdir -p $round_dir
    blktrace -d $TEST_PART -o $round_dir/trace &
    echo "$round_dir"
}

stop_round_blktrace() {
    local round_dir="$1"
    local pid=$(pgrep -f "blktrace.*$round_dir/trace" | head -1)
    [[ -n "$pid" ]] && kill $pid 2>/dev/null || true
    sleep 1  # 等待数据写入
    echo "$round_dir"
}

# ==================== 使用 iostat 实时监控 ====================
start_iostat() {
    echo "启动 iostat 监控..."
    iostat -xkd 1 $TEST_PART > /tmp/iostat.log &
    echo $! > /tmp/iostat.pid
}

stop_iostat() {
    if [[ -f /tmp/iostat.pid ]]; then
        kill $(cat /tmp/iostat.pid) 2>/dev/null || true
        rm -f /tmp/iostat.pid
    fi
}

# ==================== 主流程 ====================
main() {
    echo "========================================="
    echo "  Btrfs + NVMe GC 放大量化测试"
    echo "========================================="
    echo ""
    echo "测试原理:"
    echo "1. 用大量数据填满 SSD (900GB)"
    echo "2. 删除部分数据，制造无效块（不 TRIM）"
    echo "3. 执行快照，观察是否触发 SSD GC"
    echo "4. 通过 SMART 对比计算写放大"
    echo ""
    if [[ "$USE_BLKTRACE" == "true" ]]; then
        echo " blktrace: 启用"
    else
        echo " blktrace: 禁用 (USE_BLKTRACE=false)"
    fi
    echo ""

    read -p "确认开始测试? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi

    check_prereqs
    prepare_test_env

    # 启动监控（仅全局监控，不包括快照轮次）
    if [[ "$USE_BLKTRACE" == "true" ]]; then
        local trace_dir=$(start_blktrace)
    fi
    start_iostat

    # 执行测试
    fill_drive
    invalidate_blocks
    run_snapshot_gc_test

    # 停止监控
    if [[ "$USE_BLKTRACE" == "true" ]]; then
        stop_blktrace
    fi
    stop_iostat

    echo ""
    echo "========== 测试完成 =========="
    if [[ "$USE_BLKTRACE" == "true" ]]; then
        echo "blktrace 数据: $trace_dir"
        echo "iostat 日志: /tmp/iostat.log"
        echo ""
        echo "分析 blktrace:"
        echo "  btt -i $trace_dir/trace.blktrace.* -a"
    else
        echo "iostat 日志: /tmp/iostat.log"
    fi
}

main "$@"