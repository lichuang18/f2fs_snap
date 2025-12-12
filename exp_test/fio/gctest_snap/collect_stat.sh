#!/bin/bash

dev=nvme1n1p1              # 换成你的设备名
out=fg_gc_stat.log         # 输出文件名

base="/sys/fs/rdffs/$dev"

echo "#sec calls_delta blocks_delta calls_total blocks_total" > "$out"

prev_calls=$(cat "$base/gc_foreground_calls")
prev_blocks=$(cat "$base/moved_blocks_foreground")

t=0
while true; do
    sleep 1

    cur_calls=$(cat "$base/gc_foreground_calls")
    cur_blocks=$(cat "$base/moved_blocks_foreground")

    dcalls=$((cur_calls - prev_calls))
    dblocks=$((cur_blocks - prev_blocks))

    # time  本秒新增GC次数  本秒搬迁blocks数  累计GC次数  累计搬迁blocks
    echo "$t $dcalls $dblocks $cur_calls $cur_blocks" >> "$out"

    prev_calls=$cur_calls
    prev_blocks=$cur_blocks
    t=$((t+1))
done

