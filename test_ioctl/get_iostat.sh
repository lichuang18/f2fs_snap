#!/bin/bash
# 文件名：record_nvme_stat.sh
# 用法：./record_nvme_stat.sh output_file
# 每秒记录 /sys/block/nvme1n1/stat 到指定文件

OUTPUT_FILE="$1"

if [[ -z "$OUTPUT_FILE" ]]; then
    echo "Usage: $0 output_file"
    exit 1
fi

echo "timestamp nr_reads nr_read_merged sectors_read ms_reading nr_writes nr_write_merged sectors_written ms_writing ios_in_progress ms_doing_io weighted_ms_doing_io nr_discard nr_discard_merged discard_sectors discard_ticks discard_in_flight discard_time_pending" > "$OUTPUT_FILE"

while true; do
    STAT=$(cat /sys/block/nvme1n1/stat)
    TIMESTAMP=$(date +%s)
    echo "$TIMESTAMP $STAT" >> "$OUTPUT_FILE"
    sleep 1
done
