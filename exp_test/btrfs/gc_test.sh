#!/bin/bash

########################################
# Configuration
########################################

DEVICE="/dev/nvme1n1"
MNT="/mnt/btrfs_gc"
SIZE="900G"           # 使用 80% 容量进入 steady-state
RUNTIME=3600         # 随机写时间（秒）
LOGDIR="./btrfs_gc_logs"

umount /dev/nvme1n1
blkdiscard -f /dev/nvme1n1

########################################
# Safety Warning
########################################

echo "=============================================="
echo "WARNING: This will ERASE ALL DATA on $DEVICE"
echo "=============================================="
read -p "Type YES to continue: " CONFIRM
if [ "$CONFIRM" != "YES" ]; then
    echo "Aborted."
    exit 1
fi

mkdir -p $LOGDIR

########################################
# Step 1: Reset Device
########################################

echo "[1/6] Formatting NVMe device..."
nvme format $DEVICE

########################################
# Step 2: Create Btrfs on raw device
########################################

echo "[2/6] Creating Btrfs..."
mkfs.btrfs -f $DEVICE

mkdir -p $MNT
mount -o discard=async $DEVICE $MNT

########################################
# Step 3: Preconditioning (Sequential Write)
########################################

echo "[3/6] Preconditioning filesystem (sequential write)..."

fio --name=fill \
    --directory=$MNT \
    --direct=1 \
    --rw=write \
    --bs=1M \
    --size=$SIZE \
    --numjobs=1 \
    --iodepth=32 \
    --group_reporting \
    --fallocate=none

sync

########################################
# Record SMART after fill
########################################

echo "[4/6] Recording SMART after fill..."
nvme smart-log $DEVICE
nvme smart-log $DEVICE > $LOGDIR/smart_after_fill.log
HOST_BEFORE=$(grep "Data Units Written" $LOGDIR/smart_after_fill.log | awk '{print $4}')
########################################
# Step 4: Random Overwrite (Trigger FTL GC)
########################################

echo "[5/6] Starting random overwrite workload..."

fio --name=steady_gc \
    --directory=$MNT \
    --direct=1 \
    --rw=randwrite \
    --bs=4k \
    --size=100G \
    --numjobs=1 \
    --iodepth=32 \
    --time_based \
    --runtime=$RUNTIME \
    --group_reporting \
    --write_lat_log=$LOGDIR/lat \
    --fallocate=none

sync

########################################
# Step 5: Collect SMART after GC
########################################

echo "[6/6] Recording SMART after GC..."
nvme smart-log $DEVICE
nvme smart-log $DEVICE > $LOGDIR/smart_after_gc.log
HOST_AFTER=$(grep "Data Units Written" $LOGDIR/smart_after_gc.log | awk '{print $4}')
DELTA_HOST=$((HOST_AFTER - HOST_BEFORE))

echo "=============================================="
echo "Test completed."
echo "Logs stored in $LOGDIR"
echo "Host Data Units Written Delta: $DELTA_HOST"
echo "=============================================="
