#!/bin/bash

########################################
# Configuration
########################################

DEVICE="/dev/nvme1n1"
MNT="/mnt"
LOGDIR="./btrfs_gc_logs"


# sudo lvremove /dev/vg_data/lv_test_snap

umount $MNT

sudo mkfs.ext4 /dev/vg_data/lv_test
sudo mount /dev/vg_data/lv_test  $MNT

sync
# 控制文件深度 1 2 4 6 8 10
# 
# --bsrange=4k-2M \
mkdir -p /mnt/test3/dir2
# mkdir -p /mnt/test3/dir2/dir3/dir4/dir5/dir6/dir7/dir8/dir9/dir10
fio --name=fill \
    --filename=/mnt/test3/dir2/testfile  \
    --rw=write \
    --bs=1M \
    --size=10G \
    --direct=1 \
    --ioengine=libaio \
    --numjobs=1 \
    --fallocate=none \
    --iodepth=16
sync

echo "[4/6] Recording SMART after fill..."
smartctl -a $DEVICE
smartctl -a $DEVICE > $LOGDIR/smart_after_fill.log

HOST_BEFORE=$(grep "Data Units Written" $LOGDIR/smart_after_fill.log | awk '{print $4}')



# sudo lvcreate -L 50G -s -n lv_test_snap /dev/vg_data/lv_test

sync

fio --name=wa \
    --filename=/mnt/test3/dir2/testfile  \
    --direct=1 \
    --rw=randwrite \
    --bs=4k \
    --size=8G \
    --numjobs=1 \
    --iodepth=16 \
    --fsync=10 \
    --write_lat_log=$LOGDIR/lat \
    --fallocate=none

sync


echo "[6/6] Recording SMART after rw..."
smartctl -a $DEVICE
smartctl -a $DEVICE > $LOGDIR/smart_after_gc.log
HOST_AFTER=$(grep "Data Units Written" $LOGDIR/smart_after_gc.log | awk '{print $4}')
DELTA_HOST=$((HOST_AFTER - HOST_BEFORE))

echo "=============================================="
echo "Test completed."
echo "Logs stored in $LOGDIR"
echo "Host Data Units Written Delta: $DELTA_HOST"
echo "=============================================="
