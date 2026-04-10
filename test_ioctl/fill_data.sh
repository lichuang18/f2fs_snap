

umount /mnt
# sudo mkfs.ext4 /dev/vg_data/lv_test
# sudo mount /dev/vg_data/lv_test /mnt

mkfs.btrfs -f /dev/nvme1n1 
mount -o noautodefrag,noatime,commit=1 /dev/nvme1n1 /mnt

# mkdir -p /mnt/test3
sudo btrfs subvolume create /mnt/test3
sync
fio --name=fill \
    --filename=/mnt/test3/testfile \
    --rw=write \
    --bs=1M \
    --size=20G \
    --direct=1 \
    --ioengine=libaio \
    --numjobs=1 \
    --fallocate=none \
    --iodepth=16 
    # --runtime=100 \
    # --time_based=1

    # --status-interval=1 \
    

    # --write_bw_log=bw \
    # --write_iops_log=iops \

    # --offset=10G \

    # --status-interval=1 \
    # --rw=randwrite \
    # --rw=randread \
    # --rw=write \
    # --rw=read \
    # --bsrange=4k-2M \
    # --bs=16K \
sync
fio --name=fill \
    --filename=/mnt/test3/testfile1 \
    --rw=write \
    --bs=1M \
    --size=10G \
    --direct=1 \
    --ioengine=libaio \
    --numjobs=1 \
    --fallocate=none \
    --iodepth=16 
sync

fio --name=fill \
    --filename=/mnt/test3/testfile2 \
    --rw=write \
    --bs=1M \
    --size=10G \
    --direct=1 \
    --ioengine=libaio \
    --numjobs=1 \
    --fallocate=none \
    --iodepth=16 

sync

# sudo lvcreate -L 100G -s -n lv_test_snap /dev/vg_data/lv_test
sudo btrfs subvolume snapshot -r /mnt/test3 /mnt/snap1

sync

fio --name=t0 \
    --filename=/mnt/test3/testfile \
    --rw=randwrite \
    --bs=4K \
    --size=1G \
    --direct=0 \
    --ioengine=io_uring \
    --numjobs=4 \
    --group_reporting=1 \
    --ramp_time=20 \
    --iodepth=32 \
    --fdatasync=16 \
    --randseed=1234 \
    --percentile_list=99:99.9:99.99 &


fio --name=t1 \
    --filename=/mnt/test3/testfile1 \
    --rw=randwrite \
    --bs=4K \
    --size=1G \
    --direct=0 \
    --ioengine=io_uring \
    --numjobs=4 \
    --group_reporting=1 \
    --ramp_time=20 \
    --iodepth=32 \
    --fdatasync=16 \
    --randseed=12345 \
    --percentile_list=99:99.9:99.99

# fio --name=t1 \
#     --filename=/mnt/test3/testfile1 \
#     --rw=randwrite \
#     --bs=4K \
#     --size=1G \
#     --direct=0 \
#     --ioengine=io_uring \
#     --numjobs=16 \
#     --group_reporting=1 \
#     --ramp_time=20 \
#     --runtime=120 \
#     --time_based=1 \
#     --iodepth=32 \
#     --norandommap=1 \
#     --randrepeat=1 \
#     --fdatasync=16 \
#     --randseed=1234 \
#     --percentile_list=99:99.9:99.99

# fio --name=fill \
#     --filename=/mnt/test3/testfile1 \
#     --rw=randwrite \
#     --bs=4K \
#     --size=15G \
#     --direct=1 \
#     --ioengine=libaio \
#     --numjobs=1 \
#     --iodepth=16 

# fio --name=fill \
#     --filename=/mnt/test3/testfile2 \
#     --rw=randwrite \
#     --bs=4K \
#     --size=15G \
#     --direct=1 \
#     --ioengine=libaio \
#     --numjobs=1 \
#     --iodepth=16

# sync
# sync
