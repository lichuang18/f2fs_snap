# mkdir -p /mnt/test3
# sync
# echo 3 > /proc/sys/vm/drop_caches

fio --name=fill \
    --filename=/mnt/test3/testfile2 \
    --rw=randwrite \
    --bs=4K \
    --size=5G \
    --direct=1 \
    --ioengine=libaio \
    --numjobs=1 \
    --iodepth=16
    

    # --fsync=1 \
# fio --name=commit_sensitive \
#     --filename=/mnt/test3/testfile \
#     --rw=randwrite \
#     --bs=4k \
#     --size=1G \
#     --ioengine=psync \
#     --direct=0 \
#     --iodepth=1 \
#     --numjobs=1 \
#     --fdatasync=1 \
#     --time_based=1 \
#     --runtime=180 \
#     --ramp_time=30 \
#     --group_reporting=1 \
#     --randrepeat=0 \
#     --percentile_list=50:95:99:99.9:99.99


    # --fallocate=none \