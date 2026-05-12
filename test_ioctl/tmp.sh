mkdir -p /mnt/test3
fio --name=fill \
    --filename=/mnt/test3/testfile \
    --rw=read \
    --bs=1M \
    --size=20G \
    --direct=1 \
    --ioengine=libaio \
    --numjobs=1 \
    --fallocate=none \
    --iodepth=16

sync
echo 3 > /proc/sys/vm/drop_caches


smartctl -a /dev/nvme1n1  |grep "Units Written"
df -B1 /mnt/

time ./a.out /mnt/test3/ /mnt/ snap
sync


python3 modify_dataset.py \
    --file /mnt/test3/testfile \
    --ratio 100 \
    --block-size 4K \
    --seed 100 \
    --fsync \
    --sync \
    --log modify_10.log

# fio --name=fill \
#     --filename=/mnt/test3/testfile \
#     --rw=randwrite \
#     --bs=4K \
#     --size=10G \
#     --direct=1 \
#     --ioengine=libaio \
#     --numjobs=1 \
#     --iodepth=16 \
#     --ramp_time=0 \
#     --runtime=60 \
#     --time_based=1

# sync

smartctl -a /dev/nvme1n1  |grep "Units Written"
df -B1 /mnt/
