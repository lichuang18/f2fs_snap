mkdir -p /mnt/test3
sync
fio --name=direct_write_12k \
    --filename=/mnt/test3/f0 \
    --rw=read \
    --bs=1M \
    --size=10G \
    --direct=1 \
    --ioengine=libaio \
    --numjobs=1 \
    --iodepth=1
