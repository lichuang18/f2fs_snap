mkdir -p /mnt/test3
sync
fio --name=fill \
    --filename=/mnt/test3/testfile  \
    --rw=write \
    --bs=1M \
    --size=20G \
    --direct=1 \
    --ioengine=libaio \
    --numjobs=1 \
    --iodepth=16


    # --offset=10G \

