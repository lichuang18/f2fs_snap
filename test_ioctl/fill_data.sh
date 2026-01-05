mkdir -p /mnt/test3
sync
fio --name=fill \
    --filename=/mnt/test3/f0 \
    --rw=write \
    --bs=1M \
    --size=1G \
    --direct=1 \
    --ioengine=libaio \
    --numjobs=1 \
    --iodepth=1


    # --offset=10G \


# fio --name=overwrite \
#     --filename=/mnt/test3/f0 \
#     --rw=randwrite \
#     --bs=4k \
#     --size=14G \
#     --direct=1 \
#     --ioengine=libaio \
#     --numjobs=1 \
#     --iodepth=1


