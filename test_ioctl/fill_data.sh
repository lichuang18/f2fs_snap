mkdir -p /mnt/test3
sync
fio --name=fill \
    --filename=/mnt/test3/testfile  \
    --rw=randwrite \
    --bsrange=4k-2M \
    --size=20G \
    --direct=1 \
    --ioengine=libaio \
    --numjobs=1 \
    --fallocate=none \
    --iodepth=16
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