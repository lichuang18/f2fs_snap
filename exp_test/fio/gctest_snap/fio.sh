# 覆盖一些数据，产生一些无效的数据块
# sync
fio --name=overwrite \
    --filename=/mnt/test3/f0 \
    --rw=randwrite \
    --bs=1M \
    --size=30G \
    --direct=1 \
    --ioengine=libaio \
    --numjobs=1 \
    --iodepth=1 \
    --log_avg_msec=1000 \
    --write_bw_log=bw \
    --log_hist_msec=1000 \
    --time_based=1 \
    --runtime=1000

    # --offset=6G \