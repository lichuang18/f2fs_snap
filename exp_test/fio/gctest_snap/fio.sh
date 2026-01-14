# 覆盖一些数据，产生一些无效的数据块
# sync
fio --name=overwrite \
    --filename=/mnt/test3/f0 \
    --rw=randwrite \
    --bs=256K \
    --size=12G \
    --direct=1 \
    --ioengine=libaio \
    --numjobs=1 \
    --iodepth=1 \
    --log_avg_msec=1000 \
    --write_bw_log=bw \
    --log_hist_msec=1000 \
    --time_based=1 \
    --runtime=100

    # --offset=6G \
sleep 1
sync
sleep 2

fio --name=overwrite \
    --filename=/mnt/test3/f2 \
    --rw=randwrite \
    --bs=1M \
    --size=16G \
    --direct=1 \
    --ioengine=libaio \
    --numjobs=1 \
    --iodepth=1 \
    --log_avg_msec=1000 \
    --write_bw_log=bw \
    --log_hist_msec=1000 \
    --time_based=1 \
    --runtime=100