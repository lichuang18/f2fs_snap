# 覆盖一些数据，产生一些无效的数据块
# sync
fio --name=overwrite \
    --filename=/mnt/test3/f0 \
    --rw=randwrite \
    --bs=4k \
    --size=10G \
    --direct=1 \
    --offset=10G \
    --ioengine=libaio \
    --numjobs=1 \
    --iodepth=1



