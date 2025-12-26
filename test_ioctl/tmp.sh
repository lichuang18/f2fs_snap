#!/bin/bash
set -e

DIR="/mnt/test3"
SNAP_DIR="/mnt"

STR=$(head -c 16 /dev/urandom | base64 | tr -d '\n' | cut -c1-4096)


mkdir -p $DIR
cd $DIR

for i in $(seq 0 2); do
    touch "f$i"
    echo $STR > f$i
done

cd -

sync
# snapshot前，一定要确保所有数据都已分配有效block，持久化到盘
echo "create snapshot time (with 199 files);"
time ./a.out $DIR $SNAP_DIR snap3
sync
