#!/bin/bash
set -e

DIR="/mnt/test3"
SNAP_DIR="/mnt"

STR=$(head -c 8000 /dev/urandom | base64 | tr -d '\n' | cut -c1-6096)
# dd if=/dev/urandom of=/mnt/test3/f0 bs=1M count=$((11 * 1024)) status=progress

mkdir -p $DIR

echo "create dir success..."

cd $DIR

for i in $(seq 0 2); do
    touch "f$i"
    echo $STR > f$i
done
echo "create file success..."
cd -

sync
# snapshot前，一定要确保所有数据都已分配有效block，持久化到盘
echo "create snapshot time (with 199 files);"
time ./a.out $DIR $SNAP_DIR snap3
sync
