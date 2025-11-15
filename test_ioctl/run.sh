#!/bin/bash
set -e

DIR="/mnt/test3"
SNAP_DIR="/mnt/snap3"

STR=$(head -c 4096 /dev/urandom | base64 | tr -d '\n' | cut -c1-4096)


mkdir -p $DIR
cd $DIR

for i in $(seq 0 49); do
    touch "f$i"
    echo $STR > f$i
done

cd -

echo "create snapshot time (with 199 files);"
time ./a.out /mnt $DIR $SNAP_DIR
