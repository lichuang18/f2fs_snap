#!/bin/bash
set -e

DIR="/mnt/test3"
SNAP_DIR="/mnt"

STR=$(head -c 96 /dev/urandom | base64 | tr -d '\n' | cut -c1-4096)


mkdir -p $DIR
cd $DIR

for i in $(seq 0 90); do
    touch "f$i"
    echo $STR > f$i
done

cd -

echo "create snapshot time (with 199 files);"
time ./a.out $DIR $SNAP_DIR snap3
