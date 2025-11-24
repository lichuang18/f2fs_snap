#!/bin/bash
set -e

DIR="/mnt/test3"
SNAP_DIR="/mnt/snap3"

STR=$(head -c 40960 /dev/urandom | base64 | tr -d '\n' | cut -c1-4096)


mkdir -p $DIR
cd $DIR

for i in $(seq 0 257); do
    #touch "f$i"
    #echo $STR > f$i
    mkdir -p /mnt/dir$i
done

