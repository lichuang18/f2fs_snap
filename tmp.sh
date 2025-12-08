#!/bin/bash

mkdir /mnt/df
#dd if=/dev/urandom of=/mnt/df/file1 bs=8K count=1
dd if=/dev/zero bs=8192 count=1 2>/dev/null | tr '\0' 'A' > /mnt/df/file1
dd if=/dev/zero bs=8192 count=1 2>/dev/null | tr '\0' 'B' >> /mnt/df/file1
sync

./test_ioctl/a.out  /mnt/ /mnt/df/ /mnt/snap

sync

echo sdsadas >> /mnt/df/file1
sync
