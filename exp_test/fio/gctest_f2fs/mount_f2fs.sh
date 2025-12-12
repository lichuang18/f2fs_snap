umount /mnt
mkfs -t f2fs -f /dev/nvme1n1p1

mount -t f2fs -o mode=lfs  /dev/nvme1n1p1 /mnt
