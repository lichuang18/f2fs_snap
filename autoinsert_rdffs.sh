modprobe f2fs 
insmod snapfs.ko
./f2fs-tools/mkfs/mkfs.f2fs -t f2fs -f /dev/nvme1n1p1
mount -t snapfs -o mode=lfs  /dev/nvme1n1p1 /mnt
