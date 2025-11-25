modprobe f2fs 
insmod rdffs.ko
./f2fs-tools/mkfs/mkfs.f2fs -t f2fs -f /dev/nvme1n1
mount -t rdffs -o mode=lfs  /dev/nvme1n1 /mnt
cd test_ioctl
