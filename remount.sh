umount /mnt && rmmod rdffs && insmod rdffs.ko 
mkfs -t f2fs -f /dev/nvme1n1 && mount -t rdffs -o mode=lfs  /dev/nvme1n1 /mnt


cd test_ioctl 
