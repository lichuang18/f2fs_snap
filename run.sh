modprobe f2fs 
insmod rdffs.ko

mount -t rdffs -o mode=lfs  /dev/nvme1n1 /mnt
