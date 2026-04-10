umount /mnt/;mkfs.btrfs -f /dev/nvme1n1
#umount /mnt
#mkfs.ext4 /dev/vg_data/lv_test
# mount /dev/vg_data/lv_test /mnt

mount  /dev/nvme1n1 /mnt
# mount -o nodatacow /dev/nvme1n1 /mnt


sudo btrfs subvolume create /mnt/test3
# mkdir -p /mnt/test3
sync

fio --name=fill \
    --filename=/mnt/test3/testfile \
    --rw=read \
    --bs=1M \
    --size=20G \
    --direct=1 \
    --ioengine=libaio \
    --numjobs=1 \
    --fallocate=none \
    --iodepth=16

sync
sync
#sudo lvcreate -L 50G -s -n lv_test_snap /dev/vg_data/lv_test
# sudo btrfs subvolume snapshot /mnt/test3 /mnt/snap1

