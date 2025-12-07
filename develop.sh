mkdir -p /mnt/df
echo abcd >> /mnt/df/file1
sleep 5
./test_ioctl/a.out  /mnt/ /mnt/df/ /mnt/snap
sleep 5
echo efgh >> /mnt/df/file1
