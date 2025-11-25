mkdir -p /mnt/df
mkdir -p /mnt/df/t12
mkdir -p /mnt/df/t12/df2
mkdir -p /mnt/df/t12/df2/fgh
mkdir -p /mnt/df/t12/df2/fgh/234
echo 111 > /mnt/df/t12/df2/fgh/234/file1
echo 222 > /mnt/df/t12/df2/fgh/234/file2
echo 444 > /mnt/df/t12/df2/fgh/234/file3



./test_ioctl/a.out  /mnt/ /mnt/df/ /mnt/snap



echo sshshfdjsdjfhsdhjfjsdjhfs > /mnt/df/t12/df2/fgh/234/file1