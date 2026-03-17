
# TARGET_DIR="/mnt/test_random"
MODIFY_PCT="$1"

# 1
echo "step[1/7]: 初始化, 并挂载btrfs..."
umount /mnt/
mkfs.btrfs -f /dev/nvme1n1 
mount /dev/nvme1n1 /mnt/

# 2
echo "step[2/7]: mix方式创建随机文件..."
/home/lch/workspace/f2fs_snap/exp_test/mk_snap/mix_create.sh

# 3
echo "step[3/7]: 记录创建文件后使用量..."
sync; sleep 5
used1=$(df -T | awk '$1=="/dev/nvme1n1"{print $4}')
echo "mix创建执行后, used = $used1"

# 4
echo "step[4/7]: 开始创建快照..."
sudo btrfs subvolume snapshot /mnt/test_random /mnt/snap1
sudo btrfs subvolume list /mnt

# 5
echo "step[5/7]: 记录创建快照后使用量..."
sync; sleep 5
used2=$(df -T | awk '$1=="/dev/nvme1n1"{print $4}')
echo "快照创建后, used = $used2"


# 6
echo "step[6/7]: 按照比例修改被快照文件..."
/home/lch/workspace/f2fs_snap/exp_test/space/modify.sh /mnt/test_random/ $MODIFY_PCT

# 7
echo "step[7/7]: 指定比例修改后的使用量..."
sync; sleep 5
used3=$(df -T | awk '$1=="/dev/nvme1n1"{print $4}')
echo "修改执行后, used = $used3"
