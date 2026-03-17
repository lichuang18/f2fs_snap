
# TARGET_DIR="/mnt/test_random"
MODIFY_PCT="$1"
for pct in  20 50 100
do
    echo "当前修改比例: ${pct}%"
    ./base.sh ${pct} > ./snapfs_test_result_$pct 
done
