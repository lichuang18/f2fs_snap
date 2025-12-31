#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define FILE_PATH "/mnt/test3/f0"
#define BUF_SIZE 8192   // 8KB

int main() {
    int fd;
    ssize_t ret;
    unsigned char buf[BUF_SIZE];

    // 填充随机数据
    for (int i = 0; i < BUF_SIZE; i++) {
        buf[i] = rand() % 256;
    }

    // 打开文件，只写，没有 O_APPEND 或 O_TRUNC
    fd = open(FILE_PATH, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    // 写入 8KB
    ret = write(fd, buf, BUF_SIZE);
    if (ret < 0) {
        perror("write");
        close(fd);
        return 1;
    }

    printf("Wrote %zd bytes to %s\n", ret, FILE_PATH);

    close(fd);
    return 0;
}
