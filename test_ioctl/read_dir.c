#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define F2FS_IOCTL_MAGIC      0xf5
#define F2FS_IOC_READDIR   _IOW(F2FS_IOCTL_MAGIC, 29, char*[2])
int main(int argc, char *argv[])
{
    if (argc != 4) {
        printf("Usage: %s <f2fs_mount_point> <arg1> <arg2>\n", argv[0]);
        return -1;
    }


    const char *path = argv[1];
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    // int args[2];
    // args[0] = atoi(argv[2]);
    // args[1] = atoi(argv[3]);
    const char *paths[1];
    paths[0] = argv[2];
    paths[1] = argv[3];


    if (ioctl(fd, F2FS_IOC_READDIR, paths) < 0) {
        perror("[snapfs] ioctl");
        close(fd);
        return -1;
    }

    printf("ioctl read_dir sent successfully (arg1=%s) (arg2=%s).\n", paths[0], paths[1]);

    close(fd);
    return 0;
}
