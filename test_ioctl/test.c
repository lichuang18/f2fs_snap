#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define F2FS_IOCTL_MAGIC      0xf5
#define F2FS_IOC_SNAPSHOT   _IOW(F2FS_IOCTL_MAGIC, 28, char*[3])
int main(int argc, char *argv[])
{
    if (argc != 4) {
        printf("Usage: %s <arg1,src> <arg2,gen> <arg3,snap>\n", argv[0]);
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
    const char *paths[3];
    paths[0] = argv[1];
    paths[1] = argv[2];
    paths[2] = argv[3];

    if (ioctl(fd, F2FS_IOC_SNAPSHOT, paths) < 0) {
        perror("[snapfs ioctl]: ioctl call failed...");
        close(fd);
        return -1;
    }

    printf("[snapfs ioctl]: ioctl successfully(arg1=%s, arg2=%s, arg3=%s).\n"
        , paths[0], paths[1], paths[2]);

    close(fd);
    return 0;
}
