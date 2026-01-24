#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>

#define F2FS_IOCTL_MAGIC      0xf5
#define F2FS_IOC_DELETE_SNAPSHOT   _IOW(F2FS_IOCTL_MAGIC, 30, char*)

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: %s <snapshot_path>\n", argv[0]);
        printf("Example: %s /mnt/f2fs/snapshots/snap1\n", argv[0]);
        return -1;
    }

    const char *snap_path = argv[1];

    /* Open the snapshot directory/file */
    int fd = open(snap_path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        printf("Failed to open snapshot path: %s\n", snap_path);
        return -1;
    }

    printf("[snapfs delete test]: Deleting snapshot at '%s'\n", snap_path);

    /* Call the delete snapshot ioctl */
    if (ioctl(fd, F2FS_IOC_DELETE_SNAPSHOT, &snap_path) < 0) {
        perror("[snapfs delete test]: ioctl call failed");
        close(fd);
        return -1;
    }

    printf("[snapfs delete test]: Successfully deleted snapshot '%s'\n", snap_path);

    close(fd);
    return 0;
}
