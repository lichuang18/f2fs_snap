/*
 * Quick Usage Example for F2FS_IOC_DELETE_SNAPSHOT
 *
 * This example demonstrates how to use the delete snapshot IOCTL
 * from a C program.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>

#define F2FS_IOCTL_MAGIC      0xf5
#define F2FS_IOC_DELETE_SNAPSHOT   _IOW(F2FS_IOCTL_MAGIC, 30, char*)

int delete_snapshot(const char *snapshot_path)
{
    int fd;
    int ret;

    /* Open the snapshot directory/file */
    fd = open(snapshot_path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open snapshot: %s\n", strerror(errno));
        return -1;
    }

    /* Call the delete snapshot IOCTL */
    ret = ioctl(fd, F2FS_IOC_DELETE_SNAPSHOT, &snapshot_path);
    if (ret < 0) {
        fprintf(stderr, "Failed to delete snapshot: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    printf("Successfully deleted snapshot: %s\n", snapshot_path);
    close(fd);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <snapshot_path>\n", argv[0]);
        fprintf(stderr, "Example: %s /mnt/f2fs/snapshots/snap1\n", argv[0]);
        return 1;
    }

    return delete_snapshot(argv[1]);
}

/*
 * Compilation:
 *   gcc -o delete_snap example_delete.c
 *
 * Usage:
 *   sudo ./delete_snap /mnt/f2fs/snapshots/snap1
 *
 * Expected output:
 *   Successfully deleted snapshot: /mnt/f2fs/snapshots/snap1
 *
 * Kernel logs (dmesg):
 *   [snapfs delete]: Starting deletion of snapshot ino=12345
 *   [snapfs delete]: Deleted magic entry for snap_ino=12345, src_ino=67890
 *   [snapfs delete]: Decreased mulref for direct blk 4503280
 *   [snapfs delete]: Successfully deleted snapshot ino=12345 (src_ino=67890)
 */
