# SPDX-License-Identifier: GPL-2.0
obj-m += snapfs.o

snapfs-y		:= dir.o file.o inode.o namei.o hash.o super.o inline.o
snapfs-y		+= checkpoint.o gc.o data.o node.o segment.o recovery.o
snapfs-y		+= shrinker.o extent_cache.o sysfs.o compress.o
snapfs-y		+= compress.o xattr.o acl.o verity.o
snapfs-y		+= snapshot.o
snapfs-$(CONFIG_F2FS_STAT_FS) += debug.o
snapfs-$(CONFIG_F2FS_FS_XATTR) += xattr.o
snapfs-$(CONFIG_F2FS_FS_POSIX_ACL) += acl.o
snapfs-$(CONFIG_FS_VERITY) += verity.o
snapfs-$(CONFIG_F2FS_FS_COMPRESSION) += compress.o
snapfs-$(CONFIG_F2FS_IOSTAT) += iostat.o
EXTRA_CFLAGS += -I$(PWD)

default:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean