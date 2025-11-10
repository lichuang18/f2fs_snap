# SPDX-License-Identifier: GPL-2.0
obj-m += rdffs.o

rdffs-y		:= dir.o file.o inode.o namei.o hash.o super.o inline.o
rdffs-y		+= checkpoint.o gc.o data.o node.o segment.o recovery.o
rdffs-y		+= shrinker.o extent_cache.o sysfs.o compress.o
rdffs-y		+= compress.o xattr.o acl.o verity.o
rdffs-$(CONFIG_F2FS_STAT_FS) += debug.o
rdffs-$(CONFIG_F2FS_FS_XATTR) += xattr.o
rdffs-$(CONFIG_F2FS_FS_POSIX_ACL) += acl.o
rdffs-$(CONFIG_FS_VERITY) += verity.o
rdffs-$(CONFIG_F2FS_FS_COMPRESSION) += compress.o
rdffs-$(CONFIG_F2FS_IOSTAT) += iostat.o
EXTRA_CFLAGS += -I$(PWD)

default:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean