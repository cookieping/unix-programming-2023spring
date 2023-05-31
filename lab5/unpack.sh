#!/bin/sh
cd dist
bzip2 -d rootfs.cpio.bz2
cd rootfs
cpio -iv < ../rootfs.cpio