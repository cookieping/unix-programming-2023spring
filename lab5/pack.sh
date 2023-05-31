#!/bin/sh
cd dist/rootfs
cp ../../kshrammod/kshram.ko kshram.ko
find . | cpio -H newc -o > ../rootfs.cpio
cd ..
rm rootfs.cpio.bz2
bzip2 -z rootfs.cpio