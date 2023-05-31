
obj-m     += kshram.o
ccflags-y += -DEXPORT_SYMTAB

all:
	make ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu- -C ../dist/modulebuild M=$(PWD) modules

clean:
	make ARCH=x86_64 CROSS_COMPILE=x86_64-linux-gnu- -C ../dist/modulebuild M=$(PWD) clean

install: all
	mkdir -p ../rootfs/modules
	cp kshram.ko ../rootfs/modules
