#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include "kshram.h"


#define DEVICE_NAME "kshram"
#define DEVICE_CLASS "kshram_class"
#define DEVICE_COUNT 8
#define DEVICE_SIZE (4 * 1024)  // 4KB

static dev_t devnum;
static struct class *clazz;
static struct cdev c_dev;

struct device *kshram_data[DEVICE_COUNT];  // point to the buffer
unsigned long kshram_dev_size[DEVICE_COUNT];  // record the size of each shared memory file


int getIndex(struct file* fp) {  // get the index of kshram (ex. kshram0, kshram3, ...)
	int i = iminor(fp->f_inode) - MINOR(devnum);
	return i;
}

static int kshram_dev_open(struct inode* inode, struct file* fp) {
	// int i = imajor(inode) - imajor(devnum);  // kshram[i]
	return 0;
}

static int kshram_dev_close(struct inode* inode, struct file* fp) {
	return 0;
}

// ioctl commands
static long kshram_dev_ioctl(struct file* fp, unsigned int cmd, unsigned long arg) {
	int i = getIndex(fp);
	switch(cmd) {
        case KSHRAM_GETSLOTS:
            return DEVICE_COUNT;

		case KSHRAM_GETSIZE:
			return kshram_dev_size[i];

		case KSHRAM_SETSIZE:
			unsigned long new_size = arg;
			// printk(KERN_INFO "* in KSHRAM_SETSIZE, arg = %ld\n", arg);
			// kfree(kshram_data[i]);
			if((kshram_data[i] = krealloc(kshram_data[i], new_size, GFP_KERNEL)) == NULL) {
				return -1;
			}
			kshram_dev_size[i] = new_size;
			return 0;

        default:
            return -EINVAL;
    }
	return 0;
}

static int kshram_dev_mmap(struct file *fp, struct vm_area_struct *vma) {
	int i = getIndex(fp);

	// remap_pfn_range: remap kernel memory to userspace
	// unsigned long pfn = (virt_to_phys(kshram_data[i]) >> PAGE_SHIFT) + vma->vm_pgoff;  // page frame number of kernel physical memory address
	unsigned long pfn = page_to_pfn(virt_to_page(kshram_data[i]));
	unsigned long size = vma->vm_end - vma->vm_start;

	int ret = remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot);
	// kshram/mmap: idx 0 size 4096
	printk(KERN_INFO "kshram/mmap: idx %d size %ld\n", i, size);

	return ret;
}

static const struct file_operations kshram_dev_fops = {
	.owner = THIS_MODULE,
	.open = kshram_dev_open,
	.unlocked_ioctl = kshram_dev_ioctl,
	.mmap = kshram_dev_mmap,
	.release = kshram_dev_close,
};


static int kshram_proc_read(struct seq_file *m, void *v) {
	for(int i = 0; i < DEVICE_COUNT; i++) {
		seq_printf(m, "0%d: %ld\n", i, kshram_dev_size[i]);
	}
	return 0;
}

static int kshram_proc_open(struct inode* inode, struct file* file) {
	return single_open(file, kshram_proc_read, NULL);
}

static const struct proc_ops kshram_proc_fops = {
	.proc_open = kshram_proc_open,
	.proc_read = seq_read,
	.proc_release = single_release,
};

static char* kshram_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init kshram_init(void)
{	
	// register a range of char device numbers
	if(alloc_chrdev_region(&devnum, 0, DEVICE_COUNT, DEVICE_NAME) < 0) return -1;

	// create device class
	if((clazz = class_create(THIS_MODULE, DEVICE_CLASS)) == NULL) goto release_region;
	clazz->devnode = kshram_devnode;

	// create devices
	for(int i = 0; i < DEVICE_COUNT; i++) {
		struct device *buffer = kzalloc(DEVICE_SIZE, GFP_KERNEL);
		if(!buffer) goto release_class;
		kshram_data[i] = buffer;
		kshram_dev_size[i] = DEVICE_SIZE;
		// print allocate info [?] should we print by ourselves?
		printk(KERN_INFO "kshram%d: %d bytes allocated @ %px\n", i, DEVICE_SIZE, (void*)kshram_data[i]);

		// creates a device and registers it with sysfs
		if((buffer = device_create(clazz, NULL, MKDEV(MAJOR(devnum), MINOR(devnum) + i), NULL, "%s%d", DEVICE_NAME, i)) == NULL) goto release_class;
	}

	// initialize a cdev structure
	cdev_init(&c_dev, &kshram_dev_fops);
	// add char devices to the system
	if(cdev_add(&c_dev, devnum, DEVICE_COUNT) == -1) goto release_device;

	// create kshram proc
	if(proc_create(DEVICE_NAME, 0666, NULL, &kshram_proc_fops) == NULL) {  // [?] umode_t = 0
		remove_proc_entry(DEVICE_NAME, NULL);
		return -1;
	}
	
	printk(KERN_INFO "kshram: initialized.\n");
	return 0;

release_device:
	for(int i = 0; i < DEVICE_COUNT; i++) {
		device_destroy(clazz, MKDEV(MAJOR(devnum), MINOR(devnum) + i));
		kfree(kshram_data[i]);
	}

release_class:
	class_destroy(clazz);

release_region:
	unregister_chrdev_region(devnum, DEVICE_COUNT);
	return -1;
}

static void __exit kshram_cleanup(void)
{
	remove_proc_entry(DEVICE_NAME, NULL);

	cdev_del(&(c_dev));
	for(int i = 0; i < DEVICE_COUNT; i++) {
		device_destroy(clazz, MKDEV(MAJOR(devnum), MINOR(devnum) + i));
		kfree(kshram_data[i]);
	}
	class_destroy(clazz);
	unregister_chrdev_region(devnum, DEVICE_COUNT);

	printk(KERN_INFO "kshram: cleaned up.\n");
}

module_init(kshram_init);
module_exit(kshram_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chun-Ying Huang");
MODULE_DESCRIPTION("The unix programming course demo kernel module.");
