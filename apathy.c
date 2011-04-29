#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/selinux.h>
#include <linux/init.h>
#include <linux/uprobes.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

#include "apathy.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fedor Sakharov <sakharov@lvk.cs.msu.su>");
MODULE_DESCRIPTION("Application safe execution control");

typedef struct rs_break {
	struct list_head list;
	struct uprobe probe; // uprobe struct, describing this bpt
	char new_cont[CONT_MAXLEN]; // new SELinux context of the process
} rs_break_t;

/* list containing information about probes */

LIST_HEAD(break_list);

static struct class *apathy_class;
static struct device apathy_dev;
static struct cdev   apathy_cdev;
static dev_t  apathy_devt;


static void apathy_destructor(struct device *d)
{
}

static void uprobe_handler(struct uprobe* u, struct pt_regs *regs)
{
	struct list_head *pos;
	struct rs_break *tmp;

	list_for_each(pos, &break_list) {
		tmp = list_entry(pos, struct rs_break, list);
		if (tmp->probe.vaddr == u->vaddr ) {
			printk(KERN_INFO "Hit breakpoint at: %p\n", (void*)u->vaddr);
			printk(KERN_INFO "New context is %s\n", tmp->new_cont);
			break;
		}
	}
}

ssize_t apathy_dev_read(struct file* file, char *buffer,
		size_t length, loff_t* offset)
{
	printk(KERN_INFO "Apathy: device read is not implemented\n");
	return -0;
}

int ioctl_set_break(void __user *p)
{
	struct rs_break *brk = kmalloc(sizeof(struct rs_break),GFP_KERNEL);
	struct apathy_trans trans;
	int ret;

	if (copy_from_user(&trans, p, sizeof(trans))) {
		return -EFAULT;
	}

	if (trans.new_cont[0] == '\0')
		return -EINVAL;

	brk->probe.pid = trans.pid;
	brk->probe.vaddr = trans.addr;
	brk->probe.handler = uprobe_handler;

	printk(KERN_INFO "Apathy: Setting breakpoint pid %d vaddr %p\n",
			brk->probe.pid, (void*)brk->probe.vaddr);
	memset(brk->new_cont, 0, sizeof(brk->new_cont));
	strncpy(brk->new_cont, trans.new_cont, CONT_MAXLEN);

	list_add(&brk->list, &break_list);

	ret = register_uprobe(&brk->probe);

	if (ret != 0) {
		printk(KERN_INFO "Apathy: failed to register uprobe\n");
		printk(KERN_INFO "Apathy: returned %d\n", ret);
		return -1;
	}

	return 0;
}

static void free_bpt_list(void)
{
	struct list_head *pos,*q;
	struct rs_break *tmp;

	list_for_each_safe(pos, q, &break_list) {
		tmp = list_entry(pos, struct rs_break,list);
		printk(KERN_INFO "Apathy: deleting list: %s\n", tmp->new_cont);
		unregister_uprobe(&tmp->probe);
		list_del(pos);

		kfree(tmp);
	}
}

int ioctl_del_break(const struct apathy_trans* tr)
{
	return 0;
}

long apathy_dev_ioctl(struct file *f,
		unsigned int cmd, unsigned long __user arg)
{
	switch (cmd) {
		case APATHY_IOCTL_SET_BREAK:
			printk(KERN_INFO "Apathy: ioctl set_break\n");

			return ioctl_set_break((struct apathy_trans*)arg);

		case APATHY_IOCTL_DEL_BREAK:
			printk(KERN_INFO "Apathy: ioctl del break\n");

			return ioctl_del_break((struct apathy_trans*)arg);

		default: break;
	}
	return -0;
}

int apathy_dev_release(struct inode *i, struct file* f)
{
	printk(KERN_INFO "Apathy: asdasd\n");
	/*
	if (f->ops.close)
		f->ops.close(f);

	*/
	module_put(THIS_MODULE);
	return 0;
}

int apathy_dev_open(struct inode *i, struct file *f)
{
	int ret;
	printk(KERN_INFO "Apathy: Open\n");

	if (!f)
		return -EIO;

	if (!try_module_get(THIS_MODULE)) {
		ret = EBUSY;
		return ret;
	}

	return 0;
}

struct file_operations apathy_file_ops = {
	.owner		= THIS_MODULE,
	// .read 		= apathy_dev_read,
	.open		= apathy_dev_open,
	.release 	= apathy_dev_release,
	.unlocked_ioctl = apathy_dev_ioctl,
};

static int apathy_init(void)
{
	int ret;

	apathy_class = class_create(THIS_MODULE, "apathy");

	if (!apathy_class) {
		printk(KERN_INFO "Apathy: Failed to create device class.\n");
		return -EFAULT;
	}

	ret = alloc_chrdev_region(&apathy_devt, 0, 11, "apathy");

	if (ret < 0) {
		printk(KERN_INFO "Apathy: Failed to allocate chardev region.\n");
		return -EFAULT;
	}

	dev_set_name(&apathy_dev, "apathy");
	cdev_init(&apathy_cdev, &apathy_file_ops);
	apathy_cdev.ops = &apathy_file_ops;
	apathy_cdev.owner = THIS_MODULE;

	apathy_dev.devt = MKDEV(MAJOR(apathy_devt),MINOR(apathy_devt));
	apathy_dev.release = apathy_destructor;

	ret = cdev_add(&apathy_cdev, apathy_dev.devt, 1);

	if (ret < 0) {
		printk(KERN_INFO "Apathy: failed to add cdev\n");
		return -EFAULT;
	}

	ret = device_register(&apathy_dev);

	if (ret < 0) {
		printk(KERN_INFO "Apathy: failed to register device\n");
		return -EFAULT;
	}

	/*
	struct task_struct *tmp;
	u32 sid;
	char *p;
	printk("Listing processes and contexts\n");
	for_each_process(tmp) {
		selinux_kern_getprocattr(tmp, "current", &p);
		// printk("Task pid: %u procattr: %s\n", tmp->pid, p);
		if ( strcmp( p, "unconfined_u:unconfined_r:acedia_t:s0-s0:c0.c1023" ) == 0 ) {
			printk( "Setting context\n" );
			
			ret = selinux_string_to_sid( "system_u:system_r:sshd_t:s0-s0:c0.c1023",
						sizeof("system_u:system_r:sshd_t:s0-s0:c0.c1023"), &sid );

			if ( ret == -EINVAL ) {
				printk( "Shit\n" );
			} else {
				printk( "Sid: %u\n", sid );
			}

			ret = selinux_kern_setprocattr( tmp, "current", "system_u:system_r:sshd_t:s0-s0:c0.c1023",
								sizeof( "system_u:system_r:sshd_t:s0-s0:c0.c1023" ));

			printk( "Returned %d\n", ret );

		}
	}

	printk("Listing finished\n");
	*/
	return 0;
}

static void apathy_exit(void)
{
	printk(KERN_INFO "Exiting apathy\n");
	device_unregister(&apathy_dev);
	unregister_chrdev_region(apathy_devt, 11);
	class_destroy(apathy_class);
	free_bpt_list();
}

module_init(apathy_init);
module_exit(apathy_exit);
