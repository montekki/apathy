#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/selinux.h>
#include <linux/init.h>
#include <linux/uprobes.h>
#include <linux/utrace.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/binfmts.h>
#include <asm/uaccess.h>

#include "apathy.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fedor Sakharov <sakharov@lvk.cs.msu.su>");
MODULE_DESCRIPTION("Application safe execution control");

struct rs_break {
	struct list_head list;
	struct uprobe probe;		// uprobe struct, describing this bpt
	char new_cont[CONT_MAXLEN]; 	// new SELinux context of the process
};

struct rs_info {
	struct list_head list;
	struct apathy_trans trans;
};

LIST_HEAD(break_list);
LIST_HEAD(info_list);

static struct class *apathy_class;
static struct device apathy_dev;
static struct cdev   apathy_cdev;
static dev_t  apathy_devt;

static struct utrace_engine *engine = NULL;

static void uprobe_handler(struct uprobe* u, struct pt_regs *regs);

static int unreg_bpts(pid_t pid)
{
	struct list_head *pos,*q;
	struct rs_break *tmp;

	list_for_each_safe(pos, q, &break_list) {
		tmp = list_entry(pos, struct rs_break,list);
		if (tmp->probe.pid == pid) {
			unregister_uprobe(&tmp->probe);
			list_del(pos);
			kfree(tmp);
		}
	}

	return 0;
}

static int set_bpt(const struct rs_info* info)
{
	struct rs_break *brk;
	int ret = 0;

	brk = kzalloc(sizeof(struct rs_break), GFP_KERNEL);

	if (!brk) {
		ret = -ENOMEM;
		goto out;
	}

	printk("Apathy: Some info %u %p\n", current->pid, (void*)info->trans.addr);
	brk->probe.pid = current->pid;
	brk->probe.vaddr = info->trans.addr;
	brk->probe.handler = uprobe_handler;
	brk->probe.kdata = NULL;

	strncpy(brk->new_cont,info->trans.new_cont,CONT_MAXLEN-1);

	ret = register_uprobe(&brk->probe);

	if (ret) {
		printk(KERN_INFO "Apathy: register_uprobe returned %d\n", ret);
		goto out_clean;
	}

	list_add(&brk->list,&break_list);

	return 0;

out_clean:
	kfree(brk);

out:
	return ret;
}

static u32 my_report_exec(u32 action, struct utrace_engine *engine,
		const struct linux_binfmt *fmt,
		const struct linux_binprm *bprm,
		struct pt_regs *regs)
{
	struct list_head *pos;
	struct rs_info *tmp;
	int ret;
	printk(KERN_INFO "Apathy: my report exec\n");

	list_for_each(pos, &info_list) {
		tmp = list_entry(pos, struct rs_info, list);

		if (!strcmp(bprm->filename,tmp->trans.bin_file)) {
			printk(KERN_INFO "Apathy: About to set bpt on %s\n",
					tmp->trans.bin_file);

			set_bpt(tmp);
		}
	}
	return 0;
}

static u32 my_report_exit(u32 action, struct utrace_engine *e,
		long orig_code, long *code)
{
	int ret;
	printk(KERN_INFO "Apathy: my_report_exit\n");

	ret = utrace_control(current, engine, UTRACE_DETACH);

	engine = 0;

	unreg_bpts(current->pid);

	return 0;
}

static struct utrace_engine_ops my_utrace_ops = {
	.report_exec = my_report_exec,
	.report_exit = my_report_exit,
};

static void uprobe_handler(struct uprobe* u, struct pt_regs *regs)
{
	struct list_head *pos;
	struct task_struct *task;
	struct rs_break *tmp;
	int ret;
	u32 sid;

	printk(KERN_INFO "Apathy: handler\n");
	list_for_each(pos, &break_list) {
		tmp = list_entry(pos, struct rs_break, list);
		if (tmp->probe.vaddr == u->vaddr ) {
			printk(KERN_INFO "Hit breakpoint at: %p\n", (void*)u->vaddr);
			printk(KERN_INFO "New context is %s\n", tmp->new_cont);

			ret = selinux_string_to_sid(tmp->new_cont,
					strlen(tmp->new_cont), &sid);

			if (ret == -EINVAL) {
				printk("Acedia: Failed to translate context to sid: %s\n",
						tmp->new_cont);
				return;
			} else {
				printk("Acedia: Sid for %s is %u\n", tmp->new_cont, sid);
			}

			for_each_process(task) {
				if (task->pid == tmp->probe.pid) {
					printk(KERN_INFO "Acedia: Here\n");

					ret = selinux_kern_setprocattr( task, "current",
							tmp->new_cont, strlen(tmp->new_cont));
				}
			}

			break;
		}
	}
}


static int handl_sbh(struct linux_binprm *bprm,struct pt_regs *regs)
{
	struct list_head *pos;
	struct rs_info *tmp;
	int ret;

	list_for_each(pos, &info_list) {
		tmp = list_entry(pos, struct rs_info, list);

		if (!strcmp(bprm->filename,tmp->trans.bin_file)) {
			printk(KERN_INFO "Apathy: About to set bpt on %s\n",
					tmp->trans.bin_file);

			if (engine == 0 )
				engine = utrace_attach_task(current, UTRACE_ATTACH_CREATE, &my_utrace_ops, NULL);

			if ( engine ) {
				ret = utrace_set_events(current, engine, UTRACE_EVENT(EXEC) | UTRACE_EVENT(EXIT));
			} else {
				printk(KERN_INFO "Apathy: failed to attach utrace engine\n");
			}

			//set_bpt(tmp);
		}
	}

	jprobe_return();
}

static struct jprobe do_execve_jprobe = {
	.kp.addr = (kprobe_opcode_t *)search_binary_handler,
	.entry   = (kprobe_opcode_t *)handl_sbh
};

static void apathy_destructor(struct device *d)
{
}

ssize_t apathy_dev_read(struct file* file, char *buffer,
		size_t length, loff_t* offset)
{
	printk(KERN_INFO "Apathy: device read is not implemented\n");
	return -0;
}

int ioctl_set_break(void __user *p)
{
	struct rs_info *brk;
	struct list_head *pos;
	struct rs_info *tmp;
	int ret;

	brk = kzalloc(sizeof(struct rs_info),GFP_KERNEL);

	if (!brk) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(&brk->trans, p, sizeof(struct apathy_trans))) {
		ret = -EFAULT;
		goto out_clean;
	}

	if (brk->trans.new_cont[0] == '\0') {
		ret = -EINVAL;
		goto out_clean;
	}

	if (brk->trans.bin_file[0] == '\0') {
		ret = -EINVAL;
		goto out_clean;
	}

	list_for_each(pos, &info_list) {
		tmp = list_entry(pos, struct rs_info, list);
		if (tmp->trans.addr == brk->trans.addr &&
			strcmp(tmp->trans.bin_file,brk->trans.bin_file) == 0 &&
			strcmp(tmp->trans.new_cont,brk->trans.new_cont) == 0) {
			printk(KERN_INFO "Apathy: Breakpoint at %p for %s exists.\n",
					(void*)tmp->trans.addr,tmp->trans.bin_file);
			ret = -EBUSY;
			goto out_clean;
		}
	}

	list_add(&brk->list, &info_list);
	printk( KERN_INFO "Apathy: Set bpt for %s\n", brk->trans.bin_file);

	return 0;

out_clean:

	kfree(brk);
out:
	return ret;

	/*
	brk->probe.pid = trans.pid;
	brk->probe.vaddr = trans.addr;
	brk->probe.handler = uprobe_handler;
	brk->probe.kdata = null;

	printk(kern_info "apathy: setting breakpoint pid %d vaddr %p\n",
			brk->probe.pid, (void*)brk->probe.vaddr);
	memset(brk->new_cont, 0, sizeof(brk->new_cont));
	strncpy(brk->new_cont, trans.new_cont, cont_maxlen);

	list_add(&brk->list, &break_list);

	ret = register_uprobe(&brk->probe);

	if (ret != 0) {
		unregister_uprobe(&brk->probe);
		printk(KERN_INFO "Apathy: failed to register uprobe\n");
		printk(KERN_INFO "Apathy: returned %d\n", ret);
	}
	*/

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

static void free_inf_list(void)
{
	struct list_head *pos, *q;
	struct rs_info *tmp;

	list_for_each_safe(pos, q, &info_list) {
		tmp = list_entry(pos, struct rs_info, list);
		printk( KERN_INFO "Apathy: deleting info: %s\n", tmp->trans.bin_file);
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

	register_jprobe(&do_execve_jprobe);
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
	free_inf_list();
	unregister_jprobe(&do_execve_jprobe);
}

module_init(apathy_init);
module_exit(apathy_exit);
