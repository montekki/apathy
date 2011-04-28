#ifndef APATHY_H
#define APATHY_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/time.h>
#else
#include <sys/ioctl.h>
#include <sys/mman.h>
#endif

/*FIXME: Check ioctl number */

/** max assumed length of SELinux context */

#define CONT_MAXLEN 		256

#define APATHY_IOCTL_MAGIC 	0x8e

struct apathy_trans {
	unsigned int pid; 		/*!< pid of the process */
	unsigned long addr; 		/*!< address of the break */
	char new_cont[CONT_MAXLEN]; 	/*!< new context */
};
	
#define APATHY_IOCTL_SET_BREAK \
	_IOWR(APATHY_IOCTL_MAGIC, 0, struct apathy_trans)

#define APATHY_IOCTL_DEL_BREAK \
	_IOWR(APATHY_IOCTL_MAGIC, 1, struct apathy_trans)

#endif /* APATHY_H */
