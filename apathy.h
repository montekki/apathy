#ifndef APATHY_H
#define APATHY_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <linux/time.h>
#else
#include <sys/ioctl.h>
#include <sys/mman.h>
#endif


/* max assumed length of SELinux context */
#define CONT_MAXLEN 		256

/*FIXME: Check ioctl number */
#define APATHY_IOCTL_MAGIC 	0x8e

/*! \struct apathy_trans
  \brief information about context transition point
  */
struct apathy_trans {
	unsigned int pid; 		/*!< pid of the process */
	unsigned long addr; 		/*!< address of the break */
	char new_cont[CONT_MAXLEN]; 	/*!< new context */
};
	
/*! \def APATHY_IOCTL_SET_BREAK
  \brief set a new context transition control point
  */
#define APATHY_IOCTL_SET_BREAK \
	_IOWR(APATHY_IOCTL_MAGIC, 0, struct apathy_trans)

/*! \def APATHY_IOCTL_DEL_BREAK \
  \brief delete context transition control point
  */
#define APATHY_IOCTL_DEL_BREAK \
	_IOWR(APATHY_IOCTL_MAGIC, 1, struct apathy_trans)

#endif /* APATHY_H */
