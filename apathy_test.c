#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "apathy.h"


#define APATHY_DEVICE "/dev/apathy"

int main(int argc, char ** argv)
{
	struct apathy_trans tr;
	int res;
	int fd;

	strcpy(tr.bin_file, "/root/apathy/apathy_test2");
	tr.addr = 0x4005f8; // &&addr;
	memset(tr.new_cont,0,sizeof(tr.new_cont));
	strncpy(tr.new_cont, "system_u:system_r:sshd_t:s0-s0:c0.c1023", CONT_MAXLEN-1);

	fd = open( APATHY_DEVICE, O_RDWR );

	if (fd < 0) {
		fprintf(stderr, "Failed to open device %s\n",
				APATHY_DEVICE);
		return (-1);
	}

	res = ioctl(fd, APATHY_IOCTL_SET_BREAK, &tr);

	/*
	getchar();

	printf("shit\n");
	while (1) {
addr:
		sleep(1);
	}
	*/
	return 0;
}
