#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>

#include "apathy.h"


#define APATHY_DEVICE "/dev/apathy"

int main(int argc, char ** argv)
{
	struct apathy_trans tr;
	int res;
	int fd;

	tr.pid = 1488;
	tr.addr = 0x08888;
	memset(tr.new_cont,0,sizeof(tr.new_cont));
	strncpy(tr.new_cont, "New context", CONT_MAXLEN-1);

	fd = open( APATHY_DEVICE, O_RDWR );

	if (fd < 0) {
		fprintf(stderr, "Failed to open device %s\n",
				APATHY_DEVICE);
		return (-1);
	}

	res = ioctl(fd, APATHY_IOCTL_SET_BREAK, &tr);

	return 0;
}
