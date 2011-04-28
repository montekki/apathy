obj-m := apathy.o

KDIR 	?= $(shell uname -r)
KPATH 	?= /usr/src/linux-headers-$(KDIR)
KBDIR	?= /lib/modules/$(KDIR)/build


PWD := $(shell pwd)

default:
	$(MAKE) -C $(KPATH) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KPATH) SUBDIRS=$(PWD) clean
