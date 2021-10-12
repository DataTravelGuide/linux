ifneq ($(KERNELRELEASE),)

obj-m	:= sysrq-ping.o

else

KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
endif

clean:
	rm -rf *o .*.cmd .tmp* *.mod.c
