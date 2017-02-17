ifneq ($(KERNELRELEASE),)
    obj-m:=myhook.o
else
KERNELDIR:=/lib/modules/$(shell uname -r)/build
PWD:=$(shell pwd)
default:
	$(MAKE) -C $(KERNELDIR)  M=$(PWD) modules
	gcc -o upredirect main.c
clean:
	rm -rf *.o *.mod.c *.mod.o *.ko
	rm upredirect
endif
