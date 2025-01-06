#Kernel module makes here
PWD := $(CURDIR)

CC	:= gcc 
CCLD	:= $(CC)
LD	:= ld
CFLAGS	:=
LDFLAGS	:=

KERNEL_BUILDER_MAKEDIR:=/lib/modules/$(shell uname -r)/build

.PHONY: kmake kload kunload kreload kclean kmclean xclean
kmake: kmod

kmod:
	$(MAKE) -C $(KERNEL_BUILDER_MAKEDIR) M=$(PWD) EXTRA_CFLAGS='-DPKG_VERSION=\"$(PKG_FULLVERSION)\"' modules

kload:
	sudo insmod kyoutubeUnblock.ko

kunload:
	-sudo rmmod kyoutubeUnblock

kreload: kunload kload

kclean: kmclean

kmclean:
	-$(MAKE) -C $(KERNEL_BUILDER_MAKEDIR) M=$(PWD) clean
