# Makefile for building kernel module

name = yunblock

# Имя модуля ядра
obj-m += $(name).o

# Указание пути к заголовочным файлам ядра
KDIR := /lib/modules/$(shell uname -r)/build

# Каталог текущего проекта
PWD := $(shell pwd)
ccflags-y := -DKERNEL_SPACE

# Цель для сборки модуля
all:
	mkdir -p $(KDIR)
	$(MAKE) -C $(KDIR) M=$(PWD) modules


# Чистка скомпилированных файлов
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) EXTRA_CFLAGS="$(ccflags-y)" clean

# Загрузка модуля в ядро
insmod: all
	sudo insmod $(name).ko

# Удаление модуля из ядра
rmmod:
	sudo rmmod $(name)