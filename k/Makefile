obj-m += tcm.o

tcm-y := src/main.o \
	src/netlink/genl.o \
	src/listeners/fork.o \
	src/listeners/forkret.o \
	src/listeners/file.o

KDIR ?= /lib/modules/$(shell uname -r)/build
MO ?= $(CURDIR)/build

ccflags-y += -I$(src)/include -I$(src)/api/include

.PHONY: all clean help i install u remove uninstall r reload l ls lsmod

all:
	@mkdir -p $(MO)
	@$(MAKE) -C $(KDIR) M=$(CURDIR) MO=$(MO) modules

clean:
	@$(MAKE) -C $(KDIR) M=$(CURDIR) MO=$(MO) clean
	@if [ "$(MO)" != "$(CURDIR)" ]; then \
		rm -rf $(MO); \
	fi

i install: all
	sudo insmod $(MO)/tcm.ko || true

u remove uninstall:
	sudo rmmod tcm || true

r reload: all
	sudo rmmod tcm || true
	sudo insmod $(MO)/tcm.ko

l ls lsmod:
	@if sudo lsmod | grep -q tcm; then \
		echo "tcm module is loaded"; \
	else \
		echo "tcm module is not loaded"; \
	fi

help:
	echo "make"
	echo "make KDIR=/path/to/kernel/build"
	echo "make KBUILD_OUTPUT=/path/to/outdir"
	echo "make clean"
