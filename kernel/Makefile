
NAME = usip

# Include configuration for this system
SRCDIR := $(shell pwd)
VERSION ?= $(shell uname -r)
KERNELDIR ?= /lib/modules/$(VERSION)/build
KERNELMAP ?= /lib/modules/$(VERSION)/System.map

DESTDIR =

INCLUDEDIR := $(KERNELDIR)/include
INSTALLDIR := /lib/modules/$(VERSION)/kernel
MODDIR := $(INSTALLDIR)/fs/$(NAME)

KERNELCFG = $(KERNELDIR)/.config
-include $(KERNELCFG)

VERBOSE ?=
#VERBOSE = "V=1"

INSTALL := /usr/bin/install
DEPMOD := /sbin/depmod

.PHONY: all install uninstall remove default clean

all: include-test config-test default

O_HDRS  = usip.h internal.h
O_SRCS  = init.c event.c notify_pool.c storage.c mtab.c log.c util.c test.c
O_OBJS  = init.o event.o notify_pool.o storage.o mtab.o log.o util.o test.o
O_OTHER = Makefile
TARGET	= $(NAME).o

$(O_OBJS): $(O_HDRS) $(O_SRCS)

MODULE = $(NAME).ko

obj-m := $(TARGET)
$(NAME)-objs := $(O_OBJS)

default:
	$(MAKE) $(VERBOSE) -C $(KERNELDIR) M=${SRCDIR} modules

BACKUP  = $(shell test -e $(MODDIR)/$(MODULE).orig || echo "-b --suffix=.orig")

install: all
	-@$(INSTALL) -o root -g root -m 755 -d $(DESTDIR)$(MODDIR)
	$(INSTALL) -o root -g root -m 644 $(BACKUP) $(MODULE) $(DESTDIR)$(MODDIR)
	$(DEPMOD) -eF $(KERNELMAP)

uninstall:
	if test -e $(DESTDIR)$(MODDIR)/$(MODULE).orig; then \
		mv -f $(DESTDIR)$(MODDIR)/$(MODULE).orig $(DESTDIR)$(MODDIR)/$(MODULE); \
	fi

remove:
	if test -d $(DESTDIR)$(MODDIR); then \
		rm -rf $(DESTDIR)$(MODDIR); \
	fi

.PHONY: include-test
include-test:
	@# INCLUDEDIR must point to a valid tree of header files.
	@#   We just test for one we know should be there and must
	@#   fail if it can't be found.
	@if ! test -e $(INCLUDEDIR)/linux/module.h; then \
		echo "ERROR: include files directory does not seem to be valid"; \
		exit 1; \
	fi

.PHONY: config-test
config-test:
	@# KERNELCFG must point to a valid kernel config file.
	@if ! (test -e $(KERNELCFG) -o -e $(KERNELDIR)/.config); then \
		echo "ERROR: kernel config file cannot be found"; \
		exit 1; \
	fi

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

.PHONY: tags
tags:
	ctags *.[hc]

