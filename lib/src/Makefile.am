
lib_LTLIBRARIES		= libusip.la
libusip_la_SOURCES	= event.c mtab.c storage.c util.c

CLEANFILES		= cscope.in.out cscope.out cscope.po.out *~
DISTCLEANFILES		= Makefile.in

AM_CPPFLAGS		= -I. @LIBNL_CFLAGS@
AM_CFLAGS		= -Wall
AM_LDFLAGS		= @LIBNL_LIBS@ -lpthread
