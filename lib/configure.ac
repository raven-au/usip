AC_PREREQ([2.69])
AC_INIT([usip], [1.0.0])
AC_CONFIG_SRCDIR([src/mtab.c])
AC_CONFIG_HEADERS([include/config.h])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([-Wall -Werror silent-rules])

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_AR
AC_PROG_LIBTOOL
PKG_PROG_PKG_CONFIG

# Checks for libraries.
PKG_CHECK_MODULES([LIBNL], [libnl-genl-3.0])
AC_CHECK_LIB([pthread], [pthread_create])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h errno.h string.h unistd.h stdbool.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

AC_FUNC_MALLOC
AC_CHECK_FUNCS([strerror])

AC_OUTPUT(Makefile include/Makefile src/Makefile)
AC_OUTPUT(libusip.pc)
