dnl Author: Yifang Cao

AC_INIT([skey], [2.0])
AC_CONFIG_SRCDIR([skey-2.0/skey-src/src/skey.c])
AC_CONFIG_HEADERS([config.h])

AH_TOP([
	/* Author : Yifang Cao 
	 */
	#ifndef _CONFIG_H_
	#define _CONFIG_H_
])
AH_BOTTOM([

	#endif /* not _CONFIG_H */

	/*End of skey-2.0 config.h file*/
])

AC_CONFIG_AUX_DIR([build-aux])
AC_COPYRIGHT([Copyright (c) 2016 Yifang Cao])

AC_MSG_NOTICE(*** SYSTEM TYPES ***)
AC_CANONICAL_HOST
AMU_HOST_MACROS

AC_MSG_NOTICE(*** PACKAGE NAME AND VERSION ***)
AC_CONFIG_MACRO_DIR([skey-2.0/m4])

AC_MSG_NOTICE(*** EXTRA OPTION PROCESSING ***)
AMU_OS_CPPFLAGS
AMU_OS_CFLAGS
AMU_OS_LDFLAGS

AM_INIT_AUTOMAKE
AC_PROG_CC
AC_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_GCC_TRADITIONAL
AC_PROG_MAKE_SET
AC_ISC_POSIX
AC_AIX
AC_PROG_RANLIB
AC_MSG_NOTICE(*** OPTION PROCESSING ***)


AC_MSG_NOTICE(*** LIBRARY FILES ***)
AC_CHECK_HEADERS(stdlib.h    \
				termios.h    \
				termio.h     \
				sys/quota.h  \
				sys/systeminfo.h  \
				unistd.h 	\
				shadow.h 	\
				)

AC_CHECK_FUNCS(dqhashshift)


AC_CONFIG_FILES(
		Makefile
		skey-2.0/include/Makefile
		skey-2.0/bin/Makefile
		skey-2.0/other/Makefile
		skey-2.0/lib/Makefile
		skey-2.0/man/Makefile
				)

AC_MSG_NOTICE(*** ARCHITECTURES ***)
AC_CHECK_SIZEOF(size_t)
AC_C_BIGENDIAN

dnl Here you go 
AC_OUTPUT