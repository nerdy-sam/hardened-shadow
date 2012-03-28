# Copyright (c) 2012, Paweł Hajdan, Jr.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

AC_PREREQ([2.67])
AC_INIT([hardened-shadow],
	[0.9.1],
	[http://code.google.com/p/hardened-shadow/issues],
	[],
	[http://code.google.com/p/hardened-shadow])
AC_CONFIG_MACRO_DIR([m4])
AC_GNU_SOURCE

AC_ARG_WITH([rootprefix],
	AS_HELP_STRING([--with-rootprefix=DIR], [Root directory ("/")]),
	[],
	[case $prefix in
		NONE | /usr) with_rootprefix=/ ;;
		*) with_rootprefix=${prefix} ;;
	esac])
AC_ARG_WITH([rootlibdir],
	AS_HELP_STRING([--with-rootlibdir=DIR], [Root directory for libraries necessary for boot]),
	[],
	[with_rootlibdir=${with_rootprefix}/lib])
AC_ARG_WITH([pamlibdir],
	AS_HELP_STRING([--with-pamlibdir=DIR], [Directory for PAM modules]),
	[],
	[with_pamlibdir=${with_rootlibdir}/security])

AC_SUBST([rootprefix], [$with_rootprefix])
AC_SUBST([rootlibdir], [$with_rootlibdir])
AC_SUBST([pamlibdir], [$with_pamlibdir])

AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects silent-rules])
AM_SILENT_RULES
LT_INIT([pic-only disable-static])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_DEFINE([UNUSED], [__attribute__((unused))], [Shortcut and possible compatibility shim for "unused" attribute.])

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

CC_CHECK_CFLAGS_APPEND([ \
	-Wall \
	-Wextra \
	-fstack-protector-all \
	-fPIE])

# Checks for header files.
AC_CHECK_HEADERS([ \
	fcntl.h \
	limits.h \
	locale.h \
	malloc.h \
	netdb.h \
	paths.h \
	shadow.h \
	stdlib.h \
	string.h \
	syslog.h \
	sys/ioctl.h \
	sys/socket.h \
	sys/time.h \
	termios.h \
	unistd.h \
	utmp.h \
	utmpx.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_HEADER_STDBOOL
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_rdev])

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_FSEEKO
AC_FUNC_GETGROUPS
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_CHECK_FUNCS([ \
	endgrent \
	endpwent \
	fdatasync \
	gethostname \
	getspnam \
	gettimeofday \
	getusershell \
	lchown \
	memchr \
	memset \
	mkdir \
	putenv \
	rmdir \
	setenv \
	setlocale \
	stpcpy \
	strcasecmp \
	strchr \
	strcspn \
	strdup \
	strerror \
	strspn])

AC_ARG_ENABLE([werror], [AS_HELP_STRING([--enable-werror], [make compiler warnings into errors])])
AS_IF([test x$enable_werror = xyes], [CC_CHECK_CFLAGS_APPEND([-Werror])])

AC_ARG_ENABLE([generate-man], [AS_HELP_STRING([--enable-generate-man], [generate man pages from xml files])])
if test "x$enable_generate_man" = "xyes"; then
        AC_PATH_PROG([XSLTPROC], [xsltproc])
        if test -z "$XSLTPROC"; then
		AC_MSG_ERROR([*** xsltproc not found])
        fi

        JH_CHECK_XML_CATALOG([-//OASIS//DTD DocBook XML V4.5//EN],
                [DocBook XML DTD V4.5], [], AC_MSG_ERROR([*** DocBook DTD not found]))
        JH_CHECK_XML_CATALOG([http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl],
                [DocBook XSL Stylesheets >= 1.70.1], [], AC_MSG_ERROR([*** DocBook Stylesheet not found]))
fi

AM_CONDITIONAL(GENERATE_MAN, [test x$enable_generate_man = xyes])

AC_ARG_WITH([default-shell], [AS_HELP_STRING([--with-default-shell=SHELL], [use SHELL as default shell, default is /bin/sh])], [], [with_default_shell=/bin/sh])
AC_DEFINE_UNQUOTED(HARDENED_SHADOW_DEFAULT_SHELL, ["$with_default_shell"], [The default shell.])

AC_ARG_WITH([hardened-shadow-group], [AS_HELP_STRING([--with-hardened-shadow-group=GROUP], [use GROUP as the hardened-shadow group, default is hardened-shadow])], [], [with_hardened_shadow_group=hardened-shadow])
AC_SUBST([hardened_shadow_group], [$with_hardened_shadow_group])
AC_DEFINE_UNQUOTED(HARDENED_SHADOW_GROUP, ["$with_hardened_shadow_group"], [The name of the hardened-shadow group.])

AC_OUTPUT
AC_MSG_RESULT([
	$PACKAGE_NAME $VERSION

	prefix:			${prefix}
	exec_prefix:		${exec_prefix}
	rootprefix:		${with_rootprefix}
	libdir:			${libdir}
	rootlibdir:		${with_rootlibdir}
	pamlibdir:		${with_pamlibdir}
])
