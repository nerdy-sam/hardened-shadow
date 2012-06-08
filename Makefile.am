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

ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS= -I$(srcdir)/common -DHARDENED_SHADOW_ROOT_PREFIX=\"$(rootprefix)\"
AM_LDFLAGS = -Wl,-z,relro -Wl,-z,now -pie -no-undefined

LDADD = libcommon.la
LIBADD = libcommon.la

# Make sure files installed into those directories
# are recognized as machine-dependent, see
# http://www.gnu.org/software/automake/manual/automake.html#The-Two-Parts-of-Install
execrootlibdir = $(rootlibdir)
execrootbindir = $(rootprefix)/bin
execrootsbindir = $(rootprefix)/sbin
execpamlibdir = $(pamlibdir)

noinst_LTLIBRARIES = libcommon.la
libcommon_la_SOURCES = \
	common/config.c \
	common/dir.c \
	common/hardened-shadow.h \
	common/file.c \
	common/misc.c \
	common/parse.c \
	common/print.c \
	common/pwck.c \
	common/safeint.c \
	common/syslog.c

execrootlib_LTLIBRARIES = libnss_hardened_shadow.la
libnss_hardened_shadow_la_SOURCES = \
	nsswitch/hardened_shadow.c
	nsswitch/hardened_shadow.map
libnss_hardened_shadow_la_LIBADD = libcommon.la
libnss_hardened_shadow_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info 2 --version-script=$(srcdir)nsswitch/hardened_shadow.map

execrootbin_PROGRAMS = \
	progs/get_shell \
	progs/groups \
	progs/login \
	progs/passwd \
	progs/shell_proxy \
	progs/su

bin_PROGRAMS = \
	progs/chage \
	progs/chsh \
	progs/lastlog

execrootsbin_PROGRAMS = progs/nologin

sbin_PROGRAMS = \
	progs/groupadd \
	progs/groupdel \
	progs/groupmod \
	progs/grpck \
	progs/pwck \
	progs/pwconv \
	progs/pwunconv \
	progs/useradd \
	progs/userdel \
	progs/usermod \
	progs/vipw

progs_login_LDADD = $(LDADD) -lpam -lpam_misc
progs_passwd_LDADD = $(LDADD) -lpam -lpam_misc
progs_su_LDADD = $(LDADD) -lpam -lpam_misc

pam_pam_hardened_shadow_la_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/pam
pam_pam_hardened_shadow_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-avoid-version \
	-module \
	-Wl,--version-script=$(srcdir)/pam/pam.map
pam_pam_hardened_shadow_la_LIBADD = $(LIBADD) -lpam -lcrypt

execpamlib_LTLIBRARIES = pam/pam_hardened_shadow.la

pam_pam_hardened_shadow_la_SOURCES = \
	pam/pam.map \
	pam/pam_hardened_shadow_acct.c \
	pam/pam_hardened_shadow_auth.c \
	pam/pam_hardened_shadow_passwd.c \
	pam/pam_hardened_shadow_sess.c \
	pam/support.c \
	pam/support.h

install-exec-hook:
	chown :wheel $(DESTDIR)$(execrootbindir)/su
	chmod 4710 $(DESTDIR)$(execrootbindir)/su
	chown :$(hardened_shadow_group) $(DESTDIR)$(execrootbindir)/get_shell
	chmod 2711 $(DESTDIR)$(execrootbindir)/get_shell
	chown :$(hardened_shadow_group) $(DESTDIR)$(bindir)/chage
	chmod 2711 $(DESTDIR)$(bindir)/chage
	chown :$(hardened_shadow_group) $(DESTDIR)$(bindir)/chsh
	chmod 2711 $(DESTDIR)$(bindir)/chsh
	chown :$(hardened_shadow_group) $(DESTDIR)$(execrootbindir)/passwd
	chmod 2711 $(DESTDIR)$(execrootbindir)/passwd

dist_sysconf_DATA = etc/hardened-shadow.conf etc/securetty

defaultdir = $(sysconfdir)/default
dist_default_DATA = etc/default/useradd

pamddir = $(sysconfdir)/pam.d
dist_pamd_DATA = \
	etc/pam.d/login \
	etc/pam.d/passwd \
	etc/pam.d/su

man_XMANS = \
	man/chage.1.xml \
	man/chsh.1.xml \
	man/grpck.8.xml \
	man/groupadd.8.xml \
	man/groupdel.8.xml \
	man/groupmod.8.xml \
	man/groups.1.xml \
	man/lastlog.8.xml \
	man/login.1.xml \
	man/nologin.8.xml \
	man/passwd.1.xml \
	man/pwck.8.xml \
	man/pwconv.8.xml \
	man/su.1.xml \
	man/useradd.8.xml \
	man/userdel.8.xml \
	man/usermod.8.xml \
	man/vipw.8.xml

man_MANS = \
	man/chage.1 \
	man/chsh.1 \
	man/grpck.8 \
	man/groupadd.8 \
	man/groupdel.8 \
	man/groupmod.8 \
	man/groups.1 \
	man/lastlog.8 \
	man/login.1 \
	man/nologin.8 \
	man/passwd.1 \
	man/pwck.8 \
	man/pwconv.8 \
	man/pwunconv.8 \
	man/su.1 \
	man/useradd.8 \
	man/userdel.8 \
	man/usermod.8 \
	man/vipw.8

EXTRA_DIST = $(man_MANS) $(man_XMANS) README

if GENERATE_MAN
CLEANFILES = $(man_MANS)

% : %.xml
	$(XSLTPROC) -o $@ --nonet http://docbook.sourceforge.net/release/xsl/current/manpages/profile-docbook.xsl $<

man/pwunconv.8: man/pwconv.8.xml
endif
