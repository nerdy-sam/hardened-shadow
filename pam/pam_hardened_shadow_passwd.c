/*
 * Main coding by Elliot Lee <sopwith@redhat.com>, Red Hat Software.
 * Copyright (C) 1996.
 * Copyright (c) Jan Rękorajski, 1999.
 * Copyright (c) Red Hat, Inc., 2007, 2008.
 * Copyright (c) 2012, Paweł Hajdan, Jr.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <pwd.h>
#include <syslog.h>
#include <shadow.h>
#include <time.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>

#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include "hardened-shadow.h"
#include "support.h"

#define _UNIX_OLD_AUTHTOK	"-UN*X-OLD-PASS"
#define _UNIX_NEW_AUTHTOK	"-UN*X-NEW-PASS"

#define MAX_PASSWD_TRIES	3

static int _unix_verify_shadow(pam_handle_t *pamh, const char *user, unsigned int ctrl) {
  struct passwd *pwent = NULL;
  struct spwd *spent = NULL;
  int retval = get_account_info(pamh, user, &pwent, &spent);
  if (retval == PAM_USER_UNKNOWN)
    return retval;

  if (retval == PAM_SUCCESS && spent == NULL)
    return PAM_SUCCESS;

  if (retval == PAM_SUCCESS) {
    int daysleft;
    retval = check_shadow_expiry(pamh, spent, &daysleft);
  }

  if (on(UNIX__IAMROOT, ctrl) || retval == PAM_NEW_AUTHTOK_REQD)
    return PAM_SUCCESS;

  return retval;
}

static int _pam_unix_approve_pass(pam_handle_t *pamh, unsigned int ctrl, const char *pass_old, const char *pass_new) {
  if (!pass_new) {
    _make_remark(pamh, ctrl, PAM_ERROR_MSG, "No password supplied");
    return PAM_AUTHTOK_ERR;
  }

  if (pass_old && strcmp(pass_old, pass_new) == 0) {
    _make_remark(pamh, ctrl, PAM_ERROR_MSG, "Password unchanged");
    return PAM_AUTHTOK_ERR;
  }

  return PAM_SUCCESS;
}

static int prelim_check(pam_handle_t *pamh, int ctrl, const char *user) {
  int retval = PAM_SUCCESS;

  if (on(UNIX__NULLOK, ctrl) && _unix_blankpasswd(pamh, user))
    return PAM_SUCCESS;

  char *pass_old = NULL;
  if (on(UNIX__IAMROOT, ctrl)) {
    retval = PAM_SUCCESS;
  } else {
    if (off(UNIX__QUIET, ctrl)) {
      retval = pam_info(pamh, "Changing password for %s.", user);
      if (retval != PAM_SUCCESS)
        return retval;
    }

    retval = _unix_read_password(pamh, ctrl, PAM_OLDAUTHTOK, "(current) UNIX password: ", NULL, _UNIX_OLD_AUTHTOK, &pass_old);

    if (retval != PAM_SUCCESS) {
      pam_syslog(pamh, LOG_NOTICE, "password - (old) token not obtained");
      return retval;
    }

    retval = _unix_verify_password(pamh, user, pass_old, ctrl);
  }

  if (retval != PAM_SUCCESS) {
    pass_old = NULL;
    return retval;
  }

  retval = pam_set_item(pamh, PAM_OLDAUTHTOK, pass_old);
  pass_old = NULL;
  if (retval != PAM_SUCCESS)
    pam_syslog(pamh, LOG_CRIT, "failed to set PAM_OLDAUTHTOK");

  retval = _unix_verify_shadow(pamh, user, ctrl);
  if (retval == PAM_AUTHTOK_ERR) {
    if (on(UNIX__IAMROOT, ctrl))
      retval = PAM_SUCCESS;
    else
      _make_remark(pamh, ctrl, PAM_ERROR_MSG, "You must wait longer to change your password");
  }

  return retval;
}

static int i64c(int i) {
  if (i <= 0)
    return ('.');
  else if (i > 63)
    return ('z');
  if (i == 1)
    return ('/');
  if (i >= 2 && i <= 11)
    return ('0' - 2 + i);
  if (i >= 12 && i <= 37)
    return ('A' - 12 + i);
  if (i >= 38 && i <= 63)
    return ('a' - 38 + i);
  return ('\0');
}

static bool crypt_make_salt(char *where, int length) {
  unsigned char *src = (unsigned char *)where;
  int fd = TEMP_FAILURE_RETRY(open("/dev/urandom", O_RDONLY | O_CLOEXEC));
  if (fd < 0)
    return false;

  bool result = true;
  if (!hardened_shadow_read(fd, where, length)) {
    result = false;
    goto out;
  }

  for (int i = 0; i < length; i++)
    *where++ = i64c(src[i] & 077);
  *where = '\0';

out:
  TEMP_FAILURE_RETRY(close(fd));
  return result;
}

static char *create_password_hash(pam_handle_t *pamh, const char *password, const char *prefix) {
  char salt[64]; /* contains max 16 bytes of salt + algo id */

  if (strlen(prefix) > sizeof(salt) - 8)
    return NULL;
  char *sp = stpcpy(salt, prefix);
  if (!crypt_make_salt(sp, 8))
    return NULL;
  sp = crypt(password, salt);
  if (!hardened_shadow_starts_with(sp, prefix)) {
    pam_syslog(pamh, LOG_ERR, "Prefix %s not supported by the crypto backend.", prefix);
    memset(sp, '\0', strlen(sp));
    return NULL;
  }

  return strdup(sp);
}

static int update_pam(pam_handle_t *pamh, unsigned int ctrl, const char *user, const char *prefix) {
  int retval = PAM_SUCCESS;
  const void *pass_old = NULL;
  if (off(UNIX_NOT_SET_PASS, ctrl)) {
    retval = pam_get_item(pamh, PAM_OLDAUTHTOK, &pass_old);
  } else {
    retval = pam_get_data(pamh, _UNIX_OLD_AUTHTOK, &pass_old);
    if (retval == PAM_NO_MODULE_DATA) {
      retval = PAM_SUCCESS;
      pass_old = NULL;
    }
  }

  if (retval != PAM_SUCCESS) {
    pam_syslog(pamh, LOG_NOTICE, "user not authenticated");
    return retval;
  }

  unsigned int lctrl = ctrl;

  if (on(UNIX_USE_AUTHTOK, lctrl))
    set(UNIX_USE_FIRST_PASS, &lctrl);

  int retry = 0;
  retval = PAM_AUTHTOK_ERR;
  char *pass_new = NULL;
  while ((retval != PAM_SUCCESS) && (retry++ < MAX_PASSWD_TRIES)) {
    retval = _unix_read_password(pamh, lctrl, PAM_AUTHTOK, "Enter new UNIX password: ", "Retype new UNIX password: ", _UNIX_NEW_AUTHTOK, &pass_new);

    if (retval != PAM_SUCCESS) {
      pass_old = NULL;
      return retval;
    }

    if (*pass_new == '\0')
      pass_new = NULL;
    retval = _pam_unix_approve_pass(pamh, ctrl, pass_old, pass_new);

    if (retval != PAM_SUCCESS && off(UNIX_NOT_SET_PASS, ctrl))
      pam_set_item(pamh, PAM_AUTHTOK, NULL);
  }

  if (retval != PAM_SUCCESS) {
    pam_syslog(pamh, LOG_NOTICE, "new password not acceptable");
    pass_new = NULL;
    return retval;
  }

  if (pass_old) {
    retval = _unix_verify_password(pamh, user, pass_old, ctrl);
    if (retval != PAM_SUCCESS) {
      pam_syslog(pamh, LOG_NOTICE, "user password changed by another process");
      return retval;
    }
  }

  retval = _unix_verify_shadow(pamh, user, ctrl);
  if (retval != PAM_SUCCESS) {
    pam_syslog(pamh, LOG_NOTICE, "user shadow entry expired");
    return retval;
  }

  retval = _pam_unix_approve_pass(pamh, ctrl, pass_old, pass_new);
  if (retval != PAM_SUCCESS) {
    pam_syslog(pamh, LOG_NOTICE, "new password not acceptable 2");
    pass_new = NULL;
    return retval;
  }

  char *tpass = create_password_hash(pamh, pass_new, prefix);
  if (!tpass) {
    pam_syslog(pamh, LOG_CRIT, "out of memory for password");
    pass_new = NULL;
    return PAM_BUF_ERR;
  }

  char *shadow_contents = NULL;

  struct passwd *pwd = getpwnam(user);
  if (!pwd) {
    retval = PAM_USER_UNKNOWN;
    goto out;
  }

  struct spwd *spwd = getspnam(user);
  if (!spwd) {
    retval = PAM_USER_UNKNOWN;
    goto out;
  }

  spwd->sp_pwdp = tpass;
  spwd->sp_lstchg = time(NULL) / (60 * 60 * 24);
  if (!hardened_shadow_asprintf_shadow(&shadow_contents, spwd)) {
    retval = PAM_BUF_ERR;
    goto out;
  }
  if (hardened_shadow_replace_user_file(user, pwd->pw_uid, shadow_contents, "shadow")) {
    pam_syslog(pamh, LOG_NOTICE, "password changed for %s", user);
    retval = PAM_SUCCESS;
  } else {
    pam_syslog(pamh, LOG_ERR, "hardened_shadow_replace_user_file failed");
    retval = PAM_SYSTEM_ERR;
  }

out:
  free(shadow_contents);
  _pam_delete(tpass);
  pass_old = pass_new = NULL;
  return retval;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t * pamh, int flags, int argc, const char **argv) {
  const char *prefix = NULL;
  unsigned int ctrl = _set_ctrl(pamh, flags, argc, argv, &prefix);
  if (!prefix) {
    pam_syslog(pamh, LOG_ERR, "required \"prefix\" parameter is not present");
    return PAM_SYSTEM_ERR;
  }

  const char *user;
  int retval = pam_get_user(pamh, &user, NULL);
  if (retval == PAM_SUCCESS) {
    if (on(UNIX_DEBUG, ctrl))
      pam_syslog(pamh, LOG_DEBUG, "username [%s] obtained", user);
  } else {
    if (on(UNIX_DEBUG, ctrl))
      pam_syslog(pamh, LOG_DEBUG, "password - could not identify user");
    return retval;
  }

  if (!getpwnam(user)) {
    pam_syslog(pamh, LOG_DEBUG, "user \"%s\" has corrupted passwd entry", user);
    return PAM_USER_UNKNOWN;
  }

  /*
   * This is not an AUTH module!
   */
  if (on(UNIX__NONULL, ctrl))
    set(UNIX__NULLOK, &ctrl);

  if (flags & PAM_PRELIM_CHECK)
    return prelim_check(pamh, ctrl, user);

  if (flags & PAM_UPDATE_AUTHTOK)
    return update_pam(pamh, ctrl, user, prefix);

  pam_syslog(pamh, LOG_ALERT, "password received unknown request");
  return PAM_ABORT;
}
