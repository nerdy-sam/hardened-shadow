/* *******************************************************************
 * Copyright (c) Jan Rękorajski 1999.
 * Copyright (c) Andrew G. Morgan 1996-8.
 * Copyright (c) Alex O. Yuriev, 1996.
 * Copyright (c) Cristian Gafton 1996.
 * Copyright (c) Red Hat, Inc. 1996, 2007, 2008.
 * Copyright (c) Paweł Hajdan, Jr. 2012
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
#include "support.h"
#include "hardened-shadow.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <pwd.h>
#include <shadow.h>
#include <time.h>
#include <limits.h>
#include <utmp.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/resource.h>

#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

int _make_remark(pam_handle_t *pamh, unsigned int ctrl, int type, const char *text) {
  if (on(UNIX__QUIET, ctrl))
    return PAM_SUCCESS;
  return pam_prompt(pamh, type, NULL, "%s", text);
}

unsigned int _set_ctrl(pam_handle_t *pamh, int flags, int argc, const char **argv, const char **prefix) {
  unsigned int ctrl = 0;

  /* Set default options. */
  set(UNIX__NONULL, &ctrl);

  /* Set flags not based on module arguments. */
  if (getuid() == 0 && !(flags & PAM_CHANGE_EXPIRED_AUTHTOK))
    set(UNIX__IAMROOT, &ctrl);
  if (flags & PAM_SILENT)
    set(UNIX__QUIET, &ctrl);

  for (; argc-- > 0; ++argv) {
    size_t j;

    for (j = 0; j < HARDENED_SHADOW_ARRAYSIZE(unix_args); ++j) {
      if (unix_args[j].token
          && hardened_shadow_starts_with(*argv, unix_args[j].token)) {
        break;
      }
    }

    if (j < HARDENED_SHADOW_ARRAYSIZE(unix_args)) {
      ctrl &= unix_args[j].mask;	/* for turning things off */
      ctrl |= unix_args[j].flag;	/* for turning things on  */
    } else if (hardened_shadow_starts_with(*argv, "prefix=")) {
      if (prefix)
        *prefix = *argv + strlen("prefix=");
    } else {
      pam_syslog(pamh, LOG_ERR, "unrecognized option [%s]", *argv);
    }
  }

  if (flags & PAM_DISALLOW_NULL_AUTHTOK)
    set(UNIX__NONULL, &ctrl);

  /* auditing is a more sensitive version of debug */
  if (on(UNIX_AUDIT, ctrl))
    set(UNIX_DEBUG, &ctrl);

  return ctrl;
}

static void _cleanup(pam_handle_t *pamh UNUSED, void *x, int error_status UNUSED) {
  _pam_delete(x);
}

static int get_pwd_hash(pam_handle_t *pamh, const char *name, char **hash) {
  struct spwd *spwdent = pam_modutil_getspnam(pamh, name);
  if (!spwdent || !spwdent->sp_pwdp)
    return PAM_AUTHINFO_UNAVAIL;

  *hash = strdup(spwdent->sp_pwdp);
  return (*hash) ? PAM_SUCCESS : PAM_BUF_ERR;
}

int _unix_blankpasswd (pam_handle_t *pamh, const char *name) {
  int retval;

  char *salt = NULL;
  get_pwd_hash(pamh, name, &salt);
  if (salt) {
    retval = (*salt == '\0') ? 1 : 0;
    _pam_delete(salt);
  } else {
    retval = 0;
  }

  return retval;
}

static int verify_pwd_hash(const char *p, char *hash, unsigned int ctrl) {
  if (*hash == '\0') {
    if (on(UNIX__NONULL, ctrl))
      return PAM_AUTH_ERR;

    return PAM_SUCCESS;
  }

  if (!p || *hash == '*' || *hash == '!')
    return PAM_AUTH_ERR;

  char *pp = crypt(p, hash);
  if (pp && strcmp(pp, hash) == 0)
    return PAM_SUCCESS;

  return PAM_AUTH_ERR;
}

int _unix_verify_password(pam_handle_t * pamh, const char *name, const char *p, unsigned int ctrl) {
  if (off(UNIX_NODELAY, ctrl))
    pam_fail_delay(pamh, 2000000);

  char *salt = NULL;
  int retval = get_pwd_hash(pamh, name, &salt);
  if (retval != PAM_SUCCESS) {
    p = NULL;
    if (on(UNIX_AUDIT, ctrl)) {
      /* This might be a typo and the user has given a password
         instead of a username. Careful with this. */
      pam_syslog(pamh, LOG_WARNING, "check pass; user (%s) unknown", name);
    } else {
      name = NULL;
      if (on(UNIX_DEBUG, ctrl)) {
        pam_syslog(pamh, LOG_WARNING, "check pass; user unknown");
      } else {
        /* Don't log failure as another PAM module can succeed. */
        goto cleanup;
      }
    }
  } else {
    retval = verify_pwd_hash(p, salt, ctrl);
  }

  if (retval != PAM_SUCCESS) {
    const char *login_name = pam_modutil_getlogin(pamh);
    if (!login_name)
      login_name = "";

    const void *service = NULL;
    const void *ruser = NULL;
    const void *rhost = NULL;
    const void *tty = NULL;
    pam_get_item(pamh, PAM_SERVICE, &service);
    pam_get_item(pamh, PAM_RUSER, &ruser);
    pam_get_item(pamh, PAM_RHOST, &rhost);
    pam_get_item(pamh, PAM_TTY, &tty);

    pam_syslog(pamh, LOG_NOTICE,
               "authentication failure; "
               "logname=%s uid=%d euid=%d "
               "tty=%s ruser=%s rhost=%s "
               "%s%s",
               login_name, getuid(), geteuid(),
               tty ? (const char *)tty : "",
               ruser ? (const char *)ruser : "",
               rhost ? (const char *)rhost : "",
               (name && name[0] != '\0') ? " user=" : "",
               name);
  }

cleanup:
  if (salt)
    _pam_delete(salt);

  return retval;
}

int _unix_read_password(pam_handle_t *pamh, unsigned int ctrl, int authtok_flag, const char *prompt1, const char *prompt2, const char *data_name, char **pass) {
  int retval = PAM_SUCCESS;
  char *token = *pass = NULL;

  if (on(UNIX_TRY_FIRST_PASS, ctrl) || on(UNIX_USE_FIRST_PASS, ctrl)) {
    const void *pass_item = NULL;
    retval = pam_get_item(pamh, authtok_flag, &pass_item);
    if (retval != PAM_SUCCESS) {
      /* very strange. */
      pam_syslog(pamh, LOG_ALERT, "pam_get_item returned error to unix-read-password");
      return retval;
    } else if (pass_item) {	/* we have a password! */
      *pass = strdup(pass_item);
      return (*pass) ? PAM_SUCCESS : PAM_BUF_ERR;
    } else if (on(UNIX_USE_AUTHTOK, ctrl) && authtok_flag == PAM_AUTHTOK) {
      return PAM_AUTHTOK_ERR;
    } else if (on(UNIX_USE_FIRST_PASS, ctrl)) {
      return PAM_AUTHTOK_RECOVERY_ERR;	  /* didn't work */
    }
  }

  {
    int replies = 1;
    char *resp[2] = { NULL, NULL };

    if (retval == PAM_SUCCESS) {
      retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &resp[0], "%s", prompt1);

      if (retval == PAM_SUCCESS && prompt2 != NULL) {
        retval = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &resp[1], "%s", prompt2);
        ++replies;
      }
    }

    if (resp[0] != NULL && resp[replies - 1] != NULL) {
      if (retval == PAM_SUCCESS) {
        token = resp[0];
        if (token != NULL) {
          if (replies == 2 && strcmp(token, resp[replies - 1])) {
            retval = PAM_AUTHTOK_RECOVERY_ERR;
            _make_remark(pamh, ctrl, PAM_ERROR_MSG, "Sorry, passwords do not match");
          }
        } else {
          pam_syslog(pamh, LOG_NOTICE, "could not recover authentication token");
        }
      }
    } else {
      retval = (retval == PAM_SUCCESS) ? PAM_AUTHTOK_RECOVERY_ERR : retval;
    }

    resp[0] = NULL;
    if (replies > 1)
      _pam_delete(resp[1]);
  }

  if (retval != PAM_SUCCESS) {
    _pam_delete(token);

    if (on(UNIX_DEBUG, ctrl))
      pam_syslog(pamh, LOG_DEBUG, "unable to obtain a password");
    return retval;
  }
  /* 'token' is the entered password */

  if (off(UNIX_NOT_SET_PASS, ctrl)) {
    retval = pam_set_item(pamh, authtok_flag, token);
    _pam_delete(token);
    const void *pass_item = NULL;
    if (retval != PAM_SUCCESS || (retval = pam_get_item(pamh, authtok_flag, &pass_item)) != PAM_SUCCESS) {
      *pass = NULL;
      pam_syslog(pamh, LOG_CRIT, "error manipulating password");
      return retval;
    }

    *pass = strdup(pass_item);
    if (!*pass)
      return PAM_BUF_ERR;
  } else {
    /*
     * then store it as data specific to this module. pam_end()
     * will arrange to clean it up.
     */
    retval = pam_set_data(pamh, data_name, token, _cleanup);
    if (retval != PAM_SUCCESS) {
      pam_syslog(pamh, LOG_CRIT, "error manipulating password data [%s]", pam_strerror(pamh, retval));
      _pam_delete(token);
      return retval;
    }
    *pass = token;
    token = NULL;	/* break link to password */
  }

  return PAM_SUCCESS;
}

int get_account_info(pam_handle_t *pamh, const char *name, struct passwd **pwd, struct spwd **spwdent) {
  *pwd = pam_modutil_getpwnam(pamh, name);
  *spwdent = NULL;

  if (!*pwd)
    return PAM_USER_UNKNOWN;

  *spwdent = pam_modutil_getspnam(pamh, name);
  if (!*spwdent || !(*spwdent)->sp_pwdp)
    return PAM_AUTHINFO_UNAVAIL;

  return PAM_SUCCESS;
}

int check_shadow_expiry(pam_handle_t *pamh, struct spwd *spent, int *daysleft) {
  *daysleft = -1;
  long int curdays = (long int)(time(NULL) / (60 * 60 * 24));
  if ((curdays >= spent->sp_expire) && (spent->sp_expire != -1))
    return PAM_ACCT_EXPIRED;
  if (spent->sp_lstchg == 0) {
    *daysleft = 0;
    return PAM_NEW_AUTHTOK_REQD;
  }
  if (curdays < spent->sp_lstchg) {
    pam_syslog(pamh, LOG_DEBUG, "account %s has password changed in future", spent->sp_namp);
    return PAM_SUCCESS;
  }
  if ((curdays - spent->sp_lstchg > spent->sp_max)
      && (curdays - spent->sp_lstchg > spent->sp_inact)
      && (curdays - spent->sp_lstchg > spent->sp_max + spent->sp_inact)
      && (spent->sp_max != -1) && (spent->sp_inact != -1)) {
    *daysleft = (int)((spent->sp_lstchg + spent->sp_max) - curdays);
    return PAM_AUTHTOK_EXPIRED;
  }
  if ((curdays - spent->sp_lstchg > spent->sp_max) && (spent->sp_max != -1))
    return PAM_NEW_AUTHTOK_REQD;
  if ((curdays - spent->sp_lstchg > spent->sp_max - spent->sp_warn)
      && (spent->sp_max != -1) && (spent->sp_warn != -1)) {
    *daysleft = (int)((spent->sp_lstchg + spent->sp_max) - curdays);
  }
  if ((curdays - spent->sp_lstchg < spent->sp_min) && (spent->sp_min != -1)) {
    /*
     * The last password change was too recent. This error will be ignored
     * if no password change is attempted.
     */
    return PAM_AUTHTOK_ERR;
  }
  return PAM_SUCCESS;
}
