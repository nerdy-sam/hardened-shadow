/*
 * Copyright Elliot Lee, 1996.  All rights reserved.
 * Copyright Jan Rękorajski, 1999.  All rights reserved.
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

#include <inttypes.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>

#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "support.h"

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  unsigned int ctrl = _set_ctrl(pamh, flags, argc, argv, NULL);

  const char *uname = NULL;
  int retval = pam_get_item(pamh, PAM_USER, (const void **)&uname);
  if (retval != PAM_SUCCESS || !uname) {
    pam_syslog(pamh, LOG_ALERT, "could not identify user (from uid=%ju)", (uintmax_t)getuid());
    return PAM_USER_UNKNOWN;
  }

  struct passwd *pwent = NULL;
  struct spwd *spent = NULL;
  retval = get_account_info(pamh, uname, &pwent, &spent);
  if (retval != PAM_SUCCESS) {
    pam_syslog(pamh, LOG_ALERT, "could not identify user (from getpwnam(%s))", uname);
    return retval;
  }

  int daysleft;
  retval = check_shadow_expiry(pamh, spent, &daysleft);
  switch (retval) {
    case PAM_ACCT_EXPIRED:
      pam_syslog(pamh, LOG_NOTICE, "account %s has expired (account expired)", uname);
      _make_remark(pamh, ctrl, PAM_ERROR_MSG, "Your account has expired; please contact your system administrator");
      break;
    case PAM_NEW_AUTHTOK_REQD:
      if (daysleft == 0) {
        pam_syslog(pamh, LOG_NOTICE, "expired password for user %s (root enforced)", uname);
        _make_remark(pamh, ctrl, PAM_ERROR_MSG, "You are required to change your password immediately (root enforced)");
      } else {
        pam_syslog(pamh, LOG_DEBUG, "expired password for user %s (password aged)", uname);
        _make_remark(pamh, ctrl, PAM_ERROR_MSG, "You are required to change your password immediately (password aged)");
      }
      break;
    case PAM_AUTHTOK_EXPIRED:
      pam_syslog(pamh, LOG_NOTICE, "account %s has expired (failed to change password)", uname);
      _make_remark(pamh, ctrl, PAM_ERROR_MSG, "Your account has expired; please contact your system administrator");
      break;
    case PAM_AUTHTOK_ERR:
      retval = PAM_SUCCESS;
      /* fallthrough */
    case PAM_SUCCESS:
      if (daysleft >= 0) {
        char buf[256];
        pam_syslog(pamh, LOG_DEBUG, "password for user %s will expire in %d days", uname, daysleft);
        if (daysleft == 1)
          snprintf(buf, sizeof(buf), "Warning: your password will expire in %d day", daysleft);
        else
          snprintf(buf, sizeof(buf), "Warning: your password will expire in %d days", daysleft);
        _make_remark(pamh, ctrl, PAM_TEXT_INFO, buf);
      }
  }

  return retval;
}
