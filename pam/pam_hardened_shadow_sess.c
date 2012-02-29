/*
 * Copyright Alexander O. Yuriev, 1996.  All rights reserved.
 * Copyright Jan Rękorajski, 1999.  All rights reserved.
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

#include <inttypes.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>

#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

PAM_EXTERN int pam_sm_open_session(pam_handle_t * pamh, UNUSED int flags,
				   UNUSED int argc, UNUSED const char **argv) {
  char *user_name = NULL;
  int retval = pam_get_item(pamh, PAM_USER, (void *) &user_name);
  if (retval != PAM_SUCCESS || !user_name || *user_name == '\0') {
    pam_syslog(pamh, LOG_CRIT, "open_session - error recovering username");
    return PAM_SESSION_ERR;
  }
  const char *login_name = pam_modutil_getlogin(pamh);
  if (login_name == NULL)
    login_name = "";
  pam_syslog(pamh, LOG_INFO, "session opened for user %s by %s(uid=%ju)",
             user_name, login_name, (uintmax_t)getuid());

  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t * pamh, UNUSED int flags,
				    UNUSED int argc, UNUSED const char **argv) {
  char *user_name = NULL;
  int retval = pam_get_item(pamh, PAM_USER, (void *) &user_name);
  if (retval != PAM_SUCCESS || !user_name || *user_name == '\0') {
    pam_syslog(pamh, LOG_CRIT, "close_session - error recovering username");
    return PAM_SESSION_ERR;
  }
  pam_syslog(pamh, LOG_INFO, "session closed for user %s", user_name);

  return PAM_SUCCESS;
}
