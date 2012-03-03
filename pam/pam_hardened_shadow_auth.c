/*
 * Copyright Alexander O. Yuriev, 1996.  All rights reserved.
 * NIS+ support by Thorsten Kukuk <kukuk@weber.uni-paderborn.de>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "support.h"

#define _UNIX_AUTHTOK  "-UN*X-PASS"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags,int argc, const char **argv) {
  int ctrl = _set_ctrl(pamh, flags, argc, argv, NULL);

  const char *name = NULL;
  int retval = pam_get_user(pamh, &name, NULL);
  if (retval != PAM_SUCCESS) {
    if (retval == PAM_CONV_AGAIN)
      retval = PAM_INCOMPLETE;
    return retval;
  }

  if (on(UNIX__NULLOK, ctrl) && _unix_blankpasswd(pamh, name)) {
    name = NULL;
    retval = PAM_SUCCESS;
    return retval;
  }

  char *p;
  retval = _unix_read_password(pamh, ctrl, PAM_AUTHTOK, "Password: ", NULL, _UNIX_AUTHTOK, &p);
  if (retval != PAM_SUCCESS) {
    if (retval == PAM_CONV_AGAIN)
      retval = PAM_INCOMPLETE;
    else
      pam_syslog(pamh, LOG_CRIT, "auth could not identify password for [%s]", name);
    name = NULL;
    return retval;
  }

  retval = _unix_verify_password(pamh, name, p, ctrl);
  name = p = NULL;

  return retval;
}

PAM_EXTERN int pam_sm_setcred (pam_handle_t *pamh UNUSED, int flags UNUSED, int argc UNUSED, const char **argv UNUSED) {
  return PAM_SUCCESS;
}
