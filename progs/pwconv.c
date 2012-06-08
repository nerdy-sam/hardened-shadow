/*
 * Copyright (c) 2012, Paweł Hajdan, Jr.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <err.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "hardened-shadow.h"

static void usage(void) {
  fputs("Usage: pwconv\n", stderr);
  exit(EXIT_FAILURE);
}

static void delete_hardened_shadow(void) {
  hardened_shadow_remove_dir_contents("/etc/hardened-shadow");
  rmdir("/etc/hardened-shadow");
}

int main(int argc, char **argv UNUSED) {
  if (lckpwdf() != 0)
    err(EXIT_FAILURE, "lckpwdf");

  if (argc != 1)
    usage();

  gid_t hardened_shadow_gid;
  if (!hardened_shadow_get_hardened_shadow_gid(&hardened_shadow_gid))
    errx(EXIT_FAILURE, "failed to retrieve hardened-shadow GID");

  intmax_t system_min, system_max;
  if (!hardened_shadow_config_get_range("SYSTEM_UID_RANGE",
                                        &system_min, &system_max))
    errx(EXIT_FAILURE, "failed to retrieve SYSTEM_UID_RANGE");

  if (mkdir("/etc/hardened-shadow", 0750) != 0)
    err(EXIT_FAILURE, "mkdir");
  if (chown("/etc/hardened-shadow", 0, hardened_shadow_gid) != 0) {
    rmdir("/etc/hardened-shadow");
    err(EXIT_FAILURE, "chown");
  }

  struct passwd *tmp_pwd = NULL;
  setpwent();
  while ((tmp_pwd = getpwent())) {
    struct passwd pwd;
    if (!hardened_shadow_dup_passwd(tmp_pwd, &pwd)) {
      delete_hardened_shadow();
      errx(EXIT_FAILURE, "memory allocation failure");
    }

    /* Note: it's not fatal if the user doesn't have shadow entry. */
    struct spwd *spwd = getspnam(pwd.pw_name);

    bool system = pwd.pw_uid >= system_min && pwd.pw_uid <= system_max;
    if (!hardened_shadow_create_shadow_entry(&pwd, spwd, system, -1, -1)) {
      delete_hardened_shadow();
      errx(EXIT_FAILURE, "adding shadow entry for %s failed", pwd.pw_name);
    }

    hardened_shadow_free_passwd_contents(&pwd);
  }
  endpwent();

  if (!hardened_shadow_update_passwd_shell_proxy())
    errx(EXIT_FAILURE, "hardened_shadow_update_passwd_shell_proxy failed");

  if (ulckpwdf() != 0)
    warn("ulckpwdf");

  return EXIT_SUCCESS;
}
