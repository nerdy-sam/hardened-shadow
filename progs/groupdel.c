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
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include "hardened-shadow.h"

static void usage(void) {
  fputs("Usage: groupdel group\n", stderr);
  exit(EXIT_FAILURE);
}

static const char *group_name = NULL;

int main(int argc, char **argv) {
  if (argc != 2)
    usage();
  group_name = argv[1];

  hardened_shadow_openlog("groupdel");

  if (lckpwdf() != 0)
    err(EXIT_FAILURE, "lckpwdf");

  struct group *grp = getgrnam(group_name);
  if (!grp)
    errx(EXIT_FAILURE, "group '%s' does not exist", group_name);
  gid_t gid = grp->gr_gid;

  /* Make sure we are not removing any user's primary group. */
  setpwent();
  struct passwd *pwd = NULL;
  while ((pwd = getpwent())) {
    if (pwd->pw_gid == gid) {
      errx(EXIT_FAILURE, "cannot remove the primary group of user '%s'",
           pwd->pw_name);
    }
  }
  endpwent();

  if (!hardened_shadow_replace_group(group_name, NULL))
    errx(EXIT_FAILURE, "Failed to update /etc/group.");

  hardened_shadow_syslog(LOG_INFO, "group '%s' removed", group_name);

  hardened_shadow_flush_nscd("group");

  if (ulckpwdf() != 0)
    warn("ulckpwdf");

  return EXIT_SUCCESS;
}
