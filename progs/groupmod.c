/*
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

#include <err.h>
#include <getopt.h>
#include <grp.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "hardened-shadow.h"

static void usage (void) {
  fputs("Usage: groupmod [options] GROUP\n"
        "\n"
        "Options:\n", stderr);
  fputs("  -g, --gid GID                 change the group ID to GID\n", stderr);
  fputs("  -h, --help                    display this help message and exit\n", stderr);
  fputs("  -n, --new-name NEW_GROUP      change the name to NEW_GROUP\n", stderr);
  fputs("  -o, --non-unique              allow to use a duplicate (non-unique) GID\n", stderr);
  fputs("\n", stderr);
  exit(EXIT_FAILURE);
}

static gid_t flag_gid = -1;
static char *flag_new_name = NULL;
static bool flag_non_unique = false;
static const char *group_name = NULL;

static void parse_args(int argc, char **argv) {
  static struct option long_options[] = {
    {"gid", required_argument, NULL, 'g'},
    {"help", no_argument, NULL, 'h'},
    {"new-name", required_argument, NULL, 'n'},
    {"non-unique", no_argument, NULL, 'o'},
    {NULL, 0, NULL, '\0'}
  };
  int c;
  while ((c = getopt_long (argc, argv, "g:hn:o", long_options, NULL)) != -1) {
    switch (c) {
      case 'g': {
        intmax_t arg;
        if (!hardened_shadow_strtonum(optarg, 0, hardened_shadow_gid_max(), &arg))
          errx(EXIT_FAILURE, "invalid group ID '%s'", optarg);
        flag_gid = arg;
        break;
      }
      case 'n':
        flag_new_name = optarg;
        break;
      case 'o':
        flag_non_unique = true;
        break;
      default:
        usage();
    }
  }

  if (flag_non_unique && flag_gid != (gid_t)-1)
    usage();

  if (optind != (argc - 1))
    usage();

  group_name = argv[argc - 1];
}

int main(int argc, char **argv) {
  hardened_shadow_openlog("groupmod");

  if (lckpwdf() != 0)
    err(EXIT_FAILURE, "lckpwdf");

  parse_args(argc, argv);

  char *buffer = NULL;
  long buffer_size = sysconf(_SC_GETGR_R_SIZE_MAX);
  if (buffer_size < 0)
    err(EXIT_FAILURE, "sysconf");

  buffer = malloc(buffer_size);
  if (!buffer)
    err(EXIT_FAILURE, "malloc");

  struct group grp;
  struct group *grp_result = NULL;
  getgrnam_r(group_name, &grp, buffer, buffer_size, &grp_result);
  if (!grp_result)
    err(EXIT_FAILURE, "getgrnam_r");

  gid_t original_gid = grp.gr_gid;

  if (flag_gid != (gid_t)-1) {
    if (flag_gid == grp.gr_gid)
      flag_gid = -1;
    else if (getgrgid(flag_gid) && !flag_non_unique)
      errx(EXIT_FAILURE, "GID '%ju' already exists", (uintmax_t)flag_gid);
  }

  if (flag_new_name) {
    if (strcmp(flag_new_name, group_name) == 0)
      flag_new_name = NULL;
    else if (!hardened_shadow_is_valid_group_name(flag_new_name))
      errx(EXIT_FAILURE, "invalid group name '%s'", flag_new_name);
    else if (getgrnam(flag_new_name))
      errx(EXIT_FAILURE, "group '%s' already exists", flag_new_name);
  }

  if (flag_gid == (gid_t)-1 && !flag_new_name)
    exit(EXIT_SUCCESS);

  if (flag_new_name)
    grp.gr_name = flag_new_name;
  if (flag_gid != (gid_t)-1)
    grp.gr_gid = flag_gid;

  if (!hardened_shadow_replace_group(group_name, &grp))
    errx(EXIT_FAILURE, "Failed to update /etc/group.");
  if (flag_gid != (gid_t)-1 && flag_new_name)
    hardened_shadow_syslog(LOG_INFO, "group changed in /etc/group (group %s/%ju), new name: %s, new gid: %ju", group_name, (uintmax_t)original_gid, flag_new_name, (uintmax_t)flag_gid);
  else if (flag_gid != (gid_t)-1)
    hardened_shadow_syslog(LOG_INFO, "group changed in /etc/group (group %s/%ju), new gid: %ju", group_name, (uintmax_t)original_gid, (uintmax_t)flag_gid);
  else if (flag_new_name)
    hardened_shadow_syslog(LOG_INFO, "group changed in /etc/group (group %s/%ju), new name: %s", group_name, (uintmax_t)original_gid, flag_new_name);

  if (flag_gid != (gid_t)-1) {
    if (!hardened_shadow_update_passwd_change_gid(original_gid, flag_gid)) {
      hardened_shadow_syslog(LOG_WARNING, "failed to update /etc/passwd when changing group %s/%ju gid to %ju", group_name, (uintmax_t)original_gid, (uintmax_t)flag_gid);
      errx(EXIT_FAILURE, "Failed to update /etc/passwd.");
    }
    hardened_shadow_syslog(LOG_INFO, "group changed in /etc/passwd (group %s/%ju), new gid: %ju", group_name, (uintmax_t)original_gid, (uintmax_t)flag_gid);
  }

  hardened_shadow_flush_nscd("group");

  if (ulckpwdf() != 0)
    warn("ulckpwdf");

  free(buffer);

  return EXIT_SUCCESS;
}
