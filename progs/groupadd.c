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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>

#include "hardened-shadow.h"

static void usage (void) {
  fputs("Usage: groupadd [options] GROUP\n"
        "\n"
        "Options:\n"
        "  -f, --force                   exit successfully if the group already exists,\n"
        "                                and cancel -g if the GID is already used\n"
        "  -g, --gid GID                 use GID for the new group\n"
        "  -h, --help                    display this help message and exit\n"
        "  -o, --non-unique              allow to create groups with duplicate\n"
        "                                (non-unique) GID\n"
        "  -r, --system                  create a system account\n"
        "\n", stderr);
  exit(EXIT_FAILURE);
}

static bool flag_force = false;
static gid_t flag_gid = -1;
static bool flag_non_unique = false;
static bool flag_system = false;
static char *group_name = NULL;

static char *empty_list = NULL;

static void parse_args(int argc, char **argv) {
  static struct option long_options[] = {
    {"force", no_argument, NULL, 'f'},
    {"gid", required_argument, NULL, 'g'},
    {"help", no_argument, NULL, 'h'},
    {"non-unique", no_argument, NULL, 'o'},
    {"system", no_argument, NULL, 'r'},
    {NULL, 0, NULL, '\0'}
  };

  int c;
  while ((c = getopt_long (argc, argv, "fg:hor", long_options, NULL)) != -1) {
    switch (c) {
      case 'f':
        flag_force = true;
        break;
      case 'g': {
        intmax_t arg;
        if (!hardened_shadow_strtonum(optarg, 0, hardened_shadow_gid_max(), &arg))
          errx(EXIT_FAILURE, "invalid group ID '%s'", optarg);
        flag_gid = arg;
        break;
      }
      case 'h':
        usage();
        break;
      case 'o':
        flag_non_unique = true;
        break;
      case 'r':
        flag_system = true;
        break;
      default:
        usage();
    }
  }

  if (flag_non_unique && flag_gid == (gid_t)-1)
    usage();

  if (optind != argc - 1)
    usage();
  group_name = argv[optind];

  if (getgrnam(group_name)) {
    if (flag_force)
      exit(EXIT_SUCCESS);
    errx(EXIT_FAILURE, "group '%s' already exists", group_name);
  }

  if (flag_gid != (gid_t)-1 && getgrgid(flag_gid)) {
    if (flag_force)
      flag_gid = -1;
    else if (!flag_non_unique)
      errx(EXIT_FAILURE, "GID '%ju' already exists", (uintmax_t)flag_gid);
  }

  if (!hardened_shadow_is_valid_group_name(group_name))
    errx(EXIT_FAILURE, "'%s' is not a valid group name", group_name);
}

int main(int argc, char **argv) {
  hardened_shadow_openlog("groupadd");

  if (lckpwdf() != 0)
    err(EXIT_FAILURE, "lckpwdf");

  parse_args(argc, argv);

  if (flag_gid == (gid_t)-1) {
    const char *gid_key = (flag_system) ? "SYSTEM_GID_RANGE" : "USER_GID_RANGE";
    intmax_t gid_min, gid_max;
    if (!hardened_shadow_config_get_range(gid_key, &gid_min, &gid_max))
      errx(EXIT_FAILURE, "Failed to retrieve GID range.");
    if (!hardened_shadow_allocate_gid(gid_min, gid_max, &flag_gid))
      errx(EXIT_FAILURE, "Failed to allocate GID.");
  }

  struct group grp;
  memset(&grp, '\0', sizeof(grp));

  grp.gr_name = group_name;
  grp.gr_passwd = HARDENED_SHADOW_SHADOW_PASSWD;
  grp.gr_gid = flag_gid;
  grp.gr_mem = &empty_list;

  if (!hardened_shadow_replace_group(group_name, &grp))
    errx(EXIT_FAILURE, "Failed to update /etc/group.");

  hardened_shadow_syslog(LOG_INFO, "new group: name=%s, GID=%ju", group_name, (uintmax_t)flag_gid);

  hardened_shadow_flush_nscd("group");

  if (ulckpwdf() != 0)
    warn("ulckpwdf");

  return EXIT_SUCCESS;
}
