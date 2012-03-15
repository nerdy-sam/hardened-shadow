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
#include <getopt.h>
#include <limits.h>
#include <paths.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <utmp.h>

#include "hardened-shadow.h"

static intmax_t before_days = 0;
static intmax_t time_days = INTMAX_MAX;
static intmax_t uid_min = 0;
static intmax_t uid_max = INTMAX_MAX;

static void usage() {
  fputs("Usage: lastlog [options]\n"
        "\n"
        "Options:\n"
        "  -b, --before DAYS             print only lastlog records older than DAYS\n"
        "  -h, --help                    display this help message and exit\n"
        "  -t, --time DAYS               print only lastlog records more recent than DAYS\n"
        "  -u, --user LOGIN              print lastlog record of the specified LOGIN\n"
        "\n", stderr);
  exit(EXIT_FAILURE);
}

static void parse_args(int argc, char **argv) {
  static struct option const longopts[] = {
    {"help", no_argument, NULL, 'h'},
    {"time", required_argument, NULL, 't'},
    {"before", required_argument, NULL, 'b'},
    {"user", required_argument, NULL, 'u'},
    {NULL, 0, NULL, '\0'}
  };

  int c;
  struct passwd *pwent = NULL;
  while ((c = getopt_long(argc, argv, "ht:b:u:", longopts, NULL)) != -1) {
    switch (c) {
      case 'h':
        usage ();
        break;
      case 't':
        if (!hardened_shadow_strtonum(optarg, 0, INTMAX_MAX, &time_days))
          errx(EXIT_FAILURE, "hardened_shadow_strtonum failed");
        break;
      case 'b':
        if (!hardened_shadow_strtonum(optarg, 0, INTMAX_MAX, &before_days))
          errx(EXIT_FAILURE, "hardened_shadow_strtonum failed");
        break;
      case 'u':
        pwent = getpwnam (optarg);
        if (pwent) {
          uid_min = uid_max = pwent->pw_uid;
        } else {
          if (!hardened_shadow_getrange(optarg,
                                        0, INTMAX_MAX,
                                        &uid_min, &uid_max)) {
            errx(EXIT_FAILURE, "hardened_shadow_getrange failed");
          }
        }
        break;
      default:
        usage();
        break;
    }
  }
  if (argc > optind) {
    warnx("unexpected argument: %s", argv[optind]);
    usage();
  }
}

static bool lastlog_read(FILE *lastlog_file,
                         const struct stat *sb,
                         uid_t uid,
                         struct lastlog *entry) {
  memset(entry, 0, sizeof(*entry));

  if (!hardened_shadow_umul_ok(uid, sizeof(*entry), SIZE_MAX))
    return false;
  size_t offset = uid * sizeof(*entry);

  if (!hardened_shadow_usub_ok(sb->st_size, sizeof(*entry), SIZE_MAX))
    return false;
  size_t offset_max = sb->st_size - sizeof(*entry);

  if (offset <= offset_max) {
    if (!hardened_shadow_scast_ok(offset, OFF_MAX))
      return false;
    if (fseeko(lastlog_file, (off_t)offset, SEEK_SET) != 0)
      return false;
    if (fread(entry, sizeof(*entry), 1, lastlog_file) != 1)
      return false;
  }

  return true;
}

static bool asprintf_lastlog(char **result,
                             const char *username,
                             const struct lastlog *entry) {
  struct tm *tm = localtime(&entry->ll_time);
  if (!tm)
    return false;
  char ptime[80];
  if (entry->ll_time == 0)
    strncpy(ptime, "**Never logged in**", sizeof(ptime) - 1);
  else
    strftime(ptime, sizeof(ptime), "%a %b %e %H:%M:%S %z %Y", tm);

  if (asprintf(result,
               "%-16s %-8.8s %-16.16s %s\n",
               username,
               entry->ll_line,
               entry->ll_host,
               ptime) == -1) {
    return false;
  }

  return true;
}

int main(int argc, char **argv) {
  parse_args(argc, argv);

  FILE *lastlog_file = NULL;
  do {
    lastlog_file = fopen(_PATH_LASTLOG, "re");
  } while (!lastlog_file && errno == EINTR);
  if (!lastlog_file)
    err(EXIT_FAILURE, "fopen");

  struct stat sb;
  if (fstat(fileno(lastlog_file), &sb) != 0)
    err(EXIT_FAILURE, "fstat");

  time_t current_time = time(NULL);

  bool printed_header = false;
  struct passwd *pwent;
  setpwent();
  while ((pwent = getpwent())) {
    if (pwent->pw_uid < uid_min || pwent->pw_uid > uid_max)
      continue;

    struct lastlog lastlog_entry;
    if (!lastlog_read(lastlog_file, &sb, pwent->pw_uid, &lastlog_entry))
      errx(EXIT_FAILURE, "lastlog_read failed");

    if (time_days != INTMAX_MAX &&
        current_time - lastlog_entry.ll_time > time_days * 3600 * 24)
      continue;
    if (before_days != 0 &&
        current_time - lastlog_entry.ll_time < before_days * 3600 * 24)
      continue;

    char *printed_entry;
    if (!asprintf_lastlog(&printed_entry, pwent->pw_name, &lastlog_entry))
      errx(EXIT_FAILURE, "asprintf_lastlog failed");
    if (!printed_header) {
      puts("Username         Port     From             Latest");
      printed_header = true;
    }
    printf("%s", printed_entry);
  }
  endpwent();

  fclose(lastlog_file);

  return EXIT_SUCCESS;
}
