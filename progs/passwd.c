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
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include "hardened-shadow.h"

static void usage(void) {
  fputs("Usage: passwd [options] [LOGIN]\n"
        "\n"
        "Options:\n"
        "  -a, --all                     report password status on all accounts\n"
        "  -d, --delete                  delete the password for the named account\n"
        "  -e, --expire                  force expire the password for the named account\n"
        "  -h, --help                    display this help message and exit\n"
        "  -k, --keep-tokens             change password only if expired\n"
        "  -i, --inactive INACTIVE       set password inactive after expiration\n"
        "                                to INACTIVE\n"
        "  -l, --lock                    lock the password of the named account\n"
        "  -n, --mindays MIN_DAYS        set minimum number of days before password\n"
        "                                change to MIN_DAYS\n"
        "  -q, --quiet                   quiet mode\n"
        "  -S, --status                  report password status on the named account\n"
        "  -u, --unlock                  unlock the password of the named account\n"
        "  -w, --warndays WARN_DAYS      set expiration warning days to WARN_DAYS\n"
        "  -x, --maxdays MAX_DAYS        set maximum number of days before password\n"
        "                                change to MAX_DAYS\n"
        "\n", stderr);
  exit(EXIT_FAILURE);
}

#define FLAG_NOT_SET (-2)

static bool flag_all = false;
static bool flag_delete = false;
static bool flag_expire = false;
static bool flag_keep_tokens = false;
static intmax_t flag_inactive_days = FLAG_NOT_SET;
static bool flag_lock = false;
static intmax_t flag_mindays = FLAG_NOT_SET;
static bool flag_quiet = false;
static bool flag_status = false;
static bool flag_unlock = false;
static intmax_t flag_warndays = FLAG_NOT_SET;
static intmax_t flag_maxdays = FLAG_NOT_SET;

static bool has_nonstatus_flag = false;

static char *target_username = NULL;
static uid_t target_uid = -1;

static void parse_args(int argc, char **argv) {
  int option_index = 0;
  int c;
  static struct option long_options[] = {
    {"all", no_argument, NULL, 'a'},
    {"delete", no_argument, NULL, 'd'},
    {"expire", no_argument, NULL, 'e'},
    {"help", no_argument, NULL, 'h'},
    {"inactive", required_argument, NULL, 'i'},
    {"keep-tokens", no_argument, NULL, 'k'},
    {"lock", no_argument, NULL, 'l'},
    {"mindays", required_argument, NULL, 'n'},
    {"quiet", no_argument, NULL, 'q'},
    {"repository", required_argument, NULL, 'r'},
    {"status", no_argument, NULL, 'S'},
    {"unlock", no_argument, NULL, 'u'},
    {"warndays", required_argument, NULL, 'w'},
    {"maxdays", required_argument, NULL, 'x'},
    {NULL, 0, NULL, '\0'}
  };

  while ((c = getopt_long(argc, argv, "adei:kln:qr:Suw:x:",
                          long_options, &option_index)) != -1) {
    switch (c) {
      case 'a':
        flag_all = true;
        break;
      case 'd':
        flag_delete = true;
        has_nonstatus_flag = true;
        break;
      case 'e':
        flag_expire = true;
        has_nonstatus_flag = true;
        break;
      case 'i':
        if (!hardened_shadow_strtonum(optarg, -1, INTMAX_MAX,
                                      &flag_inactive_days)) {
          errx(EXIT_FAILURE, "invalid inactive days argument");
        }
        has_nonstatus_flag = true;
        break;
      case 'k':
        flag_keep_tokens = true;
        has_nonstatus_flag = true;
        break;
      case 'l':
        flag_lock = true;
        has_nonstatus_flag = true;
        break;
      case 'n':
        if (!hardened_shadow_strtonum(optarg, -1, INTMAX_MAX, &flag_mindays))
          errx(EXIT_FAILURE, "invalid minimum days argument");
        has_nonstatus_flag = true;
        break;
      case 'q':
        flag_quiet = true;
        break;
      case 'r':
        /* Ignored for compatibility with shadow-utils. */
        break;
      case 'S':
        flag_status = true;
        break;
      case 'u':
        flag_unlock = true;
        has_nonstatus_flag = true;
        break;
      case 'w':
        if (!hardened_shadow_strtonum(optarg, -1, INTMAX_MAX, &flag_warndays))
          errx(EXIT_FAILURE, "invalid warn days argument");
        has_nonstatus_flag = true;
        break;
      case 'x':
        if (!hardened_shadow_strtonum(optarg, -1, INTMAX_MAX, &flag_maxdays))
          errx(EXIT_FAILURE, "invalid max days argument");
        has_nonstatus_flag = true;
        break;
      default:
        usage();
    }
  }

  if (flag_all) {
    if (!flag_status || has_nonstatus_flag)
      usage();

    if (getuid() != 0)
      errx(EXIT_FAILURE, "Permission denied");
  }

  if (has_nonstatus_flag && optind >= argc)
    usage();

  if (optind + 1 < argc) {
    usage();
  } else if (optind < argc) {
    target_username = strdup(argv[optind]);
    if (!target_username)
      errx(EXIT_FAILURE, "memory allocation failure");
  } else {
    if (!hardened_shadow_get_current_username(&target_username))
      errx(EXIT_FAILURE, "Cannot determine your user name.");
  }

  struct passwd *pw = getpwnam(target_username);
  if (!pw)
    err(EXIT_FAILURE, "Cannot determine user name.");
  if (pw->pw_uid != getuid() && getuid() != 0) {
    errx(EXIT_FAILURE,
         "You may not view or modify password information for %s.",
         target_username);
  }
  target_uid = pw->pw_uid;
}

static void handle_print_status(void) {
  if (flag_all) {
    setpwent();
    struct passwd *pw;
    while ((pw = getpwent()) != NULL) {
      char *line;
      if (!hardened_shadow_asprintf_password_status(&line, pw->pw_name))
        errx(EXIT_FAILURE, "hardened_shadow_asprintf_password_status");
      fputs(line, stdout);
    }
    endpwent();
  } else {
    char *line;
    if (!hardened_shadow_asprintf_password_status(&line, target_username))
      errx(EXIT_FAILURE, "hardened_shadow_asprintf_password_status");
    fputs(line, stdout);
  }
}

static void handle_change_password(void) {
  const struct pam_conv pam_conversation = {
    misc_conv,
    NULL
  };
  pam_handle_t *pam_handle = NULL;
  int pam_rv = pam_start("passwd", target_username,
                         &pam_conversation, &pam_handle);
  if (pam_rv != PAM_SUCCESS)
    errx(EXIT_FAILURE, "pam_start() failed, error %d", pam_rv);

  int flags = 0;
  if (flag_quiet)
    flags |= PAM_SILENT;
  if (flag_keep_tokens)
    flags |= PAM_CHANGE_EXPIRED_AUTHTOK;

  pam_rv = pam_chauthtok(pam_handle, flags);
  if (pam_rv != PAM_SUCCESS) {
    warnx("%s", pam_strerror(pam_handle, pam_rv));
    pam_end(pam_handle, pam_rv);
    errx(EXIT_FAILURE, "password unchanged");
  }

  pam_end(pam_handle, PAM_SUCCESS);
  warnx("password updated successfully");
}

static bool update_expiry(void) {
  struct spwd *spwd = getspnam(target_username);
  if (!spwd) {
    warn("getspnam");
    return false;
  }

  // TODO(phajdan.jr): Take flag_lock, flag_unlock into account.
  // Relevant code how to handle them can be found in usermod.c.

  if (flag_maxdays != FLAG_NOT_SET)
    spwd->sp_max = flag_maxdays;
  if (flag_mindays != FLAG_NOT_SET)
    spwd->sp_min = flag_mindays;
  if (flag_warndays != FLAG_NOT_SET)
    spwd->sp_warn = flag_warndays;
  if (flag_inactive_days != FLAG_NOT_SET)
    spwd->sp_inact = flag_inactive_days;
  if (flag_expire)
    spwd->sp_lstchg = 0;

  char *shadow_contents = NULL;
  char *aging_contents = NULL;

  bool result = true;

  if (!hardened_shadow_asprintf_shadow(&shadow_contents, spwd)) {
    result = false;
    goto out;
  }
  if (!hardened_shadow_asprintf_aging(&aging_contents, spwd)) {
    result = false;
    goto out;
  }

  if (!hardened_shadow_replace_user_file(target_username, target_uid,
                                         shadow_contents, "shadow")) {
    result = false;
    goto out;
  }
  if (!hardened_shadow_replace_user_file(target_username, target_uid,
                                         aging_contents, "aging")) {
    result = false;
    goto out;
  }

out:
  free(shadow_contents);
  free(aging_contents);
  return result;
}

int main(int argc, char **argv) {
  hardened_shadow_openlog("passwd");

  parse_args(argc, argv);

  if (flag_delete ||
      flag_expire ||
      flag_inactive_days != FLAG_NOT_SET ||
      flag_lock ||
      flag_mindays != FLAG_NOT_SET ||
      flag_unlock ||
      flag_warndays != FLAG_NOT_SET ||
      flag_maxdays != FLAG_NOT_SET) {
    if (update_expiry())
      warnx("password expiry information changed.");
  } else if (flag_status) {
    handle_print_status();
  } else {
    handle_change_password();
  }

  hardened_shadow_closelog();

  free(target_username);

  return EXIT_SUCCESS;
}
