/*
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
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <shadow.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "hardened-shadow.h"

static void usage(void) {
  fputs("Usage: chage [options] [LOGIN]\n"
        "\n"
        "Options:\n"
        "  -d, --lastday LAST_DAY        set date of last password change to LAST_DAY\n"
        "  -E, --expiredate EXPIRE_DATE  set account expiration date to EXPIRE_DATE\n"
        "  -h, --help                    display this help message and exit\n"
        "  -I, --inactive INACTIVE       set password inactive after expiration\n"
        "                                to INACTIVE\n"
        "  -l, --list                    show account aging information\n"
        "  -m, --mindays MIN_DAYS        set minimum number of days before password\n"
        "                                change to MIN_DAYS\n"
        "  -M, --maxdays MAX_DAYS        set maximim number of days before password\n"
        "                                change to MAX_DAYS\n"
        "  -W, --warndays WARN_DAYS      set expiration warning days to WARN_DAYS\n"
        "\n", stderr);
  exit(EXIT_FAILURE);
}

#define FLAG_NOT_SET (-2)

static intmax_t flag_lastday = FLAG_NOT_SET;
static intmax_t flag_expiredate = FLAG_NOT_SET;
static intmax_t flag_inactive = FLAG_NOT_SET;
static bool flag_list = false;
static intmax_t flag_mindays = FLAG_NOT_SET;
static intmax_t flag_maxdays = FLAG_NOT_SET;
static intmax_t flag_warndays = FLAG_NOT_SET;

static const char *user_name = NULL;
static uid_t user_uid;

static void parse_args(int argc, char **argv) {
  static struct option long_options[] = {
    {"lastday", required_argument, NULL, 'd'},
    {"expiredate", required_argument, NULL, 'E'},
    {"help", no_argument, NULL, 'h'},
    {"inactive", required_argument, NULL, 'I'},
    {"list", no_argument, NULL, 'l'},
    {"mindays", required_argument, NULL, 'm'},
    {"maxdays", required_argument, NULL, 'M'},
    {"warndays", required_argument, NULL, 'W'},
    {NULL, 0, NULL, '\0'}
  };

  int c;
  while ((c = getopt_long(
             argc, argv, "d:E:hI:lm:M:W:", long_options, NULL)) != -1) {
    switch (c) {
      case 'd':
        if (!hardened_shadow_getday(optarg, &flag_lastday))
          errx(EXIT_FAILURE, "invalid date '%s'", optarg);
        break;
      case 'E':
        if (!hardened_shadow_getday(optarg, &flag_expiredate))
          errx(EXIT_FAILURE, "invalid date '%s'", optarg);
        break;
      case 'h':
        usage();
        break;
      case 'I':
        if (!hardened_shadow_strtonum(optarg, -1, INTMAX_MAX, &flag_inactive))
          errx(EXIT_FAILURE, "invalid numeric argument '%s'", optarg);
        break;
      case 'l':
        flag_list = true;
        break;
      case 'm':
        if (!hardened_shadow_strtonum(optarg, -1, INTMAX_MAX, &flag_mindays))
          errx(EXIT_FAILURE, "invalid numeric argument '%s'", optarg);
        break;
      case 'M':
        if (!hardened_shadow_strtonum(optarg, -1, INTMAX_MAX, &flag_maxdays))
          errx(EXIT_FAILURE, "invalid numeric argument '%s'", optarg);
        break;
      case 'W':
        if (!hardened_shadow_strtonum(optarg, -1, INTMAX_MAX, &flag_warndays))
          errx(EXIT_FAILURE, "invalid numeric argument '%s'", optarg);
        break;
      default:
        usage();
    }
  }

  if (argc != optind + 1)
    usage();
  user_name = argv[optind];

  struct passwd *pwd = getpwnam(user_name);
  if (!pwd)
    errx(EXIT_FAILURE, "unknown user '%s'", user_name);
  user_uid = pwd->pw_uid;

  if (getuid() != 0) {
    if (pwd->pw_uid != getuid())
      errx(EXIT_FAILURE, "permission denied");

    if (!flag_list)
      errx(EXIT_FAILURE, "permission denied");
  }

  if (flag_list &&
      (flag_lastday != FLAG_NOT_SET ||
       flag_expiredate != FLAG_NOT_SET ||
       flag_inactive != FLAG_NOT_SET ||
       flag_mindays != FLAG_NOT_SET ||
       flag_maxdays != FLAG_NOT_SET ||
       flag_warndays != FLAG_NOT_SET)) {
    errx(EXIT_FAILURE, "do not include '-l' with other flags");
  }
}

static void print_date(time_t date) {
  char *date_str = NULL;
  if (hardened_shadow_asprintf_date(&date_str, date)) {
    puts(date_str);
    free(date_str);
  } else {
    printf("time_t: %lu\n", date);
  }
}

static bool handle_list(const struct spwd *spw) {
  fputs("Last password change\t\t\t\t\t: ", stdout);
  if (spw->sp_lstchg < 0)
    puts("never");
  else if (spw->sp_lstchg == 0)
    puts("password must be changed");
  else
    print_date(spw->sp_lstchg * 60 * 60 * 24);

  fputs("Password expires\t\t\t\t\t: ", stdout);
  if (spw->sp_lstchg == 0) {
    puts("password must be changed");
  } else if (spw->sp_lstchg < 0 ||
             spw->sp_max >= 10000 ||
             spw->sp_max < 0) {
    puts("never");
  } else {
    print_date((spw->sp_lstchg + spw->sp_max) * 60 * 60 * 24);
  }

  fputs("Password inactive\t\t\t\t\t: ", stdout);
  if (spw->sp_lstchg == 0) {
    puts("password must be changed");
  } else if (spw->sp_lstchg < 0 ||
             spw->sp_inact < 0 ||
             spw->sp_max >= 10000 ||
             spw->sp_max < 0) {
    puts("never");
  } else {
    print_date((spw->sp_lstchg + spw->sp_max + spw->sp_inact) * 60 * 60 * 24);
  }

  fputs("Account expires\t\t\t\t\t\t: ", stdout);
  if (spw->sp_expire < 0)
    puts("never");
  else
    print_date(spw->sp_expire * 60 * 60 * 24);

  printf("Minimum number of days between password change\t\t: %ld\n",
         spw->sp_min);
  printf("Maximum number of days between password change\t\t: %ld\n",
         spw->sp_max);
  printf("Number of days of warning before password expires\t: %ld\n",
         spw->sp_warn);

  return true;
}

static bool update_shadow(struct spwd *spw) {
  if (flag_lastday != FLAG_NOT_SET)
    spw->sp_lstchg = flag_lastday;
  if (flag_expiredate != FLAG_NOT_SET)
    spw->sp_expire = flag_expiredate;
  if (flag_inactive != FLAG_NOT_SET)
    spw->sp_inact = flag_inactive;
  if (flag_mindays != FLAG_NOT_SET)
    spw->sp_min = flag_mindays;
  if (flag_maxdays != FLAG_NOT_SET)
    spw->sp_max = flag_maxdays;
  if (flag_warndays != FLAG_NOT_SET)
    spw->sp_warn = flag_warndays;

  char *shadow_contents = NULL;
  char *aging_contents = NULL;

  bool result = true;

  if (!hardened_shadow_asprintf_shadow(&shadow_contents, spw)) {
    result = false;
    goto out;
  }

  if (!hardened_shadow_asprintf_aging(&aging_contents, spw)) {
    result = false;
    goto out;
  }

  if (!hardened_shadow_replace_user_file(user_name, user_uid,
                                         shadow_contents, "shadow")) {
    result = false;
    goto out;
  }

  if (!hardened_shadow_replace_user_file(user_name, user_uid,
                                         aging_contents, "aging")) {
    result = false;
    goto out;
  }

out:
  free(shadow_contents);
  free(aging_contents);
  return result;
}

static bool prompt_integer(const char *prompt,
                           intmax_t default_value,
                           intmax_t minvalue,
                           intmax_t maxvalue,
                           intmax_t *prompt_result) {
  char *default_value_str = NULL;
  char *prompt_result_str = NULL;

  bool result = true;

  if (asprintf(&default_value_str, "%jd", default_value) < 0) {
    warn("asprintf");
    result = false;
    goto out;
  }

  if (!hardened_shadow_interactive_prompt(prompt,
                                          default_value_str,
                                          &prompt_result_str)) {
    warnx("Failed to get the response");
    result = false;
    goto out;
  }

  if (!hardened_shadow_strtonum(prompt_result_str,
                                minvalue,
                                maxvalue,
                                prompt_result)) {
    warnx("'%s' is not a valid integer from range (%jd) - (%jd)",
          prompt_result_str,
          minvalue,
          maxvalue);
    result = false;
    goto out;
  }

out:
  free(default_value_str);
  free(prompt_result_str);
  return result;
}

static bool prompt_date(const char *prompt,
                        intmax_t default_value,
                        intmax_t *prompt_result) {
  char *default_value_str = NULL;
  char *prompt_result_str = NULL;

  bool result = true;

  if (hardened_shadow_asprintf_date(&default_value_str,
                                    default_value * 60 * 60 * 24) < 0) {
    warnx("hardened_shadow_asprintf_date failed");
    result = false;
    goto out;
  }

  if (!hardened_shadow_interactive_prompt(prompt,
                                          default_value_str,
                                          &prompt_result_str)) {
    warnx("Failed to get the response");
    result = false;
    goto out;
  }

  if (!hardened_shadow_getday(prompt_result_str, prompt_result) &&
      !hardened_shadow_strtonum(prompt_result_str, -1, -1, prompt_result)) {
    warnx("'%s' is not a valid date", prompt_result_str);
    result = false;
    goto out;
  }

out:
  free(default_value_str);
  free(prompt_result_str);
  return result;
}

static bool interactive_prompt(const struct spwd *spw) {
  printf("Changing the aging information for %s\n", user_name);
  puts("Enter the new value, or press ENTER for the default\n");

  if (!prompt_integer("Minimum Password Age", spw->sp_min,
                      -1, LONG_MAX, &flag_mindays)) {
    return false;
  }

  if (!prompt_integer("Maximum Password Age", spw->sp_max,
                      -1, LONG_MAX, &flag_maxdays)) {
    return false;
  }

  if (!prompt_date("Last Password Change (YYYY-MM-DD)", spw->sp_lstchg,
                   &flag_lastday)) {
    return false;
  }

  if (!prompt_integer("Password Expiration Warning", spw->sp_warn,
                      -1, LONG_MAX, &flag_warndays)) {
    return false;
  }

  if (!prompt_integer("Password Inactive", spw->sp_inact,
                      -1, LONG_MAX, &flag_inactive)) {
    return false;
  }

  if (!prompt_date("Account Expiration Date (YYYY-MM-DD)",
                   spw->sp_expire, &flag_expiredate)) {
    return false;
  }

  return true;
}

int main(int argc, char **argv) {
  parse_args(argc, argv);

  struct spwd *spw = getspnam(user_name);
  if (!spw)
    errx(EXIT_FAILURE, "failed to get shadow entry for '%s'", user_name);

  if (flag_list)
    return handle_list(spw) ? EXIT_SUCCESS : EXIT_FAILURE;

  if (flag_lastday == FLAG_NOT_SET &&
      flag_expiredate == FLAG_NOT_SET &&
      flag_inactive == FLAG_NOT_SET &&
      flag_mindays == FLAG_NOT_SET &&
      flag_maxdays == FLAG_NOT_SET &&
      flag_warndays == FLAG_NOT_SET) {
    if (!interactive_prompt(spw))
      return EXIT_FAILURE;
  }

  return update_shadow(spw) ? EXIT_SUCCESS : EXIT_FAILURE;
}
