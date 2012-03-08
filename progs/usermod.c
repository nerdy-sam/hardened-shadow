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
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "hardened-shadow.h"

static void usage(void) {
  fputs("Usage: usermod [options] LOGIN\n"
        "\n"
        "Options:\n"
        "  -c, --comment COMMENT         new value of the GECOS field\n"
        "  -d, --home HOME_DIR           new home directory for the user account\n"
        "  -e, --expiredate EXPIRE_DATE  set account expiration date to EXPIRE_DATE\n"
        "  -f, --inactive INACTIVE       set password inactive after expiration\n"
        "                                to INACTIVE\n"
        "  -g, --gid GROUP               force use GROUP as new primary group\n"
        "  -G, --groups GROUPS           new list of supplementary GROUPS\n"
        "  -a, --append                  append the user to the supplemental GROUPS\n"
        "                                mentioned by the -G option without removing\n"
        "                                him/her from other groups\n"
        "  -h, --help                    display this help message and exit\n"
        "  -l, --login NEW_LOGIN         new value of the login name\n"
        "  -L, --lock                    lock the user account\n"
        "  -m, --move-home               move contents of the home directory to the\n"
        "                                new location (use only with -d)\n"
        "  -o, --non-unique              allow using duplicate (non-unique) UID\n"
        "  -p, --password PASSWORD       use encrypted password for the new password\n"
        "  -s, --shell SHELL             new login shell for the user account\n"
        "  -u, --uid UID                 new UID for the user account\n"
        "  -U, --unlock                  unlock the user account\n"
        "\n", stderr);
  exit(EXIT_FAILURE);
}

#define FLAG_NOT_SET (-2)

static bool flag_append = false;
static char *flag_comment = NULL;
static char *flag_home_dir = NULL;
static intmax_t flag_expiredate = FLAG_NOT_SET;
static intmax_t flag_inactive = FLAG_NOT_SET;
static const char *flag_gid = NULL;
static const char *flag_groups = NULL;
static char *flag_login = NULL;
static bool flag_lock = false;
static bool flag_move_home = false;
static bool flag_non_unique = false;
static char *flag_shell = NULL;
static intmax_t flag_uid = FLAG_NOT_SET;
static bool flag_unlock = false;

static char *user_name = NULL;
static gid_t user_gid = -1;
static gid_t *user_groups = NULL;
static size_t user_ngroups = 0;

static void parse_args(int argc, char **argv) {
  int c;
  static struct option long_options[] = {
    {"append", no_argument, NULL, 'a'},
    {"comment", required_argument, NULL, 'c'},
    {"home", required_argument, NULL, 'd'},
    {"expiredate", required_argument, NULL, 'e'},
    {"inactive", required_argument, NULL, 'f'},
    {"gid", required_argument, NULL, 'g'},
    {"groups", required_argument, NULL, 'G'},
    {"help", no_argument, NULL, 'h'},
    {"login", required_argument, NULL, 'l'},
    {"lock", no_argument, NULL, 'L'},
    {"move-home", no_argument, NULL, 'm'},
    {"non-unique", no_argument, NULL, 'o'},
    {"shell", required_argument, NULL, 's'},
    {"uid", required_argument, NULL, 'u'},
    {"unlock", no_argument, NULL, 'U'},
    {NULL, 0, NULL, '\0'}
  };
  while ((c = getopt_long(argc, argv, "ac:d:e:f:g:G:hl:Lmos:u:U",
                          long_options, NULL)) != -1) {
    switch (c) {
      case 'a':
        flag_append = true;
        break;
      case 'c':
        if (!hardened_shadow_is_valid_field_content(optarg))
          errx(EXIT_FAILURE, "invalid comment '%s'", optarg);
        flag_comment = optarg;
        break;
      case 'd':
        if (!hardened_shadow_is_valid_field_content(optarg) || optarg[0] != '/')
          errx(EXIT_FAILURE, "invalid home directory '%s'", optarg);
        flag_home_dir = optarg;
        break;
      case 'e':
        if (optarg[0] == '\0')
          flag_expiredate = -1;
        else if (!hardened_shadow_getday(optarg, &flag_expiredate))
          errx(EXIT_FAILURE, "invalid date '%s'", optarg);
        break;
      case 'f':
        if (!hardened_shadow_strtonum(optarg, -1, INTMAX_MAX, &flag_inactive))
          errx(EXIT_FAILURE, "invalid numeric argument '%s'", optarg);
        break;
      case 'g':
        flag_gid = optarg;
        break;
      case 'G':
        flag_groups = optarg;
        if (!hardened_shadow_parse_group_list(flag_groups,
                                              &user_groups, &user_ngroups)) {
          errx(EXIT_FAILURE, "invalid group list '%s'", flag_groups);
        }
        break;
      case 'l':
        if (!hardened_shadow_is_valid_user_name(optarg))
          errx(EXIT_FAILURE, "invalid user name '%s'", optarg);
        if (getpwnam(optarg))
          errx(EXIT_FAILURE, "user '%s' already exists", optarg);
        flag_login = optarg;
        break;
      case 'L':
        flag_lock = true;
        break;
      case 'm':
        flag_move_home = true;
        break;
      case 'o':
        flag_non_unique = true;
        break;
      case 's':
        if (!hardened_shadow_is_valid_field_content(optarg) || optarg[0] != '/')
          errx(EXIT_FAILURE, "invalid shell '%s'", optarg);
        flag_shell = optarg;
        break;
      case 'u':
        if (!hardened_shadow_strtonum(optarg, 0, UID_MAX, &flag_uid))
          errx(EXIT_FAILURE, "invalid user ID '%s'", optarg);
        break;
      case 'U':
        flag_unlock = true;
        break;
      default:
        usage();
    }
  }

  if (flag_gid && !hardened_shadow_string_to_gid(flag_gid, &user_gid))
    errx(EXIT_FAILURE, "group '%s' does not exist", flag_gid);

  if (optind != argc - 1)
    usage();

  user_name = argv[optind];
  if (!getpwnam(user_name))
    errx(EXIT_FAILURE, "user '%s' does not exist", user_name);

  if (flag_append && !flag_groups)
    errx(EXIT_FAILURE, "-a flag is only allowed with the -G flag");

  if (flag_lock && flag_unlock)
    errx(EXIT_FAILURE, "the -L and -U flags are exclusive");

  if (flag_non_unique && flag_uid == FLAG_NOT_SET)
    errx(EXIT_FAILURE, "-o flag is only allowed with the -u flag");

  if (flag_move_home && !flag_home_dir)
    errx(EXIT_FAILURE, "-m flag is only allowed with the -d flag");

  if (flag_uid != FLAG_NOT_SET && !flag_non_unique && getpwuid(flag_uid))
    errx(EXIT_FAILURE, "UID '%ju' already exists", (uintmax_t)flag_uid);
}

static bool move_home(const struct passwd *original_pwd,
                      const struct passwd *pwd) {
  struct stat sb;
  if (stat(original_pwd->pw_dir, &sb) != 0) {
    warn("stat");
    return false;
  }

  /* Especially avoid moving special files here (e.g. files in /dev). */
  if (!S_ISDIR(sb.st_mode)) {
    warnx("%s is not a directory", original_pwd->pw_dir);
    return false;
  }

  /* It is an error if the target new directory already exists. */
  if (access(pwd->pw_dir, F_OK) == 0) {
    warnx("directory %s exists", pwd->pw_dir);
    return false;
  }

  /* Rename is the simplest way to deal with the move,
   * and also safest (hard to make mistakes). */
  if (rename(original_pwd->pw_dir, pwd->pw_dir) == 0)
    return true;
  if (errno != EXDEV) {
    warn("rename");
    return false;
  }

  /* Rename failed with EXDEV error, we have to copy contents.
   * The copy is more error-prone and not atomic. */

  if (mkdir(pwd->pw_dir, sb.st_mode & (~S_IFMT)) != 0) {
    warn("mkdir");
    return false;
  }

  if (chown(pwd->pw_dir, pwd->pw_uid, pwd->pw_gid) != 0) {
    warn("chown");
    rmdir(pwd->pw_dir);
    return false;
  }

  if (!hardened_shadow_copy_dir_contents(original_pwd->pw_dir, pwd->pw_dir,
                                         pwd->pw_uid, pwd->pw_gid)) {
    warnx("hardened_shadow_copy_dir_contents failed");
    hardened_shadow_remove_dir_contents(pwd->pw_dir);
    rmdir(pwd->pw_dir);
    return false;
  }

  if (!hardened_shadow_remove_dir_contents(original_pwd->pw_dir)) {
    warnx("hardened_shadow_remove_dir_contents failed");
    return false;
  }

  if (rmdir(original_pwd->pw_dir) != 0) {
    warn("rmdir");
    return false;
  }

  return true;
}

static bool update_passwd(void) {
  char *shell_proxy =
      realpath(HARDENED_SHADOW_ROOT_PREFIX "/bin/shell_proxy", NULL);
  if (!shell_proxy)
    errx(EXIT_FAILURE, "memory allocation failure");

  bool result = true;

  struct passwd *pwd = getpwnam(user_name);
  if (!pwd) {
    warn("getpwnam");
    result = false;
    goto out;
  }

  if (flag_uid != FLAG_NOT_SET)
    pwd->pw_uid = flag_uid;
  if (flag_gid)
    pwd->pw_gid = user_gid;
  if (flag_comment)
    pwd->pw_gecos = flag_comment;
  if (flag_home_dir)
    pwd->pw_dir = flag_home_dir;
  if (flag_login)
    pwd->pw_name = flag_login;

  if (flag_shell) {
    /* Use shell_proxy if possible, so that the user can choose
     * and change his preferred shell. */
    if (hardened_shadow_is_valid_login_shell(flag_shell)) {
      pwd->pw_shell = shell_proxy;
      if (!hardened_shadow_replace_user_file(user_name, pwd->pw_uid,
                                             flag_shell, "shell")) {
        result = false;
        goto out;
      }
    } else {
      pwd->pw_shell = flag_shell;
    }
  }

  result = hardened_shadow_replace_passwd(user_name, pwd);

 out:
  free(shell_proxy);
  hardened_shadow_flush_nscd("passwd");
  return result;
}

static bool update_shadow(uid_t uid) {
  const char *effective_user_name = user_name;

  if (flag_login) {
    if (renameat(hardened_shadow_fd(), user_name,
                 hardened_shadow_fd(), flag_login) != 0) {
      return false;
    }

    effective_user_name = flag_login;
  }

  struct spwd *spw = getspnam(effective_user_name);
  if (!spw) {
    warn("getspnam");
    return false;
  }

  if (flag_lock && spw->sp_pwdp[0] != '!') {
    char *new_pwdp = NULL;
    if (asprintf(&new_pwdp, "!%s", spw->sp_pwdp) < 0)
      return false;

    bool result = true;

    spw->sp_pwdp = new_pwdp;

    char *shadow_contents = NULL;
    if (hardened_shadow_asprintf_shadow(&shadow_contents, spw)) {
      if (!hardened_shadow_replace_user_file(effective_user_name, uid,
                                             shadow_contents, "shadow")) {
        result = false;
      }

      free(shadow_contents);
    } else {
      result = false;
    }

    free(new_pwdp);
    if (!result)
      return false;
  } else if (flag_unlock && spw->sp_pwdp[0] == '!') {
    spw->sp_pwdp = spw->sp_pwdp + 1;

    char *shadow_contents = NULL;
    if (!hardened_shadow_asprintf_shadow(&shadow_contents, spw))
      return false;

    bool result = hardened_shadow_replace_user_file(effective_user_name, uid,
                                                    shadow_contents, "shadow");
    free(shadow_contents);
    if (!result)
      return false;
  }

  if (flag_expiredate != FLAG_NOT_SET)
    spw->sp_expire = flag_expiredate;
  if (flag_inactive != FLAG_NOT_SET)
    spw->sp_inact = flag_inactive;

  char *aging_contents = NULL;
  if (!hardened_shadow_asprintf_aging(&aging_contents, spw))
    return false;

  bool result = hardened_shadow_replace_user_file(effective_user_name, uid,
                                                  aging_contents, "aging");
  free(aging_contents);
  return result;
}

static bool update_group(void) {
  const char *effective_user_name = user_name;

  if (flag_login) {
    if (!hardened_shadow_update_group_change_user_name(user_name, flag_login))
      return false;

    effective_user_name = flag_login;
  }

  if (flag_groups &&
      !hardened_shadow_update_group_add_user(effective_user_name,
                                             user_groups, user_ngroups,
                                             flag_append)) {
    return false;
  }

  hardened_shadow_flush_nscd("group");
  return true;
}

int main(int argc, char **argv) {
  if (!hardened_shadow_read_config())
    errx(EXIT_FAILURE, "failed to read config");

  hardened_shadow_openlog("useradd");

  if (lckpwdf() != 0)
    err(EXIT_FAILURE, "lckpwdf");

  parse_args(argc, argv);

  struct passwd *tmp_pwd = getpwnam(user_name);
  if (!tmp_pwd)
    err(EXIT_FAILURE, "getpwnam");

  struct passwd original_pwd;
  if (!hardened_shadow_dup_passwd(tmp_pwd, &original_pwd))
    errx(EXIT_FAILURE, "memory allocation failure");

  if (!update_passwd())
    errx(EXIT_FAILURE, "update_passwd failed");
  const char *effective_user_name = (flag_login) ? flag_login : user_name;
  struct passwd *pwd = getpwnam(effective_user_name);
  if (!pwd)
    err(EXIT_FAILURE, "getpwnam");
  if (flag_move_home && !move_home(&original_pwd, pwd))
    errx(EXIT_FAILURE, "move_home failed");
  if (!update_shadow(pwd->pw_uid))
    errx(EXIT_FAILURE, "update_shadow failed");
  if (!update_group())
    errx(EXIT_FAILURE, "update_group failed");

  hardened_shadow_free_passwd_contents(&original_pwd);

  if (ulckpwdf() != 0)
    warn("ulckpwdf");

  return EXIT_SUCCESS;
}
