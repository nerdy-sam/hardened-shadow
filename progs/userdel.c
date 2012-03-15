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

#include <dirent.h>
#include <err.h>
#include <fts.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include "hardened-shadow.h"

static void usage(void) {
  fputs("Usage: userdel [options] LOGIN\n"
        "\n"
        "Options:\n"
        "  -h, --help                    display this help message and exit\n"
        "  -r, --remove                  remove home directory and mail spool\n"
        "\n", stderr);
  exit(EXIT_FAILURE);
}

static bool flag_remove = false;
static const char *user_name = NULL;
static uid_t user_uid = -1;
static gid_t user_gid = -1;
static char *user_home = NULL;

static void parse_args(int argc, char **argv) {
  static struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"remove", no_argument, NULL, 'r'},
    {NULL, 0, NULL, '\0'}
  };
  int c;
  while ((c = getopt_long(argc, argv, "hr", long_options, NULL)) != -1) {
    switch (c) {
      case 'r':
        flag_remove = true;
        break;
      default:
        usage();
    }
  }

  if ((optind + 1) != argc)
    usage();

  user_name = argv[argc - 1];
  struct passwd *pwd = getpwnam(user_name);
  if (!pwd)
    errx(EXIT_FAILURE, "user '%s' does not exist", user_name);
  user_uid = pwd->pw_uid;
  user_gid = pwd->pw_gid;
  user_home = strdup(pwd->pw_dir);
  if (!user_home)
    errx(EXIT_FAILURE, "memory allocation failure");
}

static bool recursively_remove_path(const char *path) {
  pid_t fork_rv = fork();
  if (fork_rv == (pid_t)-1)
    return false;

  if (fork_rv == 0) {
    /* Make sure we pass no undesired file descriptors to the child.
     * This is a safety net in case CLOEXEC is forgotten somewhere
     * in our code, and also in case of other unanticipated situations. */
    if (!hardened_shadow_closefrom(STDERR_FILENO + 1))
      _exit(EXIT_FAILURE);

    if (!hardened_shadow_drop_priv(user_name, user_uid, user_gid))
      _exit(EXIT_FAILURE);

    if (!hardened_shadow_remove_dir_contents(path))
      _exit(EXIT_FAILURE);

    _exit(EXIT_SUCCESS);
  }

  int status;
  if (waitpid(fork_rv, &status, 0) == -1)
    return false;

  int rmdir_rv = rmdir(path);
  if (rmdir_rv != 0)
    warn("rmdir(%s)", path);

  return (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) && (rmdir_rv == 0);
}

static bool run_userdel_command(const char *userdel_command) {
  pid_t fork_rv = fork();
  if (fork_rv == (pid_t)-1)
    return false;

  if (fork_rv == 0) {
    /* Make sure we pass no undesired file descriptors to the child.
     * This is a safety net in case CLOEXEC is forgotten somewhere
     * in our code, and also in case of other unanticipated situations. */
    if (!hardened_shadow_closefrom(STDERR_FILENO + 1))
      _exit(EXIT_FAILURE);

    execl(userdel_command, user_name, NULL);

    _exit(EXIT_FAILURE);
  }

  int status;
  if (waitpid(fork_rv, &status, 0) == -1)
    return false;

  return (WIFEXITED(status) && (WEXITSTATUS(status) == 0));
}

int main(int argc, char **argv) {
  hardened_shadow_openlog("userdel");

  if (lckpwdf() != 0)
    err(EXIT_FAILURE, "lckpwdf");

  parse_args(argc, argv);

  bool user_private_groups;
  if (!hardened_shadow_config_get_bool("USER_PRIVATE_GROUPS",
                                       &user_private_groups)) {
    errx(EXIT_FAILURE, "failed to retrieve USER_PRIVATE_GROUPS setting");
  }

  const char *userdel_command = NULL;
  if (!hardened_shadow_config_get_path("USERDEL_COMMAND", &userdel_command))
    errx(EXIT_FAILURE, "failed to retrieve USERDEL_COMMAND setting");

  /* Note: shadow-utils try to detect whether user is logged in.
   * However, it is not obvious how to perform such detection reliably,
   * especially taking daemons like cron or at into account (they usually
   * don't go through PAM or anything that'd allow us to prevent
   * running processes as user being delete in a race-free way.
   *
   * Because of those drawbacks, no such checking is performed here.
   */

  {
    char* user_dir_path = NULL;
    if (asprintf(&user_dir_path, "/etc/hardened-shadow/%s", user_name) < 0)
      errx(EXIT_FAILURE, "memory allocation failure");
    if (!recursively_remove_path(user_dir_path))
      errx(EXIT_FAILURE, "failed to remove %s", user_dir_path);
    free(user_dir_path);
  }

  if (!hardened_shadow_update_group_change_user_name(user_name, NULL))
    errx(EXIT_FAILURE, "hardened_shadow_update_group_change_user_name failed");
  if (!hardened_shadow_replace_passwd(user_name, NULL))
    errx(EXIT_FAILURE, "hardened_shadow_replace_passwd failed");
  if (user_private_groups) {
    struct group *gr = getgrnam(user_name);
    if (gr) {
      gid_t private_gid = gr->gr_gid;

      bool found = false;
      struct passwd *pwd = NULL;
      setpwent();
      while ((pwd = getpwent())) {
        if (pwd->pw_gid == private_gid) {
          found = true;
          break;
        }
      }
      endpwent();

      if (found) {
        warnx("not removing private user group because it is a primary group "
              "of at least one other user");
      } else if (!hardened_shadow_replace_group(user_name, NULL)) {
        errx(EXIT_FAILURE, "failed to remove user private group");
      }
    }
  }

  /* Note: preserve exact wording of syslog messages from shadow-utils
   * where possible. */
  hardened_shadow_syslog(LOG_INFO, "delete user '%s'", user_name);

  if (flag_remove && !recursively_remove_path(user_home))
    errx(EXIT_FAILURE, "remove_home_directory failed");

  if (!run_userdel_command(userdel_command))
    errx(EXIT_FAILURE, "failed to run USERDEL_COMMAND");

  hardened_shadow_flush_nscd("passwd");
  hardened_shadow_flush_nscd("group");

  if (ulckpwdf() != 0)
    warn("ulckpwdf");

  free(user_home);

  return EXIT_SUCCESS;
}
