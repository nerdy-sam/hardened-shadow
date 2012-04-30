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
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "hardened-shadow.h"

static bool flag_quiet = false;
static bool flag_read_only = false;

static void usage(void) {
  fputs("Usage: pwck [-q] [-r]\n", stderr);
  exit(EXIT_FAILURE);
}

static void parse_args(int argc, char **argv) {
  int c;
  while ((c = getopt(argc, argv, "qr")) != -1) {
    switch (c) {
      case 'q':
        flag_quiet = true;
        break;
      case 'r':
        flag_read_only = true;
        break;
      default:
        usage();
    }
  }

  if (argc != optind)
    usage ();
}

static bool pwck_ownership_and_permissions(int fd,
                                           uid_t uid,
                                           gid_t gid,
                                           mode_t mode,
                                           const char *description,
                                           const char *user) {
  bool result = true;

  struct stat sb;
  if (fstat(fd, &sb) == 0) {
    if (sb.st_uid != uid || sb.st_gid != gid) {
      result = false;
      warnx("%s of user '%s' has wrong ownership "
            "(actual %ju:%ju; expected %ju:%ju)",
            description, user,
            (uintmax_t)sb.st_uid, (uintmax_t)sb.st_gid,
            (uintmax_t)uid, (uintmax_t)gid);
      if (!flag_read_only &&
          hardened_shadow_interactive_confirm("fix ownership?")) {
        if (fchown(fd, uid, gid) != 0)
          warn("fchown");
      }
    }

    mode_t actual_mode = sb.st_mode & (~S_IFMT);
    if (actual_mode != mode) {
      result = false;
      warnx("%s of user '%s' has wrong permissions "
            "(actual %o; expected %o)",
            description, user,
            actual_mode, mode);
      if (!flag_read_only &&
          hardened_shadow_interactive_confirm("fix permissions?")) {
        if (fchmod(fd, mode) != 0)
          warn("fchmod");
      }
    }
  } else {
    result = false;
    warn("failed to fstat %s of user '%s'", description, user);
  }

  return result;
}

static bool pwck_shadow(void) {
  gid_t hardened_shadow_gid;
  if (!hardened_shadow_get_hardened_shadow_gid(&hardened_shadow_gid))
    return false;

  DIR* hardened_shadow_dir = opendir("/etc/hardened-shadow");
  if (!hardened_shadow_dir)
    return false;

  bool result = true;

  if (!pwck_ownership_and_permissions(hardened_shadow_fd(),
                                      0,
                                      hardened_shadow_gid,
                                      0755,
                                      "hardened-shadow root directory",
                                      "root")) {
    result = false;
  }

  struct dirent *ent;
  while ((ent = readdir(hardened_shadow_dir))) {
    if (strcmp(ent->d_name, ".") == 0 ||
        strcmp(ent->d_name, "..") == 0) {
      continue;
    }

    struct passwd *pwd_tmp = getpwnam(ent->d_name);
    if (!pwd_tmp) {
      result = false;
      warnx("user '%s' has shadow entry but no passwd entry",
            ent->d_name);
      if (!flag_read_only &&
          hardened_shadow_interactive_confirm("delete shadow entry?")) {
        char *path = NULL;
        if (asprintf(&path, "/etc/hardened-shadow/%s", ent->d_name) < 0)
          errx(EXIT_FAILURE, "memory allocation failure");

        if (hardened_shadow_remove_dir_contents(path)) {
          if (rmdir(path) != 0)
            warn("rmdir(%s)", path);
        } else {
          warnx("failed to remove %s", path);
        }

        free(path);
      }

      continue;
    }

    struct passwd pwd;
    if (!hardened_shadow_dup_passwd(pwd_tmp, &pwd))
      errx(EXIT_FAILURE, "memory allocation failure");

    struct spwd *spw = getspnam(ent->d_name);
    if (spw) {
      if (!flag_quiet) {
        if (spw->sp_lstchg > time(NULL) / (24 * 60 * 60)) {
          result = false;
          warnx("user %s: last password change in the future", ent->d_name);
        }
      }
    } else {
      result = false;
      warnx("missing/broken shadow entry for user '%s'", ent->d_name);
    }

    int user_fd = hardened_shadow_open_user_directory(ent->d_name);
    if (user_fd >= 0) {
      if (!pwck_ownership_and_permissions(user_fd,
                                          pwd.pw_uid,
                                          hardened_shadow_gid,
                                          0710,
                                          "hardened-shadow directory",
                                          ent->d_name)) {
        result = false;
      }

      int shadow_fd = hardened_shadow_open_user_file(
          user_fd, "shadow", O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
      if (shadow_fd >= 0) {
        if (!pwck_ownership_and_permissions(shadow_fd,
                                            pwd.pw_uid,
                                            hardened_shadow_gid,
                                            0640,
                                            "shadow file",
                                            ent->d_name)) {
          result = false;
        }

        TEMP_FAILURE_RETRY(close(shadow_fd));
      } else {
        result = false;
        warnx("failed to open shadow file of user '%s'", ent->d_name);
      }

      int aging_fd = hardened_shadow_open_user_file(
          user_fd, "aging", O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
      if (aging_fd >= 0) {
        if (!pwck_ownership_and_permissions(aging_fd,
                                            pwd.pw_uid,
                                            hardened_shadow_gid,
                                            0640,
                                            "aging file",
                                            ent->d_name)) {
          result = false;
        }

        TEMP_FAILURE_RETRY(close(aging_fd));
      } else {
        result = false;
        warnx("failed to open aging file of user '%s'", ent->d_name);
      }

      int shell_fd = hardened_shadow_open_user_file(
          user_fd, "shell", O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
      if (shell_fd >= 0) {
        if (!pwck_ownership_and_permissions(shell_fd,
                                            pwd.pw_uid,
                                            hardened_shadow_gid,
                                            0640,
                                            "shell file",
                                            ent->d_name)) {
          result = false;
        }

        char *shell_contents = NULL;
        size_t contents_length;

        if (hardened_shadow_read_contents(shell_fd, &shell_contents,
                                          &contents_length)) {
          if (access(shell_contents, F_OK) != 0) {
            result = false;
            warnx("shell '%s' of user '%s' does not exist",
                  shell_contents,
                  ent->d_name);
          }
        } else {
          result = false;
          warnx("failed to read shell file of user '%s'", ent->d_name);
        }

        free(shell_contents);

        TEMP_FAILURE_RETRY(close(shell_fd));
      } else {
        result = false;
        warnx("failed to open shell file of user '%s'", ent->d_name);
      }

      TEMP_FAILURE_RETRY(close(user_fd));
    } else {
      result = false;
      warnx("failed to open hardened-shadow directory of user '%s'",
            ent->d_name);
    }

    hardened_shadow_free_passwd_contents(&pwd);
  }

  closedir(hardened_shadow_dir);
  return result;
}

int main(int argc, char **argv) {
  if (lckpwdf() != 0)
    err(EXIT_FAILURE, "lckpwdf");

  parse_args(argc, argv);

  bool result = true;

  if (!hardened_shadow_pwck_passwd(flag_read_only, flag_quiet)) {
    result = false;
    warnx("passwd check failed");
  }

  if (!pwck_shadow()) {
    result = false;
    warnx("shadow check failed");
  }

  hardened_shadow_flush_nscd("passwd");

  if (ulckpwdf() != 0)
    warn("ulckpwdf");

  return (result) ? EXIT_SUCCESS : EXIT_FAILURE;
}
