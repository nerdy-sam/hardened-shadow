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
#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "hardened-shadow.h"

static char *target_shell = NULL;
static char *target_user = NULL;
static uid_t target_uid = -1;

static bool update_passwd = false;

static void usage(void) {
  fputs("Usage: chsh [options] [LOGIN]\n"
        "\n"
        "Options:\n"
        "  -h, --help                    display this help message and exit\n"
        "  -s, --shell SHELL             new login shell for the user account\n", stderr);
  if (getuid() == 0)
    fputs("  -p                            update /etc/passwd instead of user's shell file\n", stderr);
  fputs("\n", stderr);
  exit(EXIT_FAILURE);
}

static void parse_args(int argc, char **argv) {
  static struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"shell", required_argument, NULL, 's'},
    {NULL, 0, NULL, '\0'}
  };

  int c;
  while ((c = getopt_long(argc, argv, "hs:p", long_options, NULL)) != -1) {
    switch (c) {
      case 'h':
        usage();
        break;
      case 's':
        target_shell = strdup(optarg);
        if (!target_shell)
          err(EXIT_FAILURE, "memory allocation failure");
        break;
      case 'p':
        update_passwd = true;
        break;
      default:
        usage();
    }
  }

  if (update_passwd && getuid() != 0)
    errx(EXIT_FAILURE, "Permission denied.");

  if (argc > (optind + 1))
    usage();

  if (optind < argc) {
    target_user = strdup(argv[optind]);
  } else {
    struct passwd *pwdent = getpwuid(getuid());
    if (!pwdent)
      errx(EXIT_FAILURE, "Cannot determine your user name.");
    target_user = strdup(pwdent->pw_name);
  }

  if (!target_user)
    err(EXIT_FAILURE, "memory allocation failure");
}

static bool update_passwd_file(const char *user, char *shell) {
  if (lckpwdf() != 0) {
    warn("lckpwdf");
    return false;
  }

  bool result = true;
  char *buffer = NULL;

  long buffer_size = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (buffer_size < 0) {
    warn("sysconf");
    result = false;
    goto out;
  }

  buffer = malloc(buffer_size);
  if (!buffer) {
    warn("malloc");
    result = false;
    goto out;
  }

  struct passwd pwd;
  struct passwd *pwd_result = NULL;
  getpwnam_r(user, &pwd, buffer, buffer_size, &pwd_result);
  if (!pwd_result) {
    warnx("getpwnam_r failed");
    result = false;
    goto out;
  }

  pwd.pw_shell = shell;
  if (!hardened_shadow_replace_passwd(user, &pwd)) {
    warnx("hardened_shadow_replace_passwd failed");
    result = false;
  }

out:
  free(buffer);
  ulckpwdf();
  return result;
}

int main(int argc, char **argv) {
  parse_args(argc, argv);

  struct passwd *pwdent = getpwnam(target_user);
  if (!pwdent)
    errx(EXIT_FAILURE, "user '%s' does not exist", target_user);
  target_uid = pwdent->pw_uid;

  if (getuid() != 0) {
    if (pwdent->pw_uid != getuid())
      errx(EXIT_FAILURE, "You may not change the shell for '%s'.", target_user);
    if (!hardened_shadow_is_valid_login_shell(pwdent->pw_shell))
      errx(EXIT_FAILURE, "You may not change the shell for '%s'.", target_user);
  }
  char *default_shell = NULL;
  if (update_passwd) {
    default_shell = strdup(pwdent->pw_shell);
    if (!default_shell)
      err(EXIT_FAILURE, "memory allocation failure");
  } else {
    int user_fd = hardened_shadow_open_user_directory(target_user);
    if (user_fd < 0)
      errx(EXIT_FAILURE, "hardened_shadow_open_user_directory failed");
    int shell_fd = hardened_shadow_open_user_file(user_fd, "shell", O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
    if (shell_fd < 0)
      errx(EXIT_FAILURE, "hardened_shadow_open_user_file failed");
    if (!hardened_shadow_read_contents(shell_fd, &default_shell, NULL))
      errx(EXIT_FAILURE, "hardened_shadow_read_contents failed");

    TEMP_FAILURE_RETRY(close(shell_fd));
    TEMP_FAILURE_RETRY(close(user_fd));
  }

  if (!target_shell) {
    printf("Changing the login shell for %s\n", target_user);
    puts("Enter the new value, or press ENTER for the default\n");
    if (!hardened_shadow_interactive_prompt("Login Shell", default_shell, &target_shell))
      errx(EXIT_FAILURE, "Failed to get the response.");
  }

  if (!update_passwd) {
    char *shell_proxy = realpath(HARDENED_SHADOW_ROOT_PREFIX "/bin/shell_proxy", NULL);
    if (!shell_proxy)
      errx(EXIT_FAILURE, "memory allocation failure");

    int rv = strcmp(shell_proxy, target_shell);
    free(shell_proxy);
    if (rv == 0)
      errx(EXIT_FAILURE, "%s is an invalid shell.", target_shell);
  }

  if (!hardened_shadow_is_valid_field_content(target_shell))
    errx(EXIT_FAILURE, "%s is an invalid shell.", target_shell);

  if (getuid() != 0) {
    if (!hardened_shadow_is_valid_login_shell(target_shell))
      errx(EXIT_FAILURE, "%s is an invalid shell.", target_shell);
    if (access(target_shell, X_OK) != 0)
      errx(EXIT_FAILURE, "%s is an invalid shell.", target_shell);
  }

  if (update_passwd) {
    if (!update_passwd_file(target_user, target_shell))
      errx(EXIT_FAILURE, "Failed to change shell.");
    hardened_shadow_flush_nscd("passwd");
  } else {
    if (!hardened_shadow_replace_user_file(target_user, target_uid, target_shell, "shell"))
      errx(EXIT_FAILURE, "Failed to change shell.");
  }

  return EXIT_SUCCESS;
}
