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
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include "hardened-shadow.h"

static char *command = NULL;
static bool login_shell = false;
static bool preserve_environment = false;
static char *shell = NULL;
static char *current_username = NULL;
static char *target_username = NULL;
static uid_t target_uid = -1;
static gid_t target_gid = -1;
static char *target_homedir = NULL;

static __attribute__((__noreturn__)) void su_fatal() {
  hardened_shadow_syslog(LOG_NOTICE,
                         "FAILED su for %s by %s",
                         target_username ? target_username : "UNKNOWN",
                         current_username ? current_username : "UNKNOWN");
  errx(EXIT_FAILURE, "Authentication failure");
}

static void usage (void) {
  fputs("Usage: su [options] [LOGIN]\n"
        "\n"
        "Options:\n"
        "  -c, --command COMMAND         pass COMMAND to the invoked shell\n"
        "  -h, --help                    display this help message and exit\n"
        "  -, -l, --login                make the shell a login shell\n"
        "  -m, -p,\n"
        "  --preserve-environment        do not reset environment variables, and\n"
        "                                keep the same shell\n"
        "  -s, --shell SHELL             use SHELL instead of the default in passwd\n"
        "\n", stderr);
  exit(EXIT_FAILURE);
}

static void parse_args(int argc, char **argv) {
  static struct option long_options[] = {
    {"command", required_argument, NULL, 'c'},
    {"help", no_argument, NULL, 'h'},
    {"login", no_argument, NULL, 'l'},
    {"preserve-environment", no_argument, NULL, 'p'},
    {"shell", required_argument, NULL, 's'},
    {NULL, 0, NULL, '\0'}
  };

  int c;
  while ((c = getopt_long(argc, argv, "c:hlmps:", long_options, NULL)) != -1) {
    switch (c) {
      case 'c':
        command = optarg;
        break;
      case 'h':
        usage();
        break;
      case 'l':
        login_shell = true;
        break;
      case 'm':
      case 'p':
        preserve_environment = true;
        break;
      case 's':
        shell = strdup(optarg);
        if (!shell)
          errx(EXIT_FAILURE, "memory allocation failure");
        break;
      default:
        usage();
    }
  }

  if ((optind < argc) && (strcmp(argv[optind], "-") == 0)) {
    login_shell = true;
    optind++;
    if ((optind < argc) && (strcmp(argv[optind], "--") == 0))
      optind++;
  }

  if ((optind < argc) && ('-' != argv[optind][0])) {
    target_username = strdup(argv[optind++]);
    if (!target_username)
      errx(EXIT_FAILURE, "memory allocation failure");
    if ((optind < argc) && (strcmp(argv[optind], "--") == 0))
      optind++;
  }

  if (!target_username || strlen(target_username) == 0) {
    struct passwd *root_pw = getpwuid(0);
    if (!root_pw) {
      hardened_shadow_syslog(LOG_CRIT, "There is no UID 0 user.");
      su_fatal();
    }
    target_username = strdup(root_pw->pw_name);
    if (!target_username)
      errx(EXIT_FAILURE, "memory allocation failure");
  }

  struct passwd *target_pwd = getpwnam(target_username);
  if (!target_pwd)
    errx(EXIT_FAILURE, "Unknown id: %s", target_username);
  target_uid = target_pwd->pw_uid;
  target_gid = target_pwd->pw_gid;
  target_homedir = strdup(target_pwd->pw_dir);
  if (!target_homedir)
    errx(EXIT_FAILURE, "memory allocation failure");

  if (hardened_shadow_is_valid_login_shell(target_pwd->pw_shell) ||
      getuid() == 0) {
    if (shell && shell[0] == '\0') {
      free(shell);
      shell = NULL;
    }
    if (!shell && preserve_environment) {
      shell = strdup(getenv("SHELL"));
      if (!shell)
        errx(EXIT_FAILURE, "memory allocation failure");
    }
    if (shell && shell[0] == '\0') {
      free(shell);
      shell = NULL;
    }
    if (!shell) {
      shell = strdup(target_pwd->pw_shell);
      if (!shell)
        errx(EXIT_FAILURE, "memory allocation failure");
    }
    if (shell && shell[0] == '\0') {
      free(shell);
      shell = NULL;
    }
    if (!shell) {
      shell = strdup(HARDENED_SHADOW_DEFAULT_SHELL);
      if (!shell)
        errx(EXIT_FAILURE, "memory allocation failure");
    }
  } else {
    preserve_environment = false;
    if (shell)
      free(shell);
    shell = strdup(target_pwd->pw_shell);
    if (!shell)
      errx(EXIT_FAILURE, "memory allocation failure");
  }
}

static bool run_shell(const char *shellstr, char *args[], int *status) {
  pid_t child = fork();
  if (child == 0) {
    /* Make sure we pass no undesired file descriptors to the child.
     * This is a safety net in case CLOEXEC is forgotten somewhere
     * in our code, and also in case of other unanticipated situations. */
    if (!hardened_shadow_closefrom(STDERR_FILENO + 1))
      _exit(EXIT_FAILURE);

    /* Prevent TTY hijacking, see https://bugzilla.redhat.com/show_bug.cgi?format=multiple&id=173008 */
    if (command)
      setsid();

    execv(shellstr, args);
    _exit(EXIT_FAILURE);
  } else if (child == -1) {
    hardened_shadow_syslog(LOG_WARNING, "Cannot execute %s", shellstr);
    return false;
  }

  wait(status);
  return true;
}

int main(int argc, char **argv) {
  hardened_shadow_openlog("su");

  if (!hardened_shadow_get_current_username(&current_username))
    errx(EXIT_FAILURE, "Cannot determine your user name.");

  parse_args(argc, argv);

  uid_t my_uid = getuid();
  bool is_root = (my_uid == 0);

  if (!is_root && (!isatty(STDIN_FILENO) || !ttyname(STDIN_FILENO)))
    errx(EXIT_FAILURE, "must be run from a terminal");

  const struct pam_conv pam_conversation = {
    misc_conv,
    NULL
  };
  pam_handle_t *pam_handle = NULL;
  int pam_rv = pam_start("su", target_username, &pam_conversation, &pam_handle);
  if (pam_rv != PAM_SUCCESS) {
    hardened_shadow_syslog(LOG_ERR, "pam_start: error %d", pam_rv);
    su_fatal();
  }

  pam_rv = pam_set_item(pam_handle, PAM_TTY, ttyname(STDIN_FILENO));
  if (pam_rv != PAM_SUCCESS) {
    hardened_shadow_syslog(LOG_ERR, "pam_set_item: %s",
                           pam_strerror(pam_handle, pam_rv));
    goto pam_cleanup;
  }

  pam_rv = pam_set_item(pam_handle, PAM_RUSER, current_username);
  if (pam_rv != PAM_SUCCESS) {
    hardened_shadow_syslog(LOG_ERR, "pam_set_item: %s",
                           pam_strerror(pam_handle, pam_rv));
    goto pam_cleanup;
  }

  pam_rv = pam_fail_delay(pam_handle, 1000000);
  if (pam_rv != PAM_SUCCESS) {
    hardened_shadow_syslog(LOG_ERR, "pam_fail_delay: %s",
                           pam_strerror(pam_handle, pam_rv));
    goto pam_cleanup;
  }

  pam_rv = pam_authenticate(pam_handle, 0);
  if (pam_rv != PAM_SUCCESS) {
    hardened_shadow_syslog(LOG_ERR, "pam_authenticate: %s",
                           pam_strerror(pam_handle, pam_rv));
    goto pam_cleanup;
  }

  pam_rv = pam_acct_mgmt(pam_handle, 0);
  if (pam_rv != PAM_SUCCESS) {
    if (is_root) {
      warnx("%s (ignored)", pam_strerror(pam_handle, pam_rv));
    } else if (pam_rv == PAM_NEW_AUTHTOK_REQD) {
      pam_rv = pam_chauthtok(pam_handle, PAM_CHANGE_EXPIRED_AUTHTOK);
      if (pam_rv != PAM_SUCCESS) {
	hardened_shadow_syslog(LOG_ERR, "pam_chauthtok: %s",
                               pam_strerror(pam_handle, pam_rv));
        goto pam_cleanup;
      }
    } else {
      hardened_shadow_syslog(LOG_ERR, "pam_acct_mgmt: %s",
                             pam_strerror(pam_handle, pam_rv));
      goto pam_cleanup;
    }
  }

  if (setgid(target_gid) != 0) {
    hardened_shadow_syslog(LOG_ERR, "bad group ID `%d' for user `%s': %s",
                           target_gid, target_username, strerror(errno));
    pam_rv = PAM_ABORT;
    goto pam_cleanup;
  }
  if (initgroups(target_username, target_gid) != 0) {
    hardened_shadow_syslog(LOG_ERR, "initgroups failed for user `%s': %s",
                           target_username, strerror(errno));
    pam_rv = PAM_ABORT;
    goto pam_cleanup;
  }

  pam_rv = pam_setcred(pam_handle, PAM_ESTABLISH_CRED);
  if (pam_rv != PAM_SUCCESS) {
    hardened_shadow_syslog(LOG_ERR, "pam_setcred: %s",
                           pam_strerror(pam_handle, pam_rv));
    goto pam_cleanup;
  }

  pam_rv = pam_open_session(pam_handle, 0);
  if (pam_rv != PAM_SUCCESS) {
    hardened_shadow_syslog(LOG_ERR, "pam_open_session: %s",
                           pam_strerror(pam_handle, pam_rv));
    goto pam_cred_cleanup;
  }

  char **pam_env = pam_getenvlist(pam_handle);
  if (!pam_env)
    errx(EXIT_FAILURE, "pam_getenvlist returned NULL");

  struct environment_options environment_options = {
    .pam_environment = pam_env,
    .preserve_environment = preserve_environment,
    .login_shell = login_shell,
    .target_username = target_username,
    .target_homedir = target_homedir,
    .target_shell = shell,
  };
  if (!hardened_shadow_prepare_environment(&environment_options)) {
    pam_rv = PAM_ABORT;
    goto pam_session_cleanup;
  }

  if (setuid(target_uid) != 0) {
    hardened_shadow_syslog(LOG_ERR, "bad user ID `%d' for user `%s': %s",
                           target_uid, target_username, strerror(errno));
    goto pam_session_cleanup;
  }

  int shell_argc = command ? 4 : 2;
  char **shell_argv = calloc(shell_argc, sizeof(*shell_argv));
  if (!shell_argv) {
    hardened_shadow_syslog(LOG_ERR, "memory allocation failure");
    goto pam_session_cleanup;
  }
  /* When argv[0] starts with a dash ("-"), bash will recognize
   * it as a login shell. This is what shadow-utils does. */
  shell_argv[0] = login_shell ? "-su" : shell;
  if (command) {
    shell_argv[1] = "-c";
    shell_argv[2] = command;
  }
  shell_argv[shell_argc - 1] = NULL;
  int status;
  if (!run_shell(shell, shell_argv, &status)) {
    pam_rv = PAM_ABORT;
    goto pam_session_cleanup;
  }
  free(shell_argv);

  pam_rv = pam_setcred(pam_handle, PAM_DELETE_CRED);
  if (pam_rv != PAM_SUCCESS) {
    hardened_shadow_syslog(LOG_ERR, "pam_setcred: %s",
                           pam_strerror(pam_handle, pam_rv));
    pam_close_session(pam_handle, 0);
    pam_end(pam_handle, pam_rv);
    errx(EXIT_FAILURE, "pam_setcred");
  }

  pam_rv = pam_close_session(pam_handle, 0);
  if (pam_rv != PAM_SUCCESS) {
    hardened_shadow_syslog(LOG_ERR, "pam_close_session: %s",
                           pam_strerror(pam_handle, pam_rv));
    pam_end(pam_handle, pam_rv);
    errx(EXIT_FAILURE, "pam_close_session");
  }

  pam_end(pam_handle, pam_rv);

  free(shell);
  free(current_username);
  free(target_username);
  free(target_homedir);

  hardened_shadow_closelog();

  if (WIFEXITED(status))
    return WEXITSTATUS(status);

  return WTERMSIG(status) + 128;
pam_session_cleanup:
  pam_close_session(pam_handle, 0);
pam_cred_cleanup:
  pam_setcred(pam_handle, PAM_DELETE_CRED);
pam_cleanup:
  pam_end(pam_handle, pam_rv);
  su_fatal();
}
