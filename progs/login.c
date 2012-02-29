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
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <utmpx.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include "hardened-shadow.h"

static const char *hostname = NULL;
static const char *target_username = NULL;
static bool user_preauthenticated = false;
static bool preserve_environment = false;

static void login_fatal() {
  hardened_shadow_syslog(LOG_NOTICE, "FAILED login for %s", target_username ? target_username : "UNKNOWN");
  errx(EXIT_FAILURE, "Authentication failure");
}

static void usage (void) {
  fprintf (stderr, "Usage: su [-p] [name]\n");
  if (getuid() == 0)
    fprintf (stderr, "       su [-p] [-h host] [-f name]\n");
  exit(EXIT_FAILURE);
}

static void parse_args(int argc, char **argv) {
  int flag;
  while ((flag = getopt(argc, argv, "d:fh:p")) != -1) {
    switch (flag) {
      case 'd':
        /* "-d device" ignored for compatibility */
        break;
      case 'f':
        user_preauthenticated = true;
        break;
      case 'h':
        hostname = optarg;
        break;
      case 'p':
        preserve_environment = true;
        break;
      default:
        usage();
    }
  }

  if ((user_preauthenticated || hostname) && getuid() != 0)
    errx(EXIT_FAILURE, "Permission denied.");

  if (optind < argc)
    target_username = argv[optind];

  if (user_preauthenticated && !target_username)
    usage ();
}

static void setup_tty(void) {
  struct termios tp;
  if (tcgetattr(STDIN_FILENO, &tp) != 0)
    return;

  tp.c_lflag |= ISIG | ICANON | ECHO | ECHOE | ECHOKE | ECHOCTL;
  tp.c_lflag &= ~(ECHOPRT | NOFLSH | TOSTOP);

  tp.c_iflag |= ICRNL;
  tp.c_oflag |= ONLCR;

  tcsetattr(STDIN_FILENO, TCSADRAIN, &tp);
}

static int chown_tty(uid_t uid, const char *username) {
  struct group *tty_group = getgrnam("tty");
  if (!tty_group) {
    hardened_shadow_syslog(LOG_ERR, "tty group doesn't exist");
    return PAM_ABORT;
  }

  if ((fchown (STDIN_FILENO, uid, tty_group->gr_gid) != 0) ||
      (fchmod (STDIN_FILENO, 0600) != 0)) {
    hardened_shadow_syslog(LOG_ERR,
                           "unable to change owner or mode of tty stdin for user `%s': %s\n",
                           username, strerror(errno));
    return PAM_ABORT;
  }

  return PAM_SUCCESS;
}

static int get_pam_user (pam_handle_t *pam_handle, char **ptr_pam_user) {
  void *ptr_user;
  int pam_rv = pam_get_item(pam_handle, PAM_USER, (const void **)&ptr_user);
  if (pam_rv == PAM_SUCCESS) {
    if (*ptr_pam_user)
      free(*ptr_pam_user);
    *ptr_pam_user = (ptr_user) ? strdup(ptr_user) : NULL;
    if (ptr_user && !*ptr_pam_user)
      pam_rv = PAM_BUF_ERR;
  }
  return pam_rv;
}

static const char *get_failent_user(const char *username) {
  return (username && getpwnam(username)) ? username : "UNKNOWN";
}

int main(int argc, char **argv) {
  hardened_shadow_openlog("login");

  if (geteuid() != 0)
    errx(EXIT_FAILURE, "Cannot possibly work without effective root");

  parse_args(argc, argv);

  if (isatty(STDIN_FILENO) == 0 || isatty(STDOUT_FILENO) == 0 || isatty(STDERR_FILENO) == 0)
    errx(EXIT_FAILURE, "Must be used from a terminal");

  setup_tty();

  char *target_shell = NULL;
  char *target_homedir = NULL;
  char *pam_user = NULL;

  const struct pam_conv pam_conversation = {
    misc_conv,
    NULL
  };
  pam_handle_t *pam_handle = NULL;
  int pam_rv = pam_start("login", target_username, &pam_conversation, &pam_handle);
  if (pam_rv != PAM_SUCCESS) {
    hardened_shadow_syslog(LOG_ERR, "pam_start: error %d", pam_rv);
    login_fatal();
  }

  pam_rv = pam_set_item(pam_handle, PAM_RHOST, hostname);
  if (pam_rv != PAM_SUCCESS) {
    hardened_shadow_syslog(LOG_ERR, "pam_set_item: %s", pam_strerror(pam_handle, pam_rv));
    goto pam_cleanup;
  }

  pam_rv = pam_set_item(pam_handle, PAM_TTY, ttyname(STDIN_FILENO));
  if (pam_rv != PAM_SUCCESS) {
    hardened_shadow_syslog(LOG_ERR, "pam_set_item: %s", pam_strerror(pam_handle, pam_rv));
    goto pam_cleanup;
  }

  pam_rv = pam_fail_delay(pam_handle, 1000000);
  if (pam_rv != PAM_SUCCESS) {
    hardened_shadow_syslog(LOG_ERR, "pam_fail_delay: %s", pam_strerror(pam_handle, pam_rv));
    goto pam_cleanup;
  }

  if (!user_preauthenticated) {
    char local_hostname[256];
    char login_prompt[512];
    if (gethostname(local_hostname, sizeof(local_hostname)) == 0) {
      snprintf(login_prompt, sizeof(login_prompt), "%s login: ", local_hostname);
    } else {
      strncpy(login_prompt, "login:", sizeof(login_prompt));
    }

    pam_rv = pam_set_item(pam_handle, PAM_USER_PROMPT, login_prompt);
    if (pam_rv != PAM_SUCCESS) {
      hardened_shadow_syslog(LOG_ERR, "pam_set_item: %s", pam_strerror(pam_handle, pam_rv));
      goto pam_cleanup;
    }

    pam_rv = get_pam_user(pam_handle, &pam_user);
    if (pam_rv != PAM_SUCCESS) {
      hardened_shadow_syslog(LOG_ERR, "get_pam_user: %s", pam_strerror(pam_handle, pam_rv));
      goto pam_cleanup;
    }
    if (pam_user && pam_user[0] == '\0') {
      pam_rv = pam_set_item(pam_handle, PAM_USER, NULL);
      if (pam_rv != PAM_SUCCESS) {
        hardened_shadow_syslog(LOG_ERR, "pam_set_item: %s", pam_strerror(pam_handle, pam_rv));
        goto pam_cleanup;
      }
    }

    int pam_authenticate_rv = pam_authenticate(pam_handle, 0);
    if (pam_authenticate_rv != PAM_SUCCESS) {
      hardened_shadow_syslog(LOG_ERR, "pam_authenticate: %s", pam_strerror(pam_handle, pam_authenticate_rv));
      pam_rv = pam_authenticate_rv;
      goto pam_cleanup;
    }

    pam_rv = get_pam_user(pam_handle, &pam_user);
    if (pam_rv != PAM_SUCCESS) {
      hardened_shadow_syslog(LOG_ERR, "get_pam_user: %s", pam_strerror(pam_handle, pam_rv));
      goto pam_cleanup;
    }

    if (pam_authenticate_rv != PAM_SUCCESS) {
      if (pam_authenticate_rv == PAM_MAXTRIES)
        hardened_shadow_syslog(LOG_NOTICE, "TOO MANY LOGIN TRIES %s FOR '%s'", hostname, get_failent_user(pam_user));
      else if (pam_authenticate_rv == PAM_ABORT)
        hardened_shadow_syslog(LOG_ERR, "PAM_ABORT returned from pam_authenticate()");
      else
        hardened_shadow_syslog(LOG_NOTICE, "FAILED LOGIN %s FOR '%s', %s", hostname, get_failent_user(pam_user), pam_strerror(pam_handle, pam_authenticate_rv));

      puts("\nLogin incorrect.");
      goto pam_cleanup;
    }
  }

  pam_rv = pam_acct_mgmt(pam_handle, 0);
  if (pam_rv != PAM_SUCCESS) {
    if (pam_rv == PAM_NEW_AUTHTOK_REQD) {
      pam_rv = pam_chauthtok(pam_handle, PAM_CHANGE_EXPIRED_AUTHTOK);
      if (pam_rv != PAM_SUCCESS) {
        hardened_shadow_syslog(LOG_ERR, "pam_chauthtok: %s", pam_strerror(pam_handle, pam_rv));
        goto pam_cleanup;
      }
    } else {
      hardened_shadow_syslog(LOG_ERR, "pam_acct_mgmt: %s", pam_strerror(pam_handle, pam_rv));
      goto pam_cleanup;
    }
  }

  pam_rv = get_pam_user(pam_handle, &pam_user);
  if (pam_rv != PAM_SUCCESS) {
    hardened_shadow_syslog(LOG_ERR, "get_pam_user: %s", pam_strerror(pam_handle, pam_rv));
    goto pam_cleanup;
  }

  struct passwd *target_pwd = (pam_user) ? getpwnam(pam_user) : NULL;
  if (!target_pwd) {
    hardened_shadow_syslog(LOG_ERR, "cannot find user %s", get_failent_user(pam_user));
    goto pam_cleanup;
  }
  uid_t target_uid = target_pwd->pw_uid;
  gid_t target_gid = target_pwd->pw_gid;
  target_homedir = strdup(target_pwd->pw_dir);
  if (!target_homedir) {
    pam_rv = PAM_BUF_ERR;
    goto pam_cleanup;
  }
  target_shell = strdup(target_pwd->pw_shell);
  if (!target_shell) {
    pam_rv = PAM_BUF_ERR;
    goto pam_cleanup;
  }

  if (setgid(target_gid) != 0) {
    hardened_shadow_syslog(LOG_ERR, "bad group ID `%d' for user `%s': %s", target_gid, pam_user, strerror(errno));
    pam_rv = PAM_ABORT;
    goto pam_cleanup;
  }
  if (initgroups(pam_user, target_gid) != 0) {
    hardened_shadow_syslog(LOG_ERR, "initgroups failed for user `%s': %s", pam_user, strerror(errno));
    pam_rv = PAM_ABORT;
    goto pam_cleanup;
  }

  pam_rv = pam_setcred(pam_handle, PAM_ESTABLISH_CRED);
  if (pam_rv != PAM_SUCCESS) {
    hardened_shadow_syslog(LOG_ERR, "pam_setcred: %s", pam_strerror(pam_handle, pam_rv));
    goto pam_cleanup;
  }

  pam_rv = pam_open_session(pam_handle, 0);
  if (pam_rv != PAM_SUCCESS) {
    hardened_shadow_syslog(LOG_ERR, "pam_open_session: %s", pam_strerror(pam_handle, pam_rv));
    goto pam_cred_cleanup;
  }

  pam_rv = chown_tty(target_uid, get_failent_user(pam_user));
  if (pam_rv != PAM_SUCCESS)
    goto pam_session_cleanup;

  pid_t fork_rv = fork();
  if (fork_rv < 0) {
    warn("fork");
    pam_rv = PAM_SYSTEM_ERR;
    goto pam_session_cleanup;
  } else if (fork_rv > 0) {
    /* This is parent. */
    TEMP_FAILURE_RETRY(waitpid(fork_rv, NULL, 0));
    goto pam_session_cleanup;
  }

  /* This is child. */

  if (getppid() == 1) {
    if (setsid() == -1)
      err(EXIT_FAILURE, "setsid");

    /* The third argument to ioctl seems undocumented. Reading Linux kernel
     * sources indicates that it controls whether a control terminal is stolen
     * if there is already a session having that terminal.
     * 0 means "do not steal". */
    if (ioctl(STDIN_FILENO, TIOCSCTTY, 0) != 0)
      err(EXIT_FAILURE, "TIOCSCTTY");
  }

  /* Note: utmp should be updated by pam_lastlog. */

  char **pam_env = pam_getenvlist(pam_handle);
  if (!pam_env)
    errx(EXIT_FAILURE, "pam_getenvlist returned NULL");

  struct environment_options environment_options = {
    .pam_environment = pam_env,
    .preserve_environment = preserve_environment,
    .login_shell = true,
    .target_username = pam_user,
    .target_homedir = target_homedir,
    .target_shell = target_shell,
  };
  if (!hardened_shadow_prepare_environment(&environment_options))
    errx(EXIT_FAILURE, "hardened_shadow_prepare_environment");

  if (setuid(target_uid) != 0)
    err(EXIT_FAILURE, "setuid");

  {
    char *hushlogin_path = NULL;
    if (asprintf(&hushlogin_path, "%s/.hushlogin", target_homedir) < 0)
      err(EXIT_FAILURE, "memory allocation failure");
    if (putenv((access(hushlogin_path, F_OK) == 0) ? "HUSHLOGIN=TRUE" : "HUSHLOGIN=FALSE") != 0)
      err(EXIT_FAILURE, "putenv");
    free(hushlogin_path);
  }

  if (target_uid == 0)
    hardened_shadow_syslog(LOG_NOTICE, "ROOT LOGIN %s", hostname);
  else
    hardened_shadow_syslog(LOG_INFO, "'%s' logged in %s", pam_user, hostname);

  /* Make sure we pass no undesired file descriptors to the child.
   * This is a safety net in case CLOEXEC is forgotten somewhere
   * in our code, and also in case of other unanticipated situations. */
  if (!hardened_shadow_closefrom(STDERR_FILENO + 1))
    _exit(EXIT_FAILURE);

  /* When argv[0] starts with a dash ("-"), bash will recognize
   * it as a login shell. This is what shadow-utils does. */
  char *argv0 = NULL;
  if (asprintf(&argv0, "-%s", basename(target_shell)) < 0)
    _exit(EXIT_FAILURE);

  for (int i = 1; i < NSIG; i++) {
    /* Ignore the return value. We can't reset signal handler for SIGKILL,
     * and the same might be true for other signals. */
    signal(i, SIG_DFL);
  }

  char *shell_argv[] = { argv0, NULL };
  execv(target_shell, shell_argv);

  hardened_shadow_syslog(LOG_WARNING, "Cannot execute %s", target_shell);
  _exit(EXIT_FAILURE);

pam_session_cleanup:
  pam_close_session(pam_handle, 0);
pam_cred_cleanup:
  pam_setcred(pam_handle, PAM_DELETE_CRED);
pam_cleanup:
  pam_end(pam_handle, pam_rv);

  free(target_shell);
  free(target_homedir);
  free(pam_user);

  if (pam_rv != PAM_SUCCESS) {
    fputs("\nLogin incorrect\n", stderr);
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
