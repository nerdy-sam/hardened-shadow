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
#include "hardened-shadow.h"

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

bool hardened_shadow_get_current_username(char **username) {
  uid_t my_uid = getuid();
  struct passwd *my_pwd = getpwuid(my_uid);
  if (!my_pwd)
    return false;

  *username = strdup(my_pwd->pw_name);
  if (!*username)
    return false;

  return true;
}

void *hardened_shadow_calloc(size_t nmemb, size_t size) {
  if (!hardened_shadow_umul_ok(nmemb, size, SIZE_MAX))
    return NULL;
  size_t length = nmemb * size;
  void *result = malloc(length);
  if (result)
    memset(result, '\0', length);
  return result;
}

bool hardened_shadow_closefrom(int lowfd) {
  DIR *dirp = opendir("/proc/self/fd");
  if (!dirp)
    return false;
  bool result = true;
  struct dirent *dent = NULL;
  while ((dent = readdir(dirp))) {
    if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0)
      continue;
    intmax_t fd = -1;
    result = hardened_shadow_strtonum(dent->d_name, 0, INT_MAX, &fd);
    if (!result)
      goto exit;
    if (fd >= lowfd && fd != dirfd(dirp)) {
      if (close(fd) != 0) {
        result = false;
        goto exit;
      }
    }
  }
exit:
  if (closedir(dirp) != 0)
    result = false;
  return result;
}

bool hardened_shadow_flush_nscd(const char *database) {
  pid_t fork_rv = fork();
  if (fork_rv < 0)
    return false;

  if (fork_rv == 0) {
    execl("/usr/sbin/nscd", "nscd", "-i", database, NULL);
    _exit(EXIT_FAILURE);
  }

  /* Note: don't check the return value. If nscd is not running,
   * "nscd -i <database>" returns exit code 1, and we don't want
   * to fail in that case. */
  TEMP_FAILURE_RETRY(waitpid(fork_rv, NULL, 0));
  return true;
}

/* write(2) wrapper that handles partial writes and EINTR correctly. */
ssize_t hardened_shadow_write(int fd, const char *data, size_t size) {
  size_t total = 0;
  for (ssize_t partial = 0; total < size; total += partial) {
    partial = TEMP_FAILURE_RETRY(write(fd, data + total, size - total));
    if (partial < 0)
      return partial;
  }
  return total;
}

/* read(2) wrapper that handles partial reads and EINTR correctly. */
ssize_t hardened_shadow_read(int fd, char *data, size_t size) {
  size_t total = 0;
  for (ssize_t partial = 0; total < size; total += partial) {
    partial = TEMP_FAILURE_RETRY(read(fd, data + total, size - total));
    if (partial < 0)
      return partial;
    if (partial == 0)
      break;
  }
  return total;
}

bool hardened_shadow_read_contents(int fd, char **contents, size_t *length) {
  char buffer[4096];
  size_t total_bytes = 0;
  size_t total_allocated = 0;

  char *tmp_result = NULL;
  ssize_t bytes_read = -1;
  do {
    bytes_read = TEMP_FAILURE_RETRY(read(fd, buffer, sizeof(buffer)));
    if (bytes_read < 0)
      goto error;

    /* Calculate size of buffer needed to hold all contents, old and new. */
    if (!hardened_shadow_uadd_ok(total_bytes, bytes_read, SIZE_MAX))
      goto error;
    size_t tmp_read = total_bytes + bytes_read;
    if (!hardened_shadow_uadd_ok(tmp_read, 1, SIZE_MAX))
      goto error;
    tmp_read++;

    /* Allocate large enough buffer. */
    while (tmp_read > total_allocated) {
      if (!hardened_shadow_uadd_ok(bytes_read, 1, SIZE_MAX))
        goto error;

      size_t new_allocation;
      if (tmp_result)
        new_allocation = total_allocated * 2;
      else
        new_allocation = uintmin(bytes_read + 1, sizeof(buffer));

      char *reallocated = realloc(tmp_result, new_allocation);
      if (!reallocated)
        goto error;
      tmp_result = reallocated;
      total_allocated = new_allocation;
    }

    memcpy(tmp_result + total_bytes, buffer, bytes_read);
    total_bytes += bytes_read;
  } while (bytes_read > 0);

  if (total_allocated == 0) {
    /* Always return a non-NULL pointer, so that callers can be simple. */
    tmp_result = malloc(1);
    if (!tmp_result)
      goto error;
  }

  tmp_result[total_bytes] = '\0';
  if (length)
    *length = total_bytes;
  *contents = tmp_result;
  return true;

error:
  free(tmp_result);
  return false;
}

bool hardened_shadow_copy_file_contents(int in_fd, int out_fd) {
  char buffer[4096];
  memset(buffer, '\0', sizeof(buffer));

  while (true) {
    ssize_t read_result = hardened_shadow_read(in_fd, buffer, sizeof(buffer));
    if (read_result < 0)
      return false;
    if (read_result == 0)
      return true;
    ssize_t write_result = hardened_shadow_write(out_fd, buffer, read_result);
    if (write_result != read_result)
      return false;
  }
}

bool hardened_shadow_getline(FILE* stream, char **result) {
  size_t getline_length;
  *result = NULL;

  if (getline(result, &getline_length, stream) < 0) {
    free(*result);
    *result = NULL;
    return false;
  }

  /* Make sure the result never has a newline character at the end. */
  size_t length = strlen(*result);
  if (length > 0 && (*result)[length - 1] == '\n')
    (*result)[length - 1] = '\0';

  return true;
}

bool hardened_shadow_get_hardened_shadow_gid(gid_t *result) {
  struct group *gr = getgrnam(HARDENED_SHADOW_GROUP);
  if (!gr)
    return false;

  *result = gr->gr_gid;
  return true;
}

bool hardened_shadow_drop_priv(const char *user_name, uid_t uid, gid_t gid) {
  if (initgroups(user_name, gid) != 0)
    return false;

  if (setresgid(gid, gid, gid) != 0)
    return false;

  if (setresuid(uid, uid, uid) != 0)
    return false;

  return true;
}

bool hardened_shadow_starts_with(const char *text, const char *prefix) {
  return (strncmp(text, prefix, strlen(prefix)) == 0);
}

static bool get_first_free_gid(gid_t min, gid_t max, gid_t *gid) {
  if (min > max)
    return false;
  for (gid_t i = min; i <= max; i++) {
    if (!getgrgid(i)) {
      *gid = i;
      return true;
    }
  }
  return false;
}

bool hardened_shadow_allocate_gid(gid_t min, gid_t max, gid_t *gid) {
  if (min > max)
    return false;

  /* Try to allocate GID larger than any existing GID. */
  gid_t candidate = min;
  setgrent();
  struct group *grp = NULL;
  while ((grp = getgrent())) {
    if (grp->gr_gid >= candidate) {
      candidate = grp->gr_gid + 1;

      if (candidate > max) {
        /* Failed to find GID larger than existing GID and still in bounds,
         * just find any free GID in bounds. */
        return get_first_free_gid(min, max, gid);
      }
    }
  }
  endgrent();

  *gid = candidate;
  return true;
}

bool hardened_shadow_dup_passwd(const struct passwd *pwd, struct passwd *copy) {
  memset(copy, '\0', sizeof(copy));

  copy->pw_name = strdup(pwd->pw_name);
  if (!copy->pw_name)
    goto error;

  copy->pw_passwd = strdup(pwd->pw_passwd);
  if (!copy->pw_passwd)
    goto error;

  copy->pw_uid = pwd->pw_uid;
  copy->pw_gid = pwd->pw_gid;

  copy->pw_gecos = strdup(pwd->pw_gecos);
  if (!copy->pw_gecos)
    goto error;

  copy->pw_dir = strdup(pwd->pw_dir);
  if (!copy->pw_dir)
    goto error;

  copy->pw_shell = strdup(pwd->pw_shell);
  if (!copy->pw_shell)
    goto error;

  return true;

error:
  hardened_shadow_free_passwd_contents(copy);

  return false;
}

void hardened_shadow_free_passwd_contents(struct passwd *copy) {
  free(copy->pw_name);
  free(copy->pw_passwd);
  free(copy->pw_gecos);
  free(copy->pw_dir);
  free(copy->pw_shell);
}

bool hardened_shadow_interactive_confirm(const char *prompt) {
  fprintf(stderr, "%s [y/N] ", prompt);
  fflush(stderr);

  char *line = NULL;
  if (!hardened_shadow_getline(stdin, &line))
    return false;
  if (!line || line[0] == '\0')
    return false;
  return (line[0] == 'y' || line[0] == 'Y');
}

bool hardened_shadow_interactive_prompt(const char *prompt,
                                        const char *default_value,
                                        char **result) {
  printf("\t%s [%s]: ", prompt, default_value);
  fflush(stdout);

  if (!hardened_shadow_getline(stdin, result))
    return false;

  if (!*result || **result == '\0') {
    *result = strdup(default_value);
    if (!*result)
      return false;
  }

  return true;
}

static const char *kLoginPreservedEnv[] = {
  "TERM",
  "COLORTERM",
  "DISPLAY",
  "XAUTHORITY",
};

bool hardened_shadow_prepare_environment(
    const struct environment_options *options) {
  if (!options->preserve_environment) {
    char* preserved_variables[HARDENED_SHADOW_ARRAYSIZE(kLoginPreservedEnv)];
    if (options->login_shell) {
      for (size_t i = 0;
           i < HARDENED_SHADOW_ARRAYSIZE(kLoginPreservedEnv);
           i++) {
        if (getenv(kLoginPreservedEnv[i])) {
          preserved_variables[i] = strdup(getenv(kLoginPreservedEnv[i]));
          if (!preserved_variables[i]) {
            hardened_shadow_syslog(LOG_ERR, "memory allocation failure");
            return false;
          }
        } else {
          preserved_variables[i] = NULL;
        }
      }
    }
    if (clearenv() != 0) {
      hardened_shadow_syslog(LOG_ERR, "clearenv failed");
      return false;
    }
    if (options->login_shell) {
      for (size_t i = 0;
           i < HARDENED_SHADOW_ARRAYSIZE(kLoginPreservedEnv);
           i++) {
        if (!preserved_variables[i])
          continue;
        if (setenv(kLoginPreservedEnv[i], preserved_variables[i], 1) != 0) {
          hardened_shadow_syslog(LOG_ERR, "setenv failed");
          return false;
        }
        free(preserved_variables[i]);
      }

      /* Figure out an existing homedir, and set $HOME accordingly. */
      if (chdir(options->target_homedir) == 0) {
        if (setenv("HOME", options->target_homedir, 1) != 0) {
          hardened_shadow_syslog(LOG_ERR, "setenv failed");
          return false;
        }
      } else if (chdir("/") == 0) {
        if (setenv("HOME", "/", 1) != 0) {
          hardened_shadow_syslog(LOG_ERR, "setenv failed");
          return false;
        }
        puts("No directory, logging in with HOME=/");
      } else {
        hardened_shadow_syslog(LOG_ERR,
                               "unable to cd to `%s' for user `%s'",
                               options->target_homedir,
                               options->target_username);
        return false;
      }

      if (setenv("PATH", "/bin:/usr/bin", 1) != 0) {
        hardened_shadow_syslog(LOG_ERR, "setenv failed");
        return false;
      }
    } else {
      /* Not a login shell. */

      if (setenv("HOME", options->target_homedir, 1) != 0) {
        hardened_shadow_syslog(LOG_ERR, "setenv failed");
        return false;
      }
    }

    if (setenv("SHELL", options->target_shell, 1) != 0) {
      hardened_shadow_syslog(LOG_ERR, "setenv failed");
      return false;
    }
    if (setenv("USER", options->target_username, 1) != 0) {
      hardened_shadow_syslog(LOG_ERR, "setenv failed");
      return false;
    }
    if (setenv("LOGNAME", options->target_username, 1) != 0) {
      hardened_shadow_syslog(LOG_ERR, "setenv failed");
      return false;
    }

    char **env_iter = options->pam_environment;
    while (*env_iter) {
      char *pos = strchr(*env_iter, '=');
      if (!pos) {
        hardened_shadow_syslog(LOG_ERR, "pam_environment is invalid");
        return false;
      }
      *pos = '\0';
      if (setenv(*env_iter, pos + 1, 1) != 0) {
        hardened_shadow_syslog(LOG_ERR, "setenv_failed");
        return false;
      }
      env_iter++;
    }
  }

  if (setenv("IFS", " \t\n", 1) != 0) {
    hardened_shadow_syslog(LOG_ERR, "setenv failed");
    return false;
  }

  return true;
}
