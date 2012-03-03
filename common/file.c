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

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static const int kDirectoryOpenFlags = O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW;

static int internal_hardened_shadow_fd = -1;

static void __attribute__((destructor)) hardened_shadow_fd_cleanup(void) {
  if (internal_hardened_shadow_fd != -1)
    TEMP_FAILURE_RETRY(close(internal_hardened_shadow_fd));
}

static void maybe_open_hardened_shadow_directory(void) {
  if (internal_hardened_shadow_fd != -1)
    return;

  int root_fd = open("/", kDirectoryOpenFlags);
  if (root_fd < 0)
    return;

  int etc_fd = openat(root_fd, "etc", kDirectoryOpenFlags);
  if (etc_fd < 0)
    goto err_etc;

  internal_hardened_shadow_fd = TEMP_FAILURE_RETRY(openat(etc_fd, "hardened-shadow", kDirectoryOpenFlags));
  TEMP_FAILURE_RETRY(close(etc_fd));
err_etc:
  TEMP_FAILURE_RETRY(close(root_fd));
}

int hardened_shadow_fd(void) {
  maybe_open_hardened_shadow_directory();
  return internal_hardened_shadow_fd;
}

int hardened_shadow_open_user_directory(const char *username) {
  int fd = TEMP_FAILURE_RETRY(openat(hardened_shadow_fd(), username, kDirectoryOpenFlags));

  struct stat sb;
  if (fstat(fd, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
    TEMP_FAILURE_RETRY(close(fd));
    fd = -1;
  }

  return fd;
}

int hardened_shadow_open_user_file(int user_directory_fd, char *name, int flags) {
  int fd = TEMP_FAILURE_RETRY(openat(user_directory_fd, name, flags));

  struct stat sb;
  if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode)) {
    TEMP_FAILURE_RETRY(close(fd));
    fd = -1;
  }

  return fd;
}

static bool create_temp_user_file(const char *username, uid_t uid, const char *contents, char **path) {
  if (asprintf(path, "/etc/hardened-shadow/%s/.tmp.XXXXXX", username) < 0)
    return false;
  int tmp_fd = mkostemp(*path, O_CLOEXEC);
  if (tmp_fd < 0)
    return false;

  bool result = true;

  gid_t hardened_shadow_gid;
  if (!hardened_shadow_get_hardened_shadow_gid(&hardened_shadow_gid)) {
    result = false;
    goto out;
  }
  if (fchown(tmp_fd, uid, hardened_shadow_gid) != 0) {
    result = false;
    goto out;
  }
  if (fchmod(tmp_fd, 0640) != 0) {
    result = false;
    goto out;
  }

  ssize_t contents_length = strlen(contents);
  if (hardened_shadow_write(tmp_fd, contents, contents_length) != contents_length ||
      fdatasync(tmp_fd) != 0) {
    result = false;
    goto out;
  }

out:
  TEMP_FAILURE_RETRY(close(tmp_fd));
  if (!result)
    unlink(*path);
  return result;
}

void hardened_shadow_close_file_state(struct hardened_shadow_file_state *state) {
  free(state->tmp_path);

  if (state->tmp_file)
    fclose(state->tmp_file);
  if (state->original_file)
    fclose(state->original_file);

  memset(state, '\0', sizeof(*state));
}

bool hardened_shadow_begin_rewrite_file(const char *path, struct hardened_shadow_file_state *state) {
  memset(state, '\0', sizeof(*state));

  state->tmp_path = strdup("/etc/.hardened-shadow.XXXXXX");
  if (!state->tmp_path)
    return false;

  int tmp_fd = mkostemp(state->tmp_path, O_CLOEXEC);
  if (tmp_fd < 0)
    goto error;

  state->tmp_file = fdopen(tmp_fd, "w");
  if (!state->tmp_file)
    goto error;

  state->original_file = fopen(path, "re");
  if (!state->original_file)
    goto error;

  if (fstat(fileno(state->original_file), &state->original_stat) != 0)
    goto error;

  return true;

error:
  if (!state->tmp_file && tmp_fd >= 0)
    TEMP_FAILURE_RETRY(close(tmp_fd));

  hardened_shadow_close_file_state(state);
  return false;
}

bool hardened_shadow_end_rewrite_file(const char *path, struct hardened_shadow_file_state *state) {
  bool result = true;

  if (fchown(fileno(state->tmp_file), state->original_stat.st_uid, state->original_stat.st_gid) != 0) {
    result = false;
    goto out;
  }

  if (fchmod(fileno(state->tmp_file), state->original_stat.st_mode) != 0) {
    result = false;
    goto out;
  }

  if (rename(state->tmp_path, path) != 0) {
    result = false;
    goto out;
  }

out:
  hardened_shadow_close_file_state(state);
  return result;
}

struct group *hardened_shadow_sgetgrent(char *buf) {
  FILE *stream = fmemopen(buf, strlen(buf), "r");
  if (!stream)
    return NULL;
  struct group *result = fgetgrent(stream);
  TEMP_FAILURE_RETRY(fclose(stream));
  return result;
}

struct passwd *hardened_shadow_sgetpwent(char *buf) {
  FILE *stream = fmemopen(buf, strlen(buf), "r");
  if (!stream)
    return NULL;
  struct passwd *result = fgetpwent(stream);
  TEMP_FAILURE_RETRY(fclose(stream));
  return result;
}

bool hardened_shadow_replace_file(const char *contents, const char *filename) {
  char *tmp_path = NULL;
  if (asprintf(&tmp_path, "%s.tmp.XXXXXX", filename) < 0)
    return false;

  bool result = true;

  int tmp_fd = mkostemp(tmp_path, O_CLOEXEC);
  if (tmp_fd < 0) {
    result = false;
    goto out;
  }

  ssize_t contents_length = strlen(contents);
  if (hardened_shadow_write(tmp_fd, contents, contents_length) != contents_length ||
      fdatasync(tmp_fd) != 0) {
    result = false;
    unlink(tmp_path);
    goto out;
  }

  if (rename(tmp_path, filename) != 0) {
    result = false;
    unlink(tmp_path);
    goto out;
  }

out:
  if (tmp_fd != -1)
    TEMP_FAILURE_RETRY(close(tmp_fd));
  free(tmp_path);
  return result;
}

bool hardened_shadow_replace_user_file(const char *username, uid_t uid, const char *contents, const char *filename) {
  bool result = true;
  int user_directory_fd = -1;

  char *tmp_path = NULL;
  if (!create_temp_user_file(username, uid, contents, &tmp_path)) {
    result = false;
    goto out;
  }

  user_directory_fd = hardened_shadow_open_user_directory(username);
  if (user_directory_fd < 0) {
    result = false;
    goto out;
  }

  if (renameat(user_directory_fd, basename(tmp_path), user_directory_fd, filename) != 0) {
    result = false;
    goto out;
  }
  if (fsync(user_directory_fd) != 0) {
    result = false;
    goto out;
  }

out:
  if (user_directory_fd != -1)
    TEMP_FAILURE_RETRY(close(user_directory_fd));
  free(tmp_path);
  return result;
}

bool hardened_shadow_update_passwd_change_gid(gid_t old_gid, gid_t new_gid) {
  bool result = true;

  struct hardened_shadow_file_state state;
  if (!hardened_shadow_begin_rewrite_file("/etc/passwd", &state)) {
    result = false;
    goto out;
  }

  char *original_line = NULL;
  while (hardened_shadow_getline(state.original_file, &original_line)) {
    struct passwd *pwd = hardened_shadow_sgetpwent(original_line);
    if (pwd) {
      if (pwd->pw_gid == old_gid)
        pwd->pw_gid = new_gid;
      if (putpwent(pwd, state.tmp_file) != 0) {
        result = false;
        goto out;
      }
    } else if (fprintf(state.tmp_file, "%s\n", original_line) < 0) {
      result = false;
      goto out;
    }
  }
  if (!feof(state.original_file)) {
    result = false;
    goto out;
  }

  if (!hardened_shadow_end_rewrite_file("/etc/passwd", &state)) {
    result = false;
    goto out;
  }

out:
  hardened_shadow_close_file_state(&state);
  return result;
}

bool hardened_shadow_update_passwd_shell_proxy(void) {
  bool result = true;

  struct hardened_shadow_file_state state;
  if (!hardened_shadow_begin_rewrite_file("/etc/passwd", &state)) {
    result = false;
    goto out;
  }

  char *original_line = NULL;
  while (hardened_shadow_getline(state.original_file, &original_line)) {
    struct passwd *pwd = hardened_shadow_sgetpwent(original_line);
    if (pwd) {
      char *shell_buffer = NULL;

      if (hardened_shadow_is_valid_login_shell(pwd->pw_shell)) {
        if (!hardened_shadow_replace_user_file(pwd->pw_name, pwd->pw_uid, pwd->pw_shell, "shell")) {
          result = false;
          goto out;
        }

        pwd->pw_shell = shell_buffer = realpath(HARDENED_SHADOW_ROOT_PREFIX "/bin/shell_proxy", NULL);
        if (!pwd->pw_shell) {
          result = false;
          goto out;
        }
      }

      int rv = putpwent(pwd, state.tmp_file);
      free(shell_buffer);
      if (rv != 0) {
        result = false;
        goto out;
      }
    } else if (fprintf(state.tmp_file, "%s\n", original_line) < 0) {
      result = false;
      goto out;
    }
  }
  if (!feof(state.original_file)) {
    result = false;
    goto out;
  }

  if (!hardened_shadow_end_rewrite_file("/etc/passwd", &state)) {
    result = false;
    goto out;
  }

out:
  hardened_shadow_close_file_state(&state);
  return result;
}

bool hardened_shadow_update_passwd_undo_shell_proxy(void) {
  char *shell_proxy = realpath(HARDENED_SHADOW_ROOT_PREFIX "/bin/shell_proxy", NULL);
  if (!shell_proxy)
    return false;

  bool result = true;

  struct hardened_shadow_file_state state;
  if (!hardened_shadow_begin_rewrite_file("/etc/passwd", &state)) {
    result = false;
    goto out;
  }

  char *original_line = NULL;
  while (hardened_shadow_getline(state.original_file, &original_line)) {
    struct passwd *pwd = hardened_shadow_sgetpwent(original_line);
    if (pwd) {
      if (strcmp(pwd->pw_shell, shell_proxy) == 0) {
        int user_fd = hardened_shadow_open_user_directory(pwd->pw_name);
        if (user_fd < 0) {
          warn("hardened_shadow_open_user_directory failed");
          result = false;
          goto out;
        }
        int shell_fd = hardened_shadow_open_user_file(user_fd, "shell", O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
        if (shell_fd < 0) {
          warn("hardened_shadow_open_user_file failed");
          result = false;
          goto out;
        }
        if (!hardened_shadow_read_contents(shell_fd, &pwd->pw_shell, NULL)) {
          warn("hardened_shadow_read_contents failed");
          result = false;
          goto out;
        }

        TEMP_FAILURE_RETRY(close(shell_fd));
        TEMP_FAILURE_RETRY(close(user_fd));
      }

      if (putpwent(pwd, state.tmp_file) != 0) {
        result = false;
        goto out;
      }
    } else if (fprintf(state.tmp_file, "%s\n", original_line) < 0) {
      result = false;
      goto out;
    }
  }
  if (!feof(state.original_file)) {
    result = false;
    goto out;
  }

  if (!hardened_shadow_end_rewrite_file("/etc/passwd", &state)) {
    result = false;
    goto out;
  }

out:
  free(shell_proxy);
  hardened_shadow_close_file_state(&state);
  return result;
}

static size_t list_length(char **list) {
  size_t result = 0;
  while (*list) {
    result++;
    list++;
  }
  return result;
}

bool hardened_shadow_update_group_add_user(const char *user_name, const gid_t *groups, size_t groups_length, bool append) {
  char *dup_user_name = strdup(user_name);
  if (!dup_user_name)
    return false;

  bool result = true;

  struct hardened_shadow_file_state state;
  if (!hardened_shadow_begin_rewrite_file("/etc/group", &state)) {
    result = false;
    goto out;
  }

  char *original_line = NULL;
  while (hardened_shadow_getline(state.original_file, &original_line)) {
    struct group *gr = hardened_shadow_sgetgrent(original_line);
    if (gr) {
      char **new_mem = NULL;

      bool target_group = false;
      for (size_t i = 0; i < groups_length; i++) {
        if (gr->gr_gid == groups[i]) {
          target_group = true;
          break;
        }
      }

      if (target_group) {
        size_t mem_length = list_length(gr->gr_mem);
        new_mem = hardened_shadow_calloc(mem_length + 2, sizeof(*new_mem));
        if (!new_mem) {
          result = false;
          goto out;
        }

        for (size_t i = 0; i < mem_length; i++)
          new_mem[i] = gr->gr_mem[i];
        new_mem[mem_length] = NULL;
        gr->gr_mem = new_mem;

        bool found = false;
        for (size_t i = 0; i < mem_length; i++) {
          if (strcmp(gr->gr_mem[i], dup_user_name) == 0) {
            found = true;
            break;
          }
        }

        if (!found) {
          gr->gr_mem[mem_length] = dup_user_name;
          gr->gr_mem[mem_length + 1] = NULL;
        }
      }

      int rv = putgrent(gr, state.tmp_file);
      free(new_mem);
      if (rv != 0) {
        result = false;
        goto out;
      }
    } else if (!append) {
      size_t mem_length = list_length(gr->gr_mem);
      char **new_mem = hardened_shadow_calloc(mem_length + 1, sizeof(*new_mem));
      if (!new_mem) {
        result = false;
        goto out;
      }

      size_t new_mem_length = 0;
      for (size_t i = 0; i < mem_length; i++) {
        if (strcmp(dup_user_name, gr->gr_mem[i]) != 0) {
          new_mem[new_mem_length] = gr->gr_mem[i];
          new_mem_length++;
        }
      }
      new_mem[new_mem_length] = NULL;
      gr->gr_mem = new_mem;

      int rv = putgrent(gr, state.tmp_file);
      free(new_mem);
      if (rv != 0) {
        result = false;
        goto out;
      }
    } else if (fprintf(state.tmp_file, "%s\n", original_line) < 0) {
      result = false;
      goto out;
    }
  }
  if (!feof(state.original_file)) {
    result = false;
    goto out;
  }

  if (!hardened_shadow_end_rewrite_file("/etc/group", &state)) {
    result = false;
    goto out;
  }

out:
  hardened_shadow_close_file_state(&state);
  free(dup_user_name);
  return result;
}

bool hardened_shadow_update_group_change_user_name(const char *old_name, char *new_name) {
  bool result = true;

  struct hardened_shadow_file_state state;
  if (!hardened_shadow_begin_rewrite_file("/etc/group", &state)) {
    result = false;
    goto out;
  }

  char *original_line = NULL;
  while (hardened_shadow_getline(state.original_file, &original_line)) {
    struct group *gr = hardened_shadow_sgetgrent(original_line);
    if (gr) {
      size_t mem_length = list_length(gr->gr_mem);
      if (mem_length == 0) {
        if (putgrent(gr, state.tmp_file) != 0) {
          result = false;
          goto out;
        }
      } else {
        char **new_mem = hardened_shadow_calloc(mem_length + 1, sizeof(*new_mem));
        if (!new_mem) {
          result = false;
          goto out;
        }
        size_t new_mem_index = 0;
        for (size_t i = 0; i < mem_length; i++) {
          if (strcmp(gr->gr_mem[i], old_name) == 0) {
            if (new_name)
              new_mem[new_mem_index++] = new_name;
          } else {
            new_mem[new_mem_index++] = gr->gr_mem[i];
          }
        }
        new_mem[new_mem_index] = NULL;
        gr->gr_mem = new_mem;
        int rv = putgrent(gr, state.tmp_file);
        free(new_mem);
        if (rv != 0) {
          result = false;
          goto out;
        }
      }
    } else if (fprintf(state.tmp_file, "%s\n", original_line) < 0) {
      result = false;
      goto out;
    }
  }
  if (!feof(state.original_file)) {
    result = false;
    goto out;
  }

  if (!hardened_shadow_end_rewrite_file("/etc/group", &state)) {
    result = false;
    goto out;
  }

out:
  hardened_shadow_close_file_state(&state);
  return result;
}

static bool sputgrent(const struct group *grp, char **buf) {
  *buf = NULL;
  size_t buf_size;
  FILE *stream = open_memstream(buf, &buf_size);
  if (!stream)
    return false;
  bool result = (putgrent(grp, stream) == 0);
  /* Note: close the stream first, so that *buf is valid. */
  if (fclose(stream) != 0)
    result = false;
  if (result) {
    size_t length = strlen(*buf);
    if (length > 0 && (*buf)[length - 1] == '\n')
      (*buf)[length - 1] = '\0';
  } else {
    free(*buf);
    *buf = NULL;
  }
  return result;
}

static bool sputpwent(const struct passwd *pwd, char **buf) {
  *buf = NULL;
  size_t buf_size;
  FILE *stream = open_memstream(buf, &buf_size);
  if (!stream)
    return false;
  bool result = (putpwent(pwd, stream) == 0);
  /* Note: close the stream first, so that *buf is valid. */
  if (fclose(stream) != 0)
    result = false;
  if (result) {
    size_t length = strlen(*buf);
    if (length > 0 && (*buf)[length - 1] == '\n')
      (*buf)[length - 1] = '\0';
  } else {
    free(*buf);
    *buf = NULL;
  }
  return result;
}

static bool hardened_shadow_replace_line(const char *line_id, const char *replacement_line, const char *file_path) {
  bool result = true;

  struct hardened_shadow_file_state state;
  if (!hardened_shadow_begin_rewrite_file(file_path, &state)) {
    result = false;
    goto out;
  }

  bool replaced = false;

  char *original_line = NULL;
  while (hardened_shadow_getline(state.original_file, &original_line)) {
    bool matched = hardened_shadow_starts_with(original_line, line_id);

    /* NULL replacement_line means delete entry. */
    if (matched && !replacement_line)
      continue;

    if (fprintf(state.tmp_file, "%s\n", matched ? replacement_line : original_line) < 0) {
      result = false;
      goto out;
    }

    replaced = replaced || matched;
  }
  if (!feof(state.original_file)) {
    result = false;
    goto out;
  }
  if (!replaced && replacement_line) {
    if (fprintf(state.tmp_file, "%s\n", replacement_line) < 0) {
      result = false;
      goto out;
    }
    replaced = true;
  }

  if (!hardened_shadow_end_rewrite_file(file_path, &state)) {
    result = false;
    goto out;
  }

out:
  hardened_shadow_close_file_state(&state);
  return result;
}

bool hardened_shadow_replace_passwd(const char *user_name, struct passwd *replacement_pwd) {
  char *replacement_line = NULL;
  if (replacement_pwd && !sputpwent(replacement_pwd, &replacement_line))
    return false;

  bool result = true;

  char *line_id = NULL;
  if (asprintf(&line_id, "%s:", user_name) < 0) {
    result = false;
    goto out;
  }

  if (!hardened_shadow_replace_line(line_id, replacement_line, "/etc/passwd")) {
    result = false;
    goto out;
  }

out:
  free(replacement_line);
  free(line_id);
  return result;
}

bool hardened_shadow_replace_group(const char *group_name, struct group *replacement_group) {
  char *replacement_line = NULL;
  if (replacement_group && !sputgrent(replacement_group, &replacement_line))
    return false;

  bool result = true;

  char *line_id = NULL;
  if (asprintf(&line_id, "%s:", group_name) < 0) {
    result = false;
    goto out;
  }

  if (!hardened_shadow_replace_line(line_id, replacement_line, "/etc/group")) {
    result = false;
    goto out;
  }

out:
  free(replacement_line);
  free(line_id);
  return result;
}

bool hardened_shadow_create_shadow_entry(const struct passwd *pwd, const struct spwd *spwd, bool system, long inactive_days, long expiredate) {
  struct spwd default_spwd;
  default_spwd.sp_namp = pwd->pw_name;
  default_spwd.sp_pwdp = HARDENED_SHADOW_LOCKED_PASSWD;
  default_spwd.sp_lstchg = time(NULL) / (24 * 60 * 60);
  if (system) {
    default_spwd.sp_min = -1;
    default_spwd.sp_max = -1;
    default_spwd.sp_warn = -1;
    default_spwd.sp_inact = -1;
    default_spwd.sp_expire = -1;
  } else {
    intmax_t min_days, max_days, warn_age;

    if (!hardened_shadow_config_get_integer("PASS_MIN_DAYS", &min_days))
      return false;
    if (!hardened_shadow_config_get_integer("PASS_MAX_DAYS", &max_days))
      return false;
    if (!hardened_shadow_config_get_integer("PASS_WARN_AGE", &warn_age))
      return false;

    default_spwd.sp_min = min_days;
    default_spwd.sp_max = max_days;
    default_spwd.sp_warn = warn_age;
    default_spwd.sp_inact = inactive_days;
    default_spwd.sp_expire = expiredate;
  }
  default_spwd.sp_flag = -1;

  const struct spwd *effective_spwd = spwd ? spwd : &default_spwd;

  char *shadow_contents = NULL;
  char *aging_contents = NULL;

  bool result = true;

  if (!hardened_shadow_asprintf_shadow(&shadow_contents, effective_spwd)) {
    result = false;
    goto out;
  }

  if (!hardened_shadow_asprintf_aging(&aging_contents, effective_spwd)) {
    result = false;
    goto out;
  }

  int hs_fd = hardened_shadow_fd();
  if (hs_fd < 0) {
    result = false;
    goto out;
  }

  if (mkdirat(hs_fd, pwd->pw_name, 0710) != 0) {
    result = false;
    goto out;
  }
  int user_fd = hardened_shadow_open_user_directory(pwd->pw_name);
  if (user_fd < 0) {
    result = false;
    goto out;
  }
  gid_t hardened_shadow_gid;
  if (!hardened_shadow_get_hardened_shadow_gid(&hardened_shadow_gid)) {
    result = false;
    goto out;
  }
  if (fchown(user_fd, pwd->pw_uid, hardened_shadow_gid) != 0) {
    result = false;
    goto out;
  }

  if (!hardened_shadow_replace_user_file(pwd->pw_name, pwd->pw_uid, shadow_contents, "shadow")) {
    result = false;
    goto out;
  }
  if (!hardened_shadow_replace_user_file(pwd->pw_name, pwd->pw_uid, aging_contents, "aging")) {
    result = false;
    goto out;
  }
  if (!hardened_shadow_replace_user_file(pwd->pw_name, pwd->pw_uid, pwd->pw_shell, "shell")) {
    result = false;
    goto out;
  }

out:
  free(shadow_contents);
  free(aging_contents);
  return result;
}
