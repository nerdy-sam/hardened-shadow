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
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <string.h>
#include <unistd.h>

bool hardened_shadow_pwck_passwd(bool read_only, bool quiet) {
  bool result = true;

  struct hardened_shadow_file_state state;
  if (!hardened_shadow_begin_rewrite_file("/etc/passwd", &state)) {
    result = false;
    goto out;
  }

  char *original_line = NULL;
  while (hardened_shadow_getline(state.original_file, &original_line)) {
    bool delete = false;
    struct passwd *pwd_tmp = hardened_shadow_sgetpwent(original_line);
    if (pwd_tmp) {
      struct passwd pwd;
      if (!hardened_shadow_dup_passwd(pwd_tmp, &pwd)) {
        result = false;
        warnx("memory allocation failure");
        goto out;
      }

      // TODO(phajdan.jr): check for duplicates.

      if (!hardened_shadow_is_valid_username(pwd.pw_name)) {
        result = false;
        warnx("invalid user name '%s'", pwd.pw_name);
      }

      if (pwd.pw_uid > UID_MAX) {
        result = false;
        warnx("invalid user ID '%ju'", (uintmax_t)pwd.pw_uid);
      }

      if (!quiet) {
        if (!getgrgid(pwd.pw_gid)) {
          result = false;
          warnx("user '%s': no group %ju", pwd.pw_name, (uintmax_t)pwd.pw_gid);
        }

        if (access(pwd.pw_dir, F_OK) != 0) {
          result = false;
          warnx("user '%s': directory '%s' does not exist", pwd.pw_name, pwd.pw_dir);
        }

        if (access(pwd.pw_shell, F_OK) != 0) {
          result = false;
          warnx("user '%s': program '%s' does not exist", pwd.pw_name, pwd.pw_shell);
        }
      }

      if (!getspnam(pwd.pw_name)) {
        result = false;
        warnx("no shadow entry for '%s'", pwd.pw_name);
        if (!read_only && hardened_shadow_interactive_confirm("add missing entry?")) {
          intmax_t system_min, system_max;
          if (hardened_shadow_config_get_range("SYSTEM_UID_RANGE", &system_min, &system_max)) {
            bool system = pwd.pw_uid >= system_min && pwd.pw_uid <= system_max;
            if (!hardened_shadow_create_shadow_entry(&pwd, NULL, system, -1, -1))
              warnx("adding shadow entry failed");
          } else {
            warnx("failed to retrieve SYSTEM_UID_RANGE");
          }
        }
      }

      if (strcmp(pwd.pw_passwd, HARDENED_SHADOW_SHADOW_PASSWD) != 0 &&
          strcmp(pwd.pw_passwd, HARDENED_SHADOW_LOCKED_PASSWD) != 0) {
        result = false;
        warnx("user '%s' has a non-shadowed entry in /etc/passwd", pwd.pw_name);
      }

      hardened_shadow_free_passwd_contents(&pwd);
    } else {
      result = false;
      warnx("invalid passwd line '%s'", original_line);
      delete = !read_only && hardened_shadow_interactive_confirm("delete?");
    }

    if (delete)
      continue;

    if (fprintf(state.tmp_file, "%s\n", original_line) < 0) {
      result = false;
      goto out;
    }
  }
  if (!feof(state.original_file)) {
    result = false;
    goto out;
  }

  if (!read_only && !hardened_shadow_end_rewrite_file("/etc/passwd", &state)) {
    result = false;
    goto out;
  }

out:
  hardened_shadow_close_file_state(&state);
  return result;
}

bool hardened_shadow_grpck(bool read_only) {
  bool result = true;

  struct hardened_shadow_file_state state;
  if (!hardened_shadow_begin_rewrite_file("/etc/group", &state)) {
    result = false;
    goto out;
  }

  char *original_line = NULL;
  while (hardened_shadow_getline(state.original_file, &original_line)) {
    bool delete = false;
    struct group *gr = hardened_shadow_sgetgrent(original_line);
    if (gr) {
      // TODO(phajdan.jr): check for duplicates.

      if (!hardened_shadow_is_valid_group_name(gr->gr_name)) {
        result = false;
        warnx("invalid group name '%s'", gr->gr_name);
      }

      if (gr->gr_gid > GID_MAX) {
        result = false;
        warnx("invalid group ID '%ju'", (uintmax_t)gr->gr_gid);
      }

      // TODO(phajdan.jr): check the members list.
    } else {
      result = false;
      warnx("invalid group line '%s'", original_line);
      delete = !read_only && hardened_shadow_interactive_confirm("delete?");
    }

    if (delete)
      continue;

    if (fprintf(state.tmp_file, "%s\n", original_line) < 0) {
      result = false;
      goto out;
    }
  }
  if (!feof(state.original_file)) {
    result = false;
    goto out;
  }

  if (!read_only && !hardened_shadow_end_rewrite_file("/etc/group", &state)) {
    result = false;
    goto out;
  }

out:
  hardened_shadow_close_file_state(&state);
  return result;
}
