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
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <nss.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "hardened-shadow.h"

static int dup_hardened_shadow_fd = -1;

static DIR *hardened_shadow_dir = NULL;

static void __attribute__((constructor)) hardened_shadow_nss_init(void) {
  dup_hardened_shadow_fd = dup(hardened_shadow_fd());
  hardened_shadow_dir = fdopendir(dup_hardened_shadow_fd);
}

static void __attribute__((destructor)) hardened_shadow_nss_cleanup(void) {
  if (hardened_shadow_dir)
    TEMP_FAILURE_RETRY(closedir(hardened_shadow_dir));
  else if (dup_hardened_shadow_fd != -1)
    TEMP_FAILURE_RETRY(close(dup_hardened_shadow_fd));
}

enum nss_status _nss_hardened_shadow_setspent(void) {
  if (!hardened_shadow_dir)
    return NSS_STATUS_UNAVAIL;

  rewinddir(hardened_shadow_dir);
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_hardened_shadow_endspent(void) {
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_hardened_shadow_getspnam_r(
    const char *name,
    struct spwd *result,
    char *buffer,
    size_t buflen,
    int *errnop) {
  if (!buffer)
    return NSS_STATUS_UNAVAIL;

  memset(result, '\0', sizeof(*result));
  size_t name_length = strlen(name) + 1;
  if (buflen < name_length) {
    *errnop = errno = ERANGE;
    return NSS_STATUS_TRYAGAIN;
  }
  strncpy(buffer, name, buflen);
  result->sp_namp = buffer;
  buffer += name_length;
  buflen -= name_length;

  enum nss_status rv = NSS_STATUS_SUCCESS;

  int user_directory_fd = -1;

  int shadow_fd = -1;
  char *shadow_contents = NULL;

  int aging_fd = -1;
  char *aging_contents = NULL;

  user_directory_fd = hardened_shadow_open_user_directory(name);
  if (user_directory_fd < 0) {
    rv = NSS_STATUS_UNAVAIL;
    goto out;
  }

  shadow_fd = hardened_shadow_open_user_file(user_directory_fd, "shadow", O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
  if (shadow_fd < 0) {
    rv = NSS_STATUS_UNAVAIL;
    goto out;
  }
  size_t shadow_contents_length = 0;
  if (!hardened_shadow_read_contents(shadow_fd, &shadow_contents, &shadow_contents_length)) {
    rv = NSS_STATUS_TRYAGAIN;
    goto out;
  }

  aging_fd = hardened_shadow_open_user_file(user_directory_fd, "aging", O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
  if (aging_fd < 0) {
    rv = NSS_STATUS_UNAVAIL;
    goto out;
  }
  size_t aging_contents_length = 0;
  if (!hardened_shadow_read_contents(aging_fd, &aging_contents, &aging_contents_length)) {
    rv = NSS_STATUS_TRYAGAIN;
    goto out;
  }

  char *strtok_saveptr = NULL;
  char *pwd_str = strtok_r(shadow_contents, ":", &strtok_saveptr);
  char *lstchg_str = strtok_r(NULL, ":", &strtok_saveptr);

  char *min_str = strtok_r(aging_contents, ":", &strtok_saveptr);
  char *max_str = strtok_r(NULL, ":", &strtok_saveptr);
  char *warn_str = strtok_r(NULL, ":", &strtok_saveptr);
  char *inact_str = strtok_r(NULL, ":", &strtok_saveptr);
  char *expire_str = strtok_r(NULL, ":", &strtok_saveptr);

  if (!pwd_str || !lstchg_str || !min_str || !max_str || !warn_str || !inact_str || !expire_str) {
    rv = NSS_STATUS_UNAVAIL;
    goto out;
  }

  size_t pwd_str_length = strlen(pwd_str) + 1;
  if (buflen < pwd_str_length) {
    *errnop = errno = ERANGE;
    rv = NSS_STATUS_TRYAGAIN;
    goto out;
  }
  strncpy(buffer, pwd_str, buflen);
  result->sp_pwdp = buffer;
  buffer += pwd_str_length;
  buflen -= pwd_str_length;

  intmax_t lstchg_imax = -1;
  intmax_t min_imax = -1;
  intmax_t max_imax = -1;
  intmax_t warn_imax = -1;
  intmax_t inact_imax = -1;
  intmax_t expire_imax = -1;

  if (!hardened_shadow_strtonum(lstchg_str, -1, LONG_MAX, &lstchg_imax)) {
    rv = NSS_STATUS_UNAVAIL;
    goto out;
  }
  if (!hardened_shadow_strtonum(min_str, -1, LONG_MAX, &min_imax)) {
    rv = NSS_STATUS_UNAVAIL;
    goto out;
  }
  if (!hardened_shadow_strtonum(max_str, -1, LONG_MAX, &max_imax)) {
    rv = NSS_STATUS_UNAVAIL;
    goto out;
  }
  if (!hardened_shadow_strtonum(warn_str, -1, LONG_MAX, &warn_imax)) {
    rv = NSS_STATUS_UNAVAIL;
    goto out;
  }
  if (!hardened_shadow_strtonum(inact_str, -1, LONG_MAX, &inact_imax)) {
    rv = NSS_STATUS_UNAVAIL;
    goto out;
  }
  if (!hardened_shadow_strtonum(expire_str, -1, LONG_MAX, &expire_imax)) {
    rv = NSS_STATUS_UNAVAIL;
    goto out;
  }

  result->sp_lstchg = lstchg_imax;
  result->sp_min = min_imax;
  result->sp_max = max_imax;
  result->sp_warn = warn_imax;
  result->sp_inact = inact_imax;
  result->sp_expire = expire_imax;

out:
  if (user_directory_fd >= 0)
    TEMP_FAILURE_RETRY(close(user_directory_fd));

  if (shadow_fd >= 0)
    TEMP_FAILURE_RETRY(close(shadow_fd));
  free(shadow_contents);

  if (aging_fd >= 0)
    TEMP_FAILURE_RETRY(close(aging_fd));
  free(aging_contents);

  return rv;
}

enum nss_status _nss_hardened_shadow_getspent_r(
    struct spwd *result,
    char *buffer,
    size_t buflen,
    int *errnop) {
  if (!hardened_shadow_dir)
    return NSS_STATUS_UNAVAIL;

  off_t dir_pos;
  struct dirent *readdir_result;
  do {
    dir_pos = telldir(hardened_shadow_dir);
    readdir_result = readdir(hardened_shadow_dir);
    if (!readdir_result) {
      *errnop = errno = ENOENT;
      return NSS_STATUS_NOTFOUND;
    }
  } while (strcmp(readdir_result->d_name, ".") == 0 ||
           strcmp(readdir_result->d_name, "..") == 0);

  int rv = _nss_hardened_shadow_getspnam_r(readdir_result->d_name,
                                           result,
                                           buffer,
                                           buflen,
                                           errnop);
  switch (rv) {
    case NSS_STATUS_SUCCESS:
      return NSS_STATUS_SUCCESS;

    case NSS_STATUS_TRYAGAIN: {
      *errnop = errno;
      seekdir(hardened_shadow_dir, dir_pos);
      errno = *errnop;
      return NSS_STATUS_TRYAGAIN;
    }

    default:
      return rv;
  }
}
