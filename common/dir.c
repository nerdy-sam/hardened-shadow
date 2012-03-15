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
#include "hardened-shadow.h"

#include <dirent.h>
#include <err.h>
#include <fcntl.h>
#include <fts.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

bool hardened_shadow_remove_dir_contents(const char *path) {
  bool result = true;

  /* Note: nftw-based code would be possibly simpler,
   * but it wouldn't be possible to have as detailed error messages. */
  FTS *fts_handle = NULL;
  char *fts_argv[] = { strdup(path), NULL };

  /* Make sure strdup above succeeded. */
  if (!fts_argv[0]) {
    result = false;
    goto out;
  }

  fts_handle = fts_open(fts_argv, FTS_PHYSICAL | FTS_NOSTAT, NULL);
  if (!fts_handle) {
    warn("fts_open");
    result = false;
    goto out;
  }

  FTSENT *fts_entry;
  while ((fts_entry = fts_read(fts_handle))) {
    switch (fts_entry->fts_info) {
      case FTS_DNR:
      case FTS_NS:
        /* Warn about the problem, but continue deleting files. */
        warnx("%s: %s", fts_entry->fts_path, strerror(fts_entry->fts_errno));
        result = false;
        break;
      case FTS_ERR:
        /* We consider this a fatal error, i.e. abort processing now. */
        warnx("%s: %s", fts_entry->fts_path, strerror(fts_entry->fts_errno));
        result = false;
        goto out;
      case FTS_D:
        break;
      case FTS_DP:
        if (fts_entry->fts_level > 0 && rmdir(fts_entry->fts_accpath) != 0) {
          warn("%s", fts_entry->fts_accpath);
          result = false;
        }
        break;
      default:
        if (fts_entry->fts_level > 0 && unlink(fts_entry->fts_accpath) != 0) {
          warn("%s", fts_entry->fts_accpath);
          result = false;
        }
        break;
    }
  }

out:
  if (fts_handle)
    fts_close(fts_handle);
  free(fts_argv[0]);
  return result;
}

static bool copy_dir(const char *source,
                     const char *destination,
                     uid_t uid,
                     gid_t gid,
                     const struct stat *sb) {
  if (mkdir(destination, (sb->st_mode) & (~S_IFMT)) != 0)
    return false;

  if (chown(destination, uid, gid) != 0)
    return false;

  if (chmod(destination, (sb->st_mode) & (~S_IFMT)) != 0)
    return false;

  return hardened_shadow_copy_dir_contents(source, destination, uid, gid);
}

static bool copy_symlink(const char *source,
                         const char *destination,
                         uid_t uid,
                         gid_t gid,
                         UNUSED const struct stat *sb) {
  char link_destination[PATH_MAX];

  if (!hardened_shadow_usub_ok(sizeof(link_destination), 1, SIZE_MAX))
    return false;
  ssize_t rv = readlink(source, link_destination, sizeof(link_destination) - 1);
  if (rv == -1)
    return false;

  link_destination[rv] = '\0';
  if (symlink(link_destination, destination) != 0)
    return false;

  if (lchown(destination, uid, gid) != 0)
    return false;

  return true;
}

static bool copy_file(const char *source,
                      const char *destination,
                      uid_t uid,
                      gid_t gid,
                      const struct stat *sb) {
  int source_fd = open(source, O_RDONLY | O_CLOEXEC);
  if (source_fd < 0)
    return false;

  bool result = true;

  int destination_fd = open(destination,
                            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                            (sb->st_mode) & (~S_IFMT));
  if (destination_fd < 0) {
    result = false;
    goto out;
  }

  if (fchown(destination_fd, uid, gid) != 0) {
    result = false;
    goto out;
  }

  if (fchmod(destination_fd, (sb->st_mode) & (~S_IFMT)) != 0) {
    result = false;
    goto out;
  }

  if (!hardened_shadow_copy_file_contents(source_fd, destination_fd)) {
    result = false;
    goto out;
  }

out:
  TEMP_FAILURE_RETRY(close(source_fd));
  if (destination_fd != -1)
    TEMP_FAILURE_RETRY(close(destination_fd));
  return result;
}

static bool copy_special(UNUSED const char *source,
                         const char *destination,
                         uid_t uid,
                         gid_t gid,
                         const struct stat *sb) {
  if (mknod(destination, sb->st_mode, sb->st_rdev) != 0)
    return false;

  if (chown(destination, uid, gid) != 0)
    return false;

  if (chmod(destination, (sb->st_mode) & (~S_IFMT)) != 0)
    return false;

  return true;
}

static bool copy_entry(const char *source,
                       const char *destination,
                       uid_t uid,
                       gid_t gid) {
  struct stat sb;
  if (lstat(source, &sb) != 0)
    return false;

  struct timeval tv[2];
  tv[0].tv_sec = sb.st_atime;
  tv[0].tv_usec = 0;
  tv[1].tv_sec = sb.st_mtime;
  tv[1].tv_usec = 0;

  if (S_ISDIR(sb.st_mode)) {
    if (!copy_dir(source, destination, uid, gid, &sb))
      return false;
  } else if (S_ISLNK(sb.st_mode)) {
    if (!copy_symlink(source, destination, uid, gid, &sb))
      return false;
  } else if (S_ISREG(sb.st_mode)) {
    if (!copy_file(source, destination, uid, gid, &sb))
      return false;
  } else {
    if (!copy_special(source, destination, uid, gid, &sb))
      return false;
  }

  if (lutimes(destination, tv) != 0)
    return false;

  return true;
}

bool hardened_shadow_copy_dir_contents(const char *source,
                                       const char *destination,
                                       uid_t uid,
                                       gid_t gid) {
  if (uid == (uid_t)-1 || gid == (gid_t)-1)
    return false;

  DIR *dir = opendir(source);
  if (!dir)
    return false;

  char *source_path = NULL;
  char *destination_path = NULL;
  bool result = true;

  struct dirent *dirent;
  while ((dirent = readdir(dir))) {
    if (strcmp(dirent->d_name, ".") == 0 ||
        strcmp(dirent->d_name, "..") == 0) {
      continue;
    }

    if (asprintf(&source_path, "%s/%s", source, dirent->d_name) < 0) {
      result = false;
      goto out;
    }

    if (asprintf(&destination_path, "%s/%s", destination, dirent->d_name) < 0) {
      result = false;
      goto out;
    }

    if (!copy_entry(source_path, destination_path, uid, gid)) {
      result = false;
      goto out;
    }

    free(source_path);
    source_path = NULL;

    free(destination_path);
    destination_path = NULL;
  }

out:
  closedir(dir);
  free(source_path);
  free(destination_path);
  return result;
}
