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
#include "hardened-shadow.h"

#include <errno.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utmp.h>

struct hardened_shadow_lastlog_handle {
  FILE *file;
  struct stat stat;
};

bool hardened_shadow_lastlog_open(struct hardened_shadow_lastlog_handle **handle) {
  *handle = malloc(sizeof(**handle));
  if (!*handle)
    return false;
  do {
    (*handle)->file = fopen(_PATH_LASTLOG, "re");
  } while (!(*handle)->file && errno == EINTR);
  if (!(*handle)->file) {
    free(*handle);
    *handle = NULL;
    return false;
  }
  if (fstat(fileno((*handle)->file), &(*handle)->stat) != 0) {
    fclose((*handle)->file);
    free(*handle);
    *handle = NULL;
    return false;
  }

  return true;
}

bool hardened_shadow_lastlog_read(struct hardened_shadow_lastlog_handle **handle, uid_t uid, struct lastlog *entry) {
  memset(entry, 0, sizeof(*entry));

  if (!hardened_shadow_umul_ok(uid, sizeof(*entry), SIZE_MAX))
    return false;
  size_t offset = uid * sizeof(*entry);

  if (!hardened_shadow_usub_ok((*handle)->stat.st_size, sizeof(*entry), SIZE_MAX))
    return false;
  size_t offset_max = (*handle)->stat.st_size - sizeof(*entry);

  if (offset <= offset_max) {
    if (!hardened_shadow_scast_ok(offset, OFF_MAX))
      return false;
    if (fseeko((*handle)->file, (off_t)offset, SEEK_SET) != 0)
      return false;
    if (fread(entry, sizeof(*entry), 1, (*handle)->file) != 1)
      return false;
  }

  return true;
}

bool hardened_shadow_lastlog_close(struct hardened_shadow_lastlog_handle **handle) {
  if (TEMP_FAILURE_RETRY(fclose((*handle)->file)) != 0)
    return false;
  free(*handle);
  *handle = NULL;
  return true;
}
