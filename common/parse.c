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

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <utmp.h>

static const char VALID_NAME_FIRST_CHARACTERS[] = "abcdefghijklmnopqrstuvwxyz_";
static const char VALID_NAME_CHARACTERS[]       = "abcdefghijklmnopqrstuvwxyz_-0123456789";
static const char VALID_FIELD_CHARACTERS[]      = "abcdefghijklmnopqrstuvwxyz_-0123456789/., ";

static bool is_valid_name(const char *name) {
  size_t length = strlen(name);
  if (length == 0)
    return false;

  if (strspn(name, VALID_NAME_FIRST_CHARACTERS) < 1)
    return false;

  return strspn(name, VALID_NAME_CHARACTERS) == length;
}

bool hardened_shadow_is_valid_field_content(const char *content) {
  return (strspn(content, VALID_FIELD_CHARACTERS) == strlen(content));
}

bool hardened_shadow_is_valid_user_name(const char *user_name) {
  size_t length = strlen(user_name);
  if (length == 0 || length > UT_NAMESIZE)
    return false;

  return is_valid_name(user_name);
}

bool hardened_shadow_is_valid_group_name(const char *group_name) {
  if (*group_name == '\0')
    return false;
  return is_valid_name(group_name);
}

bool hardened_shadow_is_valid_login_shell(const char *shell) {
  bool found = false;
  char *line;

  setusershell();
  while ((line = getusershell()) != NULL) {
    if (('#' != *line) && (strcmp(line, shell) == 0)) {
      found = true;
      break;
    }
  }
  endusershell();

  return found;
}

bool hardened_shadow_parse_key_value(const char *text, char **key, char **value) {
  *key = *value = NULL;

  char *dup = strdup(text);
  if (!dup)
    return false;

  bool result = true;

  char *pos = strchr(dup, '=');
  if (!pos) {
    result = false;
    goto out;
  }

  *value = strdup(pos + 1);
  if (!*value) {
    result = false;
    goto out;
  }

  *pos = '\0';
  *key = strdup(dup);
  if (!*key) {
    result = false;
    goto out;
  }

out:
  free(dup);
  if (!result) {
    free(*key);
    free(*value);
  }
  return result;
}

/* Converts a comma-separated list of group names or GIDs to an array of gids. */
bool hardened_shadow_parse_group_list(const char *text,
                                      gid_t **groups,
                                      size_t *groups_length) {
  long ngroups_max_sysconf = sysconf(_SC_NGROUPS_MAX);
  if (ngroups_max_sysconf < 1)
    return false;

  size_t ngroups_max = SIZE_MAX;
  if (hardened_shadow_ucast_ok(ngroups_max_sysconf, SIZE_MAX))
    ngroups_max = (size_t)ngroups_max_sysconf;

  *groups = hardened_shadow_calloc(ngroups_max, sizeof(**groups));
  if (!*groups)
    return false;

  bool result = true;

  char *tmp = strdup(text);
  if (!tmp) {
    result = false;
    goto out;
  }

  *groups_length = 0;

  char *token = strtok(tmp, ",");
  while (token) {
    if (*groups_length > ngroups_max) {
      result = false;
      goto out;
    }

    if (!hardened_shadow_string_to_gid(token, &((*groups)[*groups_length]))) {
      result = false;
      goto out;
    }

    (*groups_length)++;
    token = strtok(NULL, ",");
  }

out:
  free(tmp);
  if (!result) {
    free(*groups);
    *groups = NULL;
  }
  return result;
}

bool hardened_shadow_string_to_bool(const char *string, bool *result) {
  if (strcasecmp(string, "yes") == 0) {
    *result = true;
    return true;
  }

  if (strcasecmp(string, "no") == 0) {
    *result = false;
    return true;
  }

  return false;
}

bool hardened_shadow_string_to_gid(const char *str, gid_t *result) {
  struct group *gr = getgrnam(str);
  if (gr) {
    *result = gr->gr_gid;
    return true;
  }

  intmax_t num = -1;
  if (!hardened_shadow_strtonum(str, 0, GID_MAX, &num))
    return false;

  *result = num;
  return true;
}

bool hardened_shadow_strtonum(const char *numstr,
                              intmax_t minval,
                              intmax_t maxval,
                              intmax_t *result) {
  if (minval > maxval)
    return false;

  errno = 0;
  char *ep = NULL;
  intmax_t imax = strtoimax(numstr, &ep, 0);
  if (numstr == ep ||
      *ep != '\0' ||
      errno != 0 ||
      imax < minval ||
      imax > maxval) {
    return false;
  }

  *result = imax;
  return true;
}

bool hardened_shadow_getrange(const char *range,
                              intmax_t minval,
                              intmax_t maxval,
                              intmax_t *minresult,
                              intmax_t *maxresult) {
  if (minval > maxval)
    return false;

  char *dup_range = strdup(range);
  if (!dup_range)
    return false;

  bool result = true;

  char *delim = strchr(dup_range, '-');
  if (!delim) {
    result = false;
    goto out;
  }

  if (delim == dup_range) {
    *minresult = minval;
  } else {
    *delim = '\0';
    if (!hardened_shadow_strtonum(dup_range, minval, maxval, minresult)) {
      result = false;
      goto out;
    }
  }

  if (*(delim + 1) == '\0') {
    *maxresult = maxval;
  } else {
    if (!hardened_shadow_strtonum(delim + 1, minval, maxval, maxresult)) {
      result = false;
      goto out;
    }
  }

out:
  free(dup_range);
  return result;
}

bool hardened_shadow_getday(const char *str, intmax_t *result) {
  struct tm tp;
  memset(&tp, '\0', sizeof(tp));

  char *cp = strptime(str, "%Y-%m-%d", &tp);
  if (!cp || cp[0] != '\0')
    return false;

  time_t rv = mktime(&tp);
  if (rv == -1)
    return false;

  *result = rv / (60 * 60 * 24);
  return true;
}
