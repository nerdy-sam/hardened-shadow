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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum entry_type {
  BOOL,
  INTEGER,
  MODE,
  PATH,
  RANGE
};

struct config_entry {
  const char *key;
  char *value;
  const enum entry_type type;
  const intmax_t min;
  const intmax_t max;
};

struct config_entry config_entries[] = {
  { "CREATE_HOME", "yes", BOOL, -1, -1 },
  { "USER_PRIVATE_GROUPS", "yes", BOOL, -1, -1 },
  { "PASS_MIN_DAYS", "0", INTEGER, 0, LONG_MAX },
  { "PASS_MAX_DAYS", "99999", INTEGER, 0, LONG_MAX },
  { "PASS_WARN_AGE", "7", INTEGER, 0, LONG_MAX },
  { "HOME_DIRECTORY_MODE", "0755", MODE, -1, -1 },
  { "MAIL_DIRECTORY", "/var/mail", PATH, -1, -1 },
  { "USERDEL_COMMAND", "/bin/true", PATH, -1, -1 },
  { "USER_UID_RANGE", "1000-60000", RANGE, 0, INTMAX_MAX },
  { "SYSTEM_UID_RANGE", "101-999", RANGE, 0, INTMAX_MAX },
  { "USER_GID_RANGE", "1000-60000", RANGE, 0, INTMAX_MAX },
  { "SYSTEM_GID_RANGE", "101-999", RANGE, 0, INTMAX_MAX },
};

static bool validate_config_entry(const struct config_entry *entry) {
  switch (entry->type) {
    case BOOL: {
      bool b;
      return hardened_shadow_string_to_bool(entry->value, &b);
    }
    case INTEGER: {
      intmax_t a;
      if (!hardened_shadow_strtonum(entry->value, INTMAX_MIN, INTMAX_MAX, &a))
        return false;
      return (a >= entry->min && a <= entry->max);
    }
    case MODE:
      return (strspn(entry->value, "01234567") == strlen(entry->value));
    case PATH:
      return (access(entry->value, F_OK) == 0);
    case RANGE: {
      intmax_t a, b;
      if (!hardened_shadow_getrange(entry->value, INTMAX_MIN, INTMAX_MAX, &a, &b))
        return false;
      return (a <= b && a >= entry->min && b <= entry->max);
    }
    default:
      return false;
  }
}

static bool validate_config_entries(void) {
  bool valid = true;
  for (size_t i = 0; i < HARDENED_SHADOW_ARRAYSIZE(config_entries); i++) {
    if (!validate_config_entry(&config_entries[i])) {
      warnx("invalid value for key '%s': '%s'", config_entries[i].key, config_entries[i].value);
      valid = false;
    }
  }
  return valid;
}

bool hardened_shadow_read_config(void) {
  if (!validate_config_entries()) {
    warnx("internal error: default config is invalid");
    return false;
  }

  FILE *file = fopen("/etc/hardened-shadow.conf", "re");
  if (!file) {
    warn("failed to open configuration file");
    return false;
  }

  bool result = true;

  char *line = NULL;
  while (hardened_shadow_getline(file, &line)) {
    /* Skip empty and comment lines. */
    if (*line == '\0')
      continue;
    if (hardened_shadow_starts_with(line, "#"))
      continue;

    char *key = NULL;
    char *value = NULL;
    if (!hardened_shadow_parse_key_value(line, &key, &value)) {
      warnx("failed to parse config line '%s'", line);
      result = false;
      goto out;
    }

    bool found = false;
    for (size_t i = 0; i < HARDENED_SHADOW_ARRAYSIZE(config_entries); i++) {
      if (strcmp(key, config_entries[i].key) != 0)
        continue;

      found = true;
      config_entries[i].value = value;
      break;
    }

    if (!found) {
      warnx("invalid key '%s'", key);
      result = false;
      goto out;
    }

    free(key);

    /* Note: value is now used in config_entries. */
  }
  if (!validate_config_entries()) {
    result = false;
    goto out;
  }
  if (!feof(file)) {
    warnx("I/O error when reading from configuration file");
    result = false;
    goto out;
  }

out:
  TEMP_FAILURE_RETRY(fclose(file));
  return result;
}

bool hardened_shadow_config_get_bool(const char *key, bool *result) {
  for (size_t i = 0; i < HARDENED_SHADOW_ARRAYSIZE(config_entries); i++) {
    if (strcmp(key, config_entries[i].key) != 0)
      continue;

    if (config_entries[i].type != BOOL)
      return false;
    return hardened_shadow_string_to_bool(config_entries[i].value, result);
  }

  return false;
}

bool hardened_shadow_config_get_integer(const char *key, intmax_t *result) {
  for (size_t i = 0; i < HARDENED_SHADOW_ARRAYSIZE(config_entries); i++) {
    if (strcmp(key, config_entries[i].key) != 0)
      continue;

    if (config_entries[i].type != INTEGER)
      return false;
    return hardened_shadow_strtonum(config_entries[i].value, config_entries[i].min, config_entries[i].max, result);
  }

  return false;
}

bool hardened_shadow_config_get_mode(const char *key, mode_t *result) {
  for (size_t i = 0; i < HARDENED_SHADOW_ARRAYSIZE(config_entries); i++) {
    if (strcmp(key, config_entries[i].key) != 0)
      continue;

    if (config_entries[i].type != MODE)
      return false;

    sscanf(config_entries[i].value, "%o", result);
    return true;
  }

  return false;
}

bool hardened_shadow_config_get_path(const char *key, const char **result) {
  for (size_t i = 0; i < HARDENED_SHADOW_ARRAYSIZE(config_entries); i++) {
    if (strcmp(key, config_entries[i].key) != 0)
      continue;

    if (config_entries[i].type != PATH)
      return false;
    *result = config_entries[i].value;
    return true;
  }

  return false;
}

bool hardened_shadow_config_get_range(const char *key, intmax_t *minresult, intmax_t *maxresult) {
  for (size_t i = 0; i < HARDENED_SHADOW_ARRAYSIZE(config_entries); i++) {
    if (strcmp(key, config_entries[i].key) != 0)
      continue;

    if (config_entries[i].type != RANGE)
      return false;
    return hardened_shadow_getrange(config_entries[i].value, config_entries[i].min, config_entries[i].max, minresult, maxresult);
  }

  return false;
}
