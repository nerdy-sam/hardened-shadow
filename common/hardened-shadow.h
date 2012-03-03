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

#ifndef HARDENED_SHADOW_H
#define HARDENED_SHADOW_H

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

struct group;
struct lastlog;
struct passwd;
struct spwd;

struct hardened_shadow_file_state {
  char *tmp_path;
  FILE *tmp_file;
  FILE *original_file;
  struct stat original_stat;
};

#define HARDENED_SHADOW_ARRAYSIZE(a)                   \
  ((sizeof(a) / sizeof(*(a))) /                 \
   (size_t)(!(sizeof(a) % sizeof(*(a)))))

/* We are not sure what types gid_t, uid_t, off_t really are,
 * so use a very conservative guess. */

#ifndef GID_MAX
#define GID_MAX INT_MAX
#endif

#ifndef UID_MAX
#define UID_MAX INT_MAX
#endif

#ifndef OFF_MAX
#define OFF_MAX INT_MAX
#endif

static inline uintmax_t uintmin(uintmax_t a, uintmax_t b) {
  return (a < b) ? a : b;
}

bool hardened_shadow_read_config(void);
bool hardened_shadow_config_get_bool(const char *key, bool *result);
bool hardened_shadow_config_get_integer(const char *key, intmax_t *result);
bool hardened_shadow_config_get_mode(const char *key, mode_t *result);
bool hardened_shadow_config_get_path(const char *key, const char **result);
bool hardened_shadow_config_get_range(const char *key, intmax_t *minresult, intmax_t *maxresult);

void hardened_shadow_openlog(const char *ident);
void hardened_shadow_syslog(int priority, const char *format, ...) __attribute__((__format__(__printf__, 2, 3)));
void hardened_shadow_closelog(void);

bool hardened_shadow_ucast_ok(intmax_t a, uintmax_t max);
bool hardened_shadow_scast_ok(uintmax_t a, intmax_t max);

bool hardened_shadow_uadd_ok(uintmax_t a, uintmax_t b, uintmax_t max);
bool hardened_shadow_usub_ok(uintmax_t a, uintmax_t b, uintmax_t max);
bool hardened_shadow_umul_ok(uintmax_t a, uintmax_t b, uintmax_t max);

bool hardened_shadow_sadd_ok(intmax_t a, intmax_t b, intmax_t min, intmax_t max);
bool hardened_shadow_ssub_ok(intmax_t a, intmax_t b, intmax_t min, intmax_t max);
bool hardened_shadow_smul_ok(intmax_t a, intmax_t b, intmax_t min, intmax_t max);
bool hardened_shadow_sdiv_ok(intmax_t a, intmax_t b, intmax_t min, intmax_t max);

void *hardened_shadow_calloc(size_t nmemb, size_t size);

bool hardened_shadow_strtonum(const char *numstr, intmax_t minval, intmax_t maxval, intmax_t *result);
bool hardened_shadow_getrange(const char *range, intmax_t minval, intmax_t maxval, intmax_t *minresult, intmax_t *maxresult);
bool hardened_shadow_getday(const char *str, intmax_t* result);

extern const char hardened_shadow_lastlog_header[];

#define HARDENED_SHADOW_LOCKED_PASSWD "!"
#define HARDENED_SHADOW_SHADOW_PASSWD "x"

bool hardened_shadow_get_current_username(char **username);
bool hardened_shadow_getgroups(gid_t **groups, size_t *ngroups);

bool hardened_shadow_get_hardened_shadow_gid(gid_t *result);
bool hardened_shadow_drop_priv(const char *user_name, uid_t uid, gid_t gid);

int hardened_shadow_fd(void);
int hardened_shadow_open_user_directory(const char *username);
int hardened_shadow_open_user_file(int user_subdirectory_fd, char *name, int flags);
void hardened_shadow_close_file_state(struct hardened_shadow_file_state *state);
bool hardened_shadow_begin_rewrite_file(const char *path, struct hardened_shadow_file_state *state);
bool hardened_shadow_end_rewrite_file(const char *path, struct hardened_shadow_file_state *state);
struct group *hardened_shadow_sgetgrent(char *buf);
struct passwd *hardened_shadow_sgetpwent(char *buf);
bool hardened_shadow_replace_file(const char *contents, const char *filename);
bool hardened_shadow_replace_user_file(const char *username, uid_t uid, const char *contents, const char *filename);
bool hardened_shadow_update_group_add_user(const char *user_name, const gid_t *groups, size_t groups_length, bool append);
bool hardened_shadow_update_group_change_user_name(const char *old_name, char *new_name);
bool hardened_shadow_update_passwd_change_gid(gid_t old_gid, gid_t new_gid);
bool hardened_shadow_update_passwd_shell_proxy(void);
bool hardened_shadow_update_passwd_undo_shell_proxy(void);
bool hardened_shadow_replace_passwd(const char *user_name, struct passwd *replacement_pwd);
bool hardened_shadow_replace_group(const char *group_name, struct group *replacement_group);
bool hardened_shadow_create_shadow_entry(const struct passwd *pwd, const struct spwd *spwd, bool system, long inactive_days, long expiredate);

bool hardened_shadow_is_nis_line(const char *line);
bool hardened_shadow_is_valid_username(const char *username);
bool hardened_shadow_is_valid_group_name(const char *group_name);
bool hardened_shadow_is_valid_field_content(const char *content);
bool hardened_shadow_is_valid_login_shell(const char *shell);
bool hardened_shadow_parse_key_value(const char *text, char **key, char **value);
bool hardened_shadow_parse_group_list(const char *text, gid_t **groups, size_t *groups_length);
bool hardened_shadow_string_to_bool(const char *string, bool *result);
bool hardened_shadow_string_to_gid(const char *str, gid_t *result);

struct hardened_shadow_lastlog_handle;
bool hardened_shadow_lastlog_open(struct hardened_shadow_lastlog_handle **handle);
bool hardened_shadow_lastlog_read(struct hardened_shadow_lastlog_handle **handle, uid_t uid, struct lastlog *entry);
bool hardened_shadow_lastlog_close(struct hardened_shadow_lastlog_handle **handle);

bool hardened_shadow_asprintf_lastlog(char **result, const char *username, const struct lastlog *entry);
bool hardened_shadow_asprintf_date(char **result, time_t date);
bool hardened_shadow_asprintf_password_status(char **result, const char *username);
bool hardened_shadow_asprintf_shadow(char **result, const struct spwd *spwd);
bool hardened_shadow_asprintf_aging(char **result, const struct spwd *spwd);

struct environment_options {
  char **pam_environment;
  bool preserve_environment;
  bool login_shell;
  const char *target_username;
  const char *target_homedir;
  const char *target_shell;
};

bool hardened_shadow_prepare_environment(const struct environment_options *options);
bool hardened_shadow_closefrom(int lowfd);
bool hardened_shadow_flush_nscd(const char *database);

ssize_t hardened_shadow_write(int fd, const char *data, size_t size);
ssize_t hardened_shadow_read(int fd, char *data, size_t size);
bool hardened_shadow_read_contents(int fd, char **contents, size_t *length);
bool hardened_shadow_copy_file_contents(int in_fd, int out_fd);
bool hardened_shadow_getline(FILE* stream, char **result);

bool hardened_shadow_starts_with(const char *text, const char *prefix);

bool hardened_shadow_allocate_gid(gid_t min, gid_t max, gid_t *gid);

bool hardened_shadow_dup_passwd(const struct passwd *pwd, struct passwd *copy);
void hardened_shadow_free_passwd_contents(struct passwd *copy);

bool hardened_shadow_interactive_confirm(const char *prompt);
bool hardened_shadow_interactive_prompt(const char *prompt, const char *default_value, char **result);

bool hardened_shadow_remove_dir_contents(const char *path);
bool hardened_shadow_copy_dir_contents(const char *source, const char *destination, uid_t uid, gid_t gid);

bool hardened_shadow_pwck_passwd(bool read_only, bool quiet);
bool hardened_shadow_grpck(bool read_only);

#endif /* HARDENED_SHADOW_H */
