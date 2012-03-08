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

#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <lastlog.h>
#include <limits.h>
#include <pwd.h>
#include <shadow.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "hardened-shadow.h"

static void usage(void) {
  fputs("Usage: useradd [options] LOGIN\n"
        "\n"
        "Options:\n"
        "  -b, --base-dir BASE_DIR       base directory for the home directory of the\n"
        "                                new account\n"
	"  -c, --comment COMMENT         GECOS field of the new account\n"
	"  -d, --home-dir HOME_DIR       home directory of the new account\n"
	"  -D, --defaults                print or change default useradd configuration\n"
	"  -e, --expiredate EXPIRE_DATE  expiration date of the new account\n"
	"  -f, --inactive INACTIVE       password inactivity period of the new account\n"
	"  -g, --gid GROUP               name or ID of the primary group of the new\n"
        "                                account\n"
	"  -G, --groups GROUPS           list of supplementary groups of the new\n"
        "                                account\n"
	"  -h, --help                    display this help message and exit\n"
	"  -k, --skel SKEL_DIR           use this alternative skeleton directory\n"
	"  -l, --no-log-init             do not add the user to the lastlog database\n"
	"  -m, --create-home             create the user's home directory\n"
	"  -M, --no-create-home          do not create the user's home directory\n"
	"  -N, --no-user-group           do not create a group with the same name as\n"
        "                                the user\n"
	"  -o, --non-unique              allow to create users with duplicate\n"
        "                                (non-unique) UID\n"
	"  -p, --password PASSWORD       encrypted password of the new account\n"
	"  -r, --system                  create a system account\n"
	"  -s, --shell SHELL             login shell of the new account\n"
	"  -u, --uid UID                 user ID of the new account\n"
	"  -U, --user-group              create a group with the same name as the user\n"
	"\n", stderr);
  exit(EXIT_FAILURE);
}

#define DEFAULTS_FILE ("/etc/default/useradd")
#define FLAG_NOT_SET (-2)

static const char *flag_base_dir = NULL;
static char *flag_comment = NULL;
static const char *flag_home_dir = NULL;
static bool flag_defaults = false;
static intmax_t flag_expiredate = FLAG_NOT_SET;
static intmax_t flag_inactive = FLAG_NOT_SET;
static const char* flag_gid = NULL;
static const char* flag_groups = NULL;
static const char *flag_skel = NULL;
static bool flag_no_log_init = false;
static bool flag_create_home = false;
static bool flag_no_create_home = false;
static bool flag_no_user_group = false;
static bool flag_non_unique = false;
static const char *flag_password = NULL;
static bool flag_system = false;
static char *flag_shell = NULL;
static intmax_t flag_uid = FLAG_NOT_SET;
static bool flag_user_group = false;

static char *user_name = NULL;
static uid_t user_uid = -1;
static gid_t user_gid = -1;
static gid_t *user_groups = NULL;
static size_t user_ngroups = 0;
static char *user_home_dir = NULL;

static char *default_gid = NULL;
static char *default_home_dir = NULL;
static char *default_shell = NULL;
static intmax_t default_inactive = -1;
static intmax_t default_expiredate = -1;
static char *default_skel = NULL;
static bool default_create_mail_spool = false;

static void parse_args(int argc, char **argv) {
  static struct option long_options[] = {
    {"base-dir", required_argument, NULL, 'b'},
    {"comment", required_argument, NULL, 'c'},
    {"home-dir", required_argument, NULL, 'd'},
    {"defaults", no_argument, NULL, 'D'},
    {"expiredate", required_argument, NULL, 'e'},
    {"inactive", required_argument, NULL, 'f'},
    {"gid", required_argument, NULL, 'g'},
    {"groups", required_argument, NULL, 'G'},
    {"help", no_argument, NULL, 'h'},
    {"skel", required_argument, NULL, 'k'},
    {"create-home", no_argument, NULL, 'm'},
    {"no-create-home", no_argument, NULL, 'M'},
    {"no-log-init", no_argument, NULL, 'l'},
    {"no-user-group", no_argument, NULL, 'N'},
    {"non-unique", no_argument, NULL, 'o'},
    {"password", required_argument, NULL, 'p'},
    {"system", no_argument, NULL, 'r'},
    {"shell", required_argument, NULL, 's'},
    {"uid", required_argument, NULL, 'u'},
    {"user-group", no_argument, NULL, 'U'},
    {NULL, 0, NULL, '\0'}
  };

  int c;
  while ((c = getopt_long(argc, argv, "b:c:d:De:f:g:G:k:lmMNop:rs:u:U",
                          long_options, NULL)) != -1) {
    switch (c) {
      case 'b':
        if (!hardened_shadow_is_valid_field_content(optarg) || optarg[0] != '/')
          errx(EXIT_FAILURE, "invalid base directory '%s'", optarg);
        flag_base_dir = optarg;
        break;
      case 'c':
        if (!hardened_shadow_is_valid_field_content(optarg))
          errx(EXIT_FAILURE, "invalid comment '%s'", optarg);
        flag_comment = optarg;
        break;
      case 'd':
        if (!hardened_shadow_is_valid_field_content(optarg) || optarg[0] != '/')
          errx(EXIT_FAILURE, "invalid home directory '%s'", optarg);
        flag_home_dir = optarg;
        break;
      case 'D':
        flag_defaults = true;
        break;
      case 'e':
        if (optarg[0] == '\0')
          flag_expiredate = -1;
        else if (!hardened_shadow_getday(optarg, &flag_expiredate))
          errx(EXIT_FAILURE, "invalid date '%s'", optarg);
        break;
      case 'f':
        if (!hardened_shadow_strtonum(optarg, -1, INTMAX_MAX, &flag_inactive))
          errx(EXIT_FAILURE, "invalid numeric argument '%s'", optarg);
        break;
      case 'g':
        flag_gid = optarg;
        break;
      case 'G':
        flag_groups = optarg;
        if (!hardened_shadow_parse_group_list(flag_groups, &user_groups,
                                              &user_ngroups)) {
          errx(EXIT_FAILURE, "invalid group list '%s'", flag_groups);
        }
        break;
      case 'h':
        usage();
        break;
      case 'k':
        flag_skel = optarg;
        break;
      case 'l':
        flag_no_log_init = true;
        break;
      case 'm':
        flag_create_home = true;
        break;
      case 'M':
        flag_no_create_home = true;
        break;
      case 'N':
        flag_no_user_group = true;
        break;
      case 'o':
        flag_non_unique = true;
        break;
      case 'p':
        flag_password = optarg;
        break;
      case 'r':
        flag_system = true;
        break;
      case 's':
        if (!hardened_shadow_is_valid_field_content(optarg) || optarg[0] != '/')
          errx(EXIT_FAILURE, "invalid shell '%s'", optarg);
        flag_shell = optarg;
        break;
      case 'u':
        if (!hardened_shadow_strtonum(optarg, 0, UID_MAX, &flag_uid))
          errx(EXIT_FAILURE, "invalid user ID '%s'", optarg);
        break;
      case 'U':
        flag_user_group = true;
        break;
      default:
        usage();
    }
  }

  if (!flag_gid && !flag_no_user_group && !flag_user_group) {
    if (!hardened_shadow_config_get_bool("USER_PRIVATE_GROUPS",
                                         &flag_user_group)) {
      errx(EXIT_FAILURE, "failed to retrieve USER_PRIVATE_GROUPS setting");
    }
  }

  if (flag_non_unique && flag_uid == FLAG_NOT_SET)
    errx(EXIT_FAILURE, "-o flag is only allowed with the -u flag");
  if (flag_skel && !flag_create_home)
    errx(EXIT_FAILURE, "-k flag is only allowed with the -m flag");
  if (flag_user_group && flag_gid)
    errx(EXIT_FAILURE, "options -U and -g conflict");
  if (flag_user_group && flag_no_user_group)
    errx(EXIT_FAILURE, "options -U and -N conflict");
  if (flag_create_home && flag_no_create_home)
    errx(EXIT_FAILURE, "options -m and -M conflict");

  if (flag_defaults) {
    if (optind != argc)
      usage();

    if (flag_uid ||
        flag_non_unique ||
        flag_groups ||
        flag_home_dir ||
        flag_comment ||
        flag_create_home) {
      usage();
    }
  } else {
    if (optind != argc - 1)
      usage();

    user_name = argv[optind];
    if (getpwnam(user_name))
      errx(EXIT_FAILURE, "user '%s' already exists", user_name);
    if (!hardened_shadow_is_valid_user_name(user_name))
      errx(EXIT_FAILURE, "invalid user name '%s'", user_name);

    if (flag_home_dir) {
      user_home_dir = strdup(flag_home_dir);
      if (!user_home_dir)
        errx(EXIT_FAILURE, "memory allocation failure");
    } else {
      if (asprintf(&user_home_dir, "%s/%s", default_home_dir, user_name) < 0)
        errx(EXIT_FAILURE, "memory allocation failure");
    }
  }


  if (flag_expiredate == FLAG_NOT_SET)
    flag_expiredate = default_expiredate;

  if (!flag_gid)
    flag_gid = default_gid;
  if (!hardened_shadow_string_to_gid(flag_gid, &user_gid))
    errx(EXIT_FAILURE, "group '%s' does not exist", flag_gid);

  if (!flag_shell)
    flag_shell = (flag_system) ? "/sbin/nologin" : default_shell;

  if (!flag_system) {
    if (!hardened_shadow_config_get_bool("CREATE_HOME", &flag_create_home))
      errx(EXIT_FAILURE, "failed to retrieve default setting for the -m flag");
  }

  if (flag_no_create_home)
    flag_create_home = false;

  if (flag_user_group && getgrnam(user_name)) {
    errx(EXIT_FAILURE,
         "group %s exists - "
         "if you want to add this user to that group, use -g.",
         user_name);
  }
}

static bool read_defaults_file(void) {
  bool result = true;

  FILE *defaults_file = fopen(DEFAULTS_FILE, "re");
  if (!defaults_file) {
    warn("fopen");
    result = false;
  }

  if (defaults_file) {
    char *defaults_line = NULL;
    while (hardened_shadow_getline(defaults_file, &defaults_line)) {
      /* Skip empty and comment lines. */
      if (*defaults_line == '\0')
        continue;
      if (hardened_shadow_starts_with(defaults_line, "#"))
        continue;

      char *key = NULL;
      char *value = NULL;
      if (!hardened_shadow_parse_key_value(defaults_line, &key, &value))
        errx(EXIT_FAILURE, "failed to parse defaults line '%s'", defaults_line);

      if (strcmp("GROUP", key) == 0) {
        default_gid = value;
      } else if (strcmp("HOME", key) == 0) {
        default_home_dir = value;
      } else if (strcmp("SHELL", key) == 0) {
        default_shell = value;
      } else if (strcmp("INACTIVE", key) == 0) {
        if (!hardened_shadow_strtonum(value, -1, INTMAX_MAX, &default_inactive))
          errx(EXIT_FAILURE, "invalid numeric argument '%s'", defaults_line);
        free(value);
      } else if (strcmp("EXPIRE", key) == 0) {
        if (value[0] != '\0' &&
            !hardened_shadow_getday(value, &default_expiredate)) {
          errx(EXIT_FAILURE, "invalid date '%s'", defaults_line);
        }
        free(value);
      } else if (strcmp("SKEL", key) == 0) {
        default_skel = value;
      } else if (strcmp("CREATE_MAIL_SPOOL", key) == 0) {
        if (!hardened_shadow_string_to_bool(value, &default_create_mail_spool))
          errx(EXIT_FAILURE, "invalid boolean argument '%s'", defaults_line);
        free(value);
      } else {
        errx(EXIT_FAILURE, "unrecognized default '%s'", defaults_line);
      }

      free(key);
    }
    if (!feof(defaults_file)) {
      result = false;
      goto out;
    }
  }

  /* Set variables not mentioned in the file to their hardcoded defaults. */

  if (!default_gid) {
    default_gid = strdup("100");
    if (!default_gid)
      errx(EXIT_FAILURE, "memory allocation failure");
  }
  if (!default_home_dir) {
    default_home_dir = strdup("/home");
    if (!default_home_dir)
      errx(EXIT_FAILURE, "memory allocation failure");
  }
  if (!default_shell) {
    default_shell = strdup(HARDENED_SHADOW_DEFAULT_SHELL);
    if (!default_shell)
      errx(EXIT_FAILURE, "memory allocation failure");
  }
  if (!default_skel) {
    default_skel = strdup("/etc/skel");
    if (!default_skel)
      errx(EXIT_FAILURE, "memory allocation failure");
  }

out:
  if (defaults_file)
    TEMP_FAILURE_RETRY(fclose(defaults_file));
  return result;
}

static bool show_defaults(void) {
  printf("GROUP=%s\n", default_gid);
  printf("HOME=%s\n", default_home_dir);
  printf("INACTIVE=%lld\n", default_inactive);
  printf("EXPIRE=%lld\n", default_expiredate);
  printf("SHELL=%s\n", default_shell);
  printf("SKEL=%s\n", default_skel);
  printf("CREATE_MAIL_SPOOL=%s\n", default_create_mail_spool ? "yes" : "no");
  return true;
}

static bool set_defaults(void) {
  char *output_buffer = NULL;
  size_t buffer_size;
  FILE *output_stream = open_memstream(&output_buffer, &buffer_size);
  if (!output_stream) {
    err(EXIT_FAILURE, "open_memstream");
    return false;
  }

  long long inactive;
  if (flag_inactive == FLAG_NOT_SET)
    inactive = default_inactive;
  else
    inactive = flag_inactive;

  long long expiredate;
  if (flag_expiredate == FLAG_NOT_SET)
    expiredate = default_expiredate;
  else
    expiredate = flag_expiredate;

  bool result = true;

  bool written_group = false;
  bool written_home = false;
  bool written_shell = false;
  bool written_inactive = false;
  bool written_expiredate = false;
  bool written_skel = false;

  FILE *defaults_file = fopen(DEFAULTS_FILE, "re");
  if (defaults_file) {
    char *defaults_line = NULL;
    while (hardened_shadow_getline(defaults_file, &defaults_line)) {
      if (hardened_shadow_starts_with(defaults_line, "GROUP=")) {
        if (fprintf(output_stream, "GROUP=%s\n",
                    flag_gid ? flag_gid : default_gid) < 0) {
          warn("fprintf");
          result = false;
          goto out;
        }
        written_group = true;
      } else if (hardened_shadow_starts_with(defaults_line, "HOME=")) {
        if (fprintf(output_stream, "HOME=%s\n",
                    flag_base_dir ? flag_base_dir : default_home_dir) < 0) {
          warn("fprintf");
          result = false;
          goto out;
        }
        written_home = true;
      } else if (hardened_shadow_starts_with(defaults_line, "SHELL=")) {
        if (fprintf(output_stream, "SHELL=%s\n",
                    flag_shell ? flag_shell : default_shell) < 0) {
          warn("fprintf");
          result = false;
          goto out;
        }
        written_shell = true;
      } else if (hardened_shadow_starts_with(defaults_line, "INACTIVE=")) {
        if (fprintf(output_stream, "INACTIVE=%lld\n", inactive) < 0) {
          warn("fprintf");
          result = false;
          goto out;
        }
        written_inactive = true;
      } else if (hardened_shadow_starts_with(defaults_line, "EXPIRE=")) {
        int rc = -1;
        if (expiredate == -1)
          rc = fprintf(output_stream, "EXPIRE=\n");
        else
          rc = fprintf(output_stream, "EXPIRE=%lld\n", expiredate);
        if (rc < 0) {
          warn("fprintf");
          result = false;
          goto out;
        }
        written_expiredate = true;
      } else if (hardened_shadow_starts_with(defaults_line, "SKEL=")) {
        if (fprintf(output_stream, "SKEL=%s\n",
                    flag_skel ? flag_skel : default_skel) < 0) {
          warn("fprintf");
          result = false;
          goto out;
        }
        written_skel = true;
      } else if (fprintf(output_stream, "%s\n", defaults_line) < 0) {
        warn("fprintf");
        result = false;
        goto out;
      }
    }
    if (!feof(defaults_file)) {
      warnx("!feof");
      result = false;
      goto out;
    }
  }
  if (!written_group &&
      fprintf(output_stream, "GROUP=%s\n",
              flag_gid ? flag_gid : default_gid) < 0) {
    warn("fprintf");
    result = false;
    goto out;
  }
  if (!written_home &&
      fprintf(output_stream, "HOME=%s\n",
              flag_base_dir ? flag_base_dir : default_home_dir) < 0) {
    warn("fprintf");
    result = false;
    goto out;
  }
  if (!written_shell &&
      fprintf(output_stream, "SHELL=%s\n",
              flag_shell ? flag_shell : default_shell) < 0) {
    warn("fprintf");
    result = false;
    goto out;
  }
  if (!written_inactive &&
      fprintf(output_stream, "INACTIVE=%lld\n", inactive) < 0) {
    warn("fprintf");
    result = false;
    goto out;
  }
  if (!written_expiredate) {
    int rc = -1;
    if (expiredate == -1)
      rc = fprintf(output_stream, "EXPIRE=\n");
    else
      rc = fprintf(output_stream, "EXPIRE=%lld\n", expiredate);
    if (rc < 0) {
      warn("fprintf");
      result = false;
      goto out;
    }
  }
  if (!written_skel &&
      fprintf(output_stream, "SKEL=%s\n",
              flag_skel ? flag_skel : default_skel) < 0) {
    warn("fprintf");
    result = false;
    goto out;
  }

  TEMP_FAILURE_RETRY(fclose(output_stream));
  output_stream = NULL;

  if (!hardened_shadow_replace_file(output_buffer, DEFAULTS_FILE)) {
    warnx("hardened_shadow_replace_file failed");
    result = false;
    goto out;
  }

  hardened_shadow_syslog(LOG_INFO,
                         "useradd defaults: GROUP=%s, HOME=%s, "
                         "INACTIVE=%lld, EXPIRE=%lld, SHELL=%s, SKEL=%s, "
                         "CREATE_MAIL_SPOOL=%s",
                         default_gid,
                         default_home_dir,
                         default_inactive,
                         default_expiredate,
                         default_shell,
                         default_skel,
                         default_create_mail_spool ? "yes" : "no");

out:
  if (defaults_file)
    TEMP_FAILURE_RETRY(fclose(defaults_file));
  if (output_stream)
    TEMP_FAILURE_RETRY(fclose(output_stream));
  return result;
}

static bool handle_flag_defaults(void) {
  if (flag_gid ||
      flag_base_dir ||
      flag_inactive != FLAG_NOT_SET ||
      flag_expiredate != FLAG_NOT_SET ||
      flag_shell) {
    return set_defaults();
  } else {
    return show_defaults();
  }
}

static bool get_first_free_uid(uid_t min, uid_t max, uid_t *uid) {
  if (min > max)
    return false;
  for (uid_t i = min; i <= max; i++) {
    if (!getpwuid(i)) {
      *uid = i;
      return true;
    }
  }
  return false;
}

static bool allocate_uid(uid_t min, uid_t max, uid_t *uid) {
  if (min > max)
    return false;
  uid_t candidate = min;
  setpwent();
  struct passwd *pwd = NULL;
  while ((pwd = getpwent())) {
    if (pwd->pw_uid >= candidate) {
      candidate = pwd->pw_uid + 1;
      if (candidate > max)
        return get_first_free_uid(min, max, uid);
    }
  }
  endpwent();

  *uid = candidate;
  return true;
}

static void determine_uid_gid(void) {
  if (flag_non_unique) {
    user_uid = flag_uid;
  } else {
    if (flag_uid == FLAG_NOT_SET) {
      const char *key = (flag_system) ? "SYSTEM_UID_RANGE" : "USER_UID_RANGE";
      intmax_t uid_min, uid_max;
      if (!hardened_shadow_config_get_range(key, &uid_min, &uid_max))
        errx(EXIT_FAILURE, "Failed to retrieve UID range.");
      if (!allocate_uid(uid_min, uid_max, &user_uid))
        errx(EXIT_FAILURE, "Failed to allocate UID.");
    } else {
      if (getpwuid(flag_uid))
        errx(EXIT_FAILURE, "UID %ju is not unique", (uintmax_t)flag_uid);

      user_uid = flag_uid;
    }
  }

  if (flag_user_group) {
    const char *gid_key = (flag_system) ? "SYSTEM_GID_RANGE" : "USER_GID_RANGE";
    intmax_t gid_min, gid_max;
    if (!hardened_shadow_config_get_range(gid_key, &gid_min, &gid_max))
      errx(EXIT_FAILURE, "Failed to retrieve GID range.");

    if (user_uid < gid_min || user_uid > gid_max) {
      errx(EXIT_FAILURE,
           "User UID is not within valid GID range %ju vs. (%ju-%ju)",
           (uintmax_t)user_uid, (uintmax_t)gid_min, (uintmax_t)gid_max);
    }

    if (getgrgid(user_uid)) {
      if (!hardened_shadow_allocate_gid(gid_min, gid_max, &user_gid))
        errx(EXIT_FAILURE, "Failed to allocate GID.");
    } else {
      user_gid = user_uid;
    }

    char *group_members[] = { user_name, NULL };

    struct group grp;
    grp.gr_name = user_name;
    grp.gr_passwd = HARDENED_SHADOW_SHADOW_PASSWD;
    grp.gr_gid = user_gid;
    grp.gr_mem = group_members;

    if (!hardened_shadow_replace_group(user_name, &grp))
      errx(EXIT_FAILURE, "hardened_shadow_replace_group failed");

    hardened_shadow_syslog(LOG_INFO, "new group: name=%s, GID=%ju",
                           grp.gr_name, (uintmax_t)grp.gr_gid);
  }
}

static void initialize_lastlog(void) {
  struct lastlog lastlog_entry;
  memset(&lastlog_entry, '\0', sizeof(lastlog_entry));

  int fd = open(_PATH_LASTLOG, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    /* Ignore "file does not exist" errors. */
    if (errno == ENOENT)
      return;

    err(EXIT_FAILURE, "open");
  }

  if (!hardened_shadow_umul_ok(sizeof(lastlog_entry), user_uid, OFF_MAX))
    errx(EXIT_FAILURE, "integer overflow detected");
  off_t offset = sizeof(lastlog_entry) * user_uid;

  if (lseek(fd, offset, SEEK_SET) != offset)
    err(EXIT_FAILURE, "lseek");
  if (hardened_shadow_write(fd, (const char *)&lastlog_entry,
                            sizeof(lastlog_entry)) != sizeof(lastlog_entry)) {
    errx(EXIT_FAILURE, "hardened_shadow_write failed");
  }
  if (fsync(fd) != 0)
    err(EXIT_FAILURE, "fsync");

  TEMP_FAILURE_RETRY(close(fd));
}

static bool make_path(char *path, mode_t leaf_mode, mode_t parent_mode) {
  char *tmp = path;

  while (true) {
    tmp += strspn(tmp, "/");
    tmp += strcspn(tmp, "/");

    bool leaf = (*tmp == '\0');
    *tmp = '\0';

    struct stat st;
    int stat_rv = stat(path, &st);

    if (!leaf && stat_rv == 0 && S_ISDIR(st.st_mode)) {
      *tmp = '/';
      continue;
    }

    mode_t mode = (leaf) ? leaf_mode : parent_mode;

    if (mkdir(path, mode) != 0) {
      warn("mkdir(%s)", path);
      return false;
    }
    if (mode > 0777 && chmod(path, mode) != 0) {
      warn("chmod(%s)", path);
      return false;
    }

    if (leaf)
      break;

    *tmp = '/';
  }
  return true;
}

static void create_home_dir(void) {
  if (access(user_home_dir, F_OK) == 0)
    errx(EXIT_FAILURE, "home directory '%s' already exists", user_home_dir);

  mode_t mode;
  if (!hardened_shadow_config_get_mode("HOME_DIRECTORY_MODE", &mode))
    errx(EXIT_FAILURE, "failed to retrieve home directory mode");
  if (!make_path(user_home_dir, mode, mode))
    errx(EXIT_FAILURE, "make_path failed");
  if (chown(user_home_dir, user_uid, user_gid) != 0)
    err(EXIT_FAILURE, "chown");

  const char *skel_dir = (flag_skel) ? flag_skel : default_skel;
  if (!hardened_shadow_copy_dir_contents(skel_dir, user_home_dir,
                                         user_uid, user_gid)) {
    errx(EXIT_FAILURE, "hardened_shadow_copy_dir_contents failed");
  }
}

static void create_mail_spool(void) {
  const char *mail_dir = NULL;
  if (!hardened_shadow_config_get_path("MAIL_DIRECTORY", &mail_dir))
    errx(EXIT_FAILURE, "failed to retrieve path to mail directory");

  char *spool_path = NULL;
  if (asprintf(&spool_path, "%s/%s", mail_dir, user_name) < 0)
    errx(EXIT_FAILURE, "memory allocation failure");

  int fd = open(spool_path, O_CREAT | O_WRONLY | O_EXCL | O_CLOEXEC, 0);
  if (fd < 0)
    err(EXIT_FAILURE, "open");

  gid_t mail_gid = user_gid;
  mode_t mail_mode = 0600;
  struct group *gr = getgrnam("mail");
  if (gr) {
    mail_gid = gr->gr_gid;
    mail_mode = 0660;
  }

  if (fchown(fd, user_uid, mail_gid) != 0)
    err(EXIT_FAILURE, "fchown");
  if (fchmod(fd, mail_mode) != 0)
    err(EXIT_FAILURE, "fchmod");

  TEMP_FAILURE_RETRY(close(fd));
}

static void create_account(void) {
  char *shell_proxy =
      realpath(HARDENED_SHADOW_ROOT_PREFIX "/bin/shell_proxy", NULL);
  if (!shell_proxy)
    errx(EXIT_FAILURE, "memory allocation failure");

  char *target_shell = (flag_shell) ? flag_shell : default_shell;

  struct passwd pwd;
  pwd.pw_name = user_name;
  pwd.pw_passwd = HARDENED_SHADOW_SHADOW_PASSWD;
  pwd.pw_uid = user_uid;
  pwd.pw_gid = user_gid;
  pwd.pw_gecos = (flag_comment) ? flag_comment : "";
  pwd.pw_dir = user_home_dir;

  /* Use shell_proxy if possible, so that the user can choose
   * and change his preferred shell. */
  if (hardened_shadow_is_valid_login_shell(target_shell))
    pwd.pw_shell = shell_proxy;
  else
    pwd.pw_shell = target_shell;

  /* Send a log message now, for consistency with shadow-utils. */
  hardened_shadow_syslog(LOG_INFO,
                         "new user: name=%s, UID=%ju, GID=%ju, "
                         "home=%s, shell=%s",
                         pwd.pw_name,
                         (uintmax_t)pwd.pw_uid,
                         (uintmax_t)pwd.pw_gid,
                         pwd.pw_dir,
                         pwd.pw_shell);

  if (!hardened_shadow_replace_passwd(user_name, &pwd))
    errx(EXIT_FAILURE, "hardened_shadow_replace_passwd failed");
  if (user_groups &&
      !hardened_shadow_update_group_add_user(user_name,
                                             user_groups, user_ngroups, true)) {
    errx(EXIT_FAILURE, "hardened_shadow_update_group_add_user failed");
  }
  if (!hardened_shadow_create_shadow_entry(
          &pwd, NULL, flag_system,
          flag_inactive == FLAG_NOT_SET ? -1 : flag_inactive,
          flag_expiredate == FLAG_NOT_SET ? -1 : flag_expiredate)) {
    errx(EXIT_FAILURE, "hardened_shadow_create_shadow_entry failed");
  }
  if (!hardened_shadow_replace_user_file(user_name, user_uid,
                                         target_shell, "shell")) {
    errx(EXIT_FAILURE, "hardened_shadow_replace_user_file failed");
  }
}

int main(int argc, char **argv) {
  if (!hardened_shadow_read_config())
    errx(EXIT_FAILURE, "failed to read config");

  hardened_shadow_openlog("useradd");

  if (lckpwdf() != 0)
    err(EXIT_FAILURE, "lckpwdf");

  if (!read_defaults_file())
    warnx("failed to read defaults file");

  parse_args(argc, argv);

  if (flag_defaults)
    return (handle_flag_defaults()) ? EXIT_SUCCESS : EXIT_FAILURE;

  determine_uid_gid();
  if (!flag_no_log_init)
    initialize_lastlog();
  if (flag_create_home)
    create_home_dir();
  if (default_create_mail_spool && !flag_system)
    create_mail_spool();
  create_account();

  hardened_shadow_flush_nscd("passwd");
  hardened_shadow_flush_nscd("group");

  if (ulckpwdf() != 0)
    warn("ulckpwdf");

  return EXIT_SUCCESS;
}
