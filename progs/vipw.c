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
#include <shadow.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "hardened-shadow.h"

static void usage(void) {
  fputs("Usage: vipw [options]\n"
        "\n"
        "Options:\n"
        "  -g, --group                   edit group database\n"
        "  -h, --help                    display this help message and exit\n"
        "  -p, --passwd                  edit passwd database\n"
        "\n", stderr);
  exit(EXIT_FAILURE);
}

static bool flag_group = false;
static bool flag_passwd = false;

static void parse_args(int argc, char **argv) {
  int c;
  static struct option long_options[] = {
    {"group", no_argument, NULL, 'g'},
    {"help", no_argument, NULL, 'h'},
    {"passwd", no_argument, NULL, 'p'},
    {NULL, 0, NULL, '\0'}
  };
  while ((c = getopt_long (argc, argv, "ghp", long_options, NULL)) != -1) {
    switch (c) {
      case 'g':
        flag_group = true;
        break;
      case 'h':
        usage();
        break;
      case 'p':
        flag_passwd = true;
        break;
      default:
        usage();
    }
  }

  if (flag_group && flag_passwd)
    usage();
  if (!flag_group && !flag_passwd)
    flag_passwd = true;
}

static bool edit_file(const char *filename) {
  if (lckpwdf() != 0) {
    warn("lckpwdf");
    return false;
  }

  bool result = true;

  int tmp_fd = -1;
  int original_fd = TEMP_FAILURE_RETRY(open(filename, O_RDONLY | O_CLOEXEC));
  if (original_fd < 0) {
    warn("open");
    result = false;
    goto out;
  }

  struct stat original_stat;
  if (fstat(original_fd, &original_stat) != 0) {
    warn("fstat");
    result = false;
    goto out;
  }

  char tmp_path[] = "/etc/.vipw.XXXXXX";
  tmp_fd = mkostemp(tmp_path, O_CLOEXEC);
  if (tmp_fd < 0) {
    warn("mkostemp");
    result = false;
    goto out;
  }

  if (fchown(tmp_fd, original_stat.st_uid, original_stat.st_gid) != 0) {
    warn("fchown");
    result = false;
    goto out;
  }

  if (fchmod(tmp_fd, original_stat.st_mode) != 0) {
    warn("fchmod");
    result = false;
    goto out;
  }

  if (!hardened_shadow_copy_file_contents(original_fd, tmp_fd)) {
    warnx("hardened_shadow_copy_file_contents failed");
    result = false;
    goto out;
  }

  const char *editor = getenv("VISUAL");
  if (!editor)
    editor = getenv("EDITOR");
  if (!editor)
    editor = "vi";

  while (true) {
    char *editor_cmdline = NULL;
    if (asprintf(&editor_cmdline, "%s %s", editor, tmp_path) < 0) {
      warn("asprintf");
      result = false;
      goto out;
    }

    int rv = system(editor_cmdline);
    if (!WIFEXITED(rv) || WEXITSTATUS(rv) != EXIT_SUCCESS) {
      warnx("system(%s) failed", editor_cmdline);
      result = false;
      goto out;
    }

    bool consistency_check;
    if (flag_passwd)
      consistency_check = hardened_shadow_pwck_passwd(true, true);
    else
      consistency_check = hardened_shadow_grpck(true);
    if (consistency_check ||
        hardened_shadow_interactive_confirm("save ignoring errors?")) {
      break;
    }
  }

  if (rename(tmp_path, filename) != 0) {
    warn("rename");
    result = false;
    goto out;
  }

out:
  if (!result && tmp_fd >= 0) {
    if (unlink(tmp_path) != 0)
      warn("unlink");
  }

  if (ulckpwdf() != 0)
    warn("ulckpwdf");
  return result;
}

int main(int argc, char **argv) {
  parse_args(argc, argv);

  if (!edit_file(flag_passwd ? "/etc/passwd" : "/etc/group"))
    errx(EXIT_FAILURE, "Edit failed.");

  hardened_shadow_flush_nscd("passwd");
  hardened_shadow_flush_nscd("group");

  return EXIT_SUCCESS;
}
