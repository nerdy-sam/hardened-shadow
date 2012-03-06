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

#include <fcntl.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "hardened-shadow.h"

int main(UNUSED int argc, char **argv) {
  struct passwd *pwd = getpwuid(getuid());
  if (!pwd)
    exit(EXIT_FAILURE);
  int user_fd = hardened_shadow_open_user_directory(pwd->pw_name);
  if (user_fd < 0)
    exit(EXIT_FAILURE);
  int shell_fd = hardened_shadow_open_user_file(user_fd, "shell", O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
  if (shell_fd < 0)
    exit(EXIT_FAILURE);
  char *shell_contents = NULL;
  if (!hardened_shadow_read_contents(shell_fd, &shell_contents, NULL))
    exit(EXIT_FAILURE);
  if (!hardened_shadow_closefrom(STDERR_FILENO + 1))
    exit(EXIT_FAILURE);

  if (setenv("SHELL", shell_contents, 1) != 0)
    exit(EXIT_FAILURE);

  if (!argv[0])
    exit(EXIT_FAILURE);
  if (argv[0][0] == '-') {
    if (asprintf(&argv[0], "-%s", basename(shell_contents)) < 0)
      exit(EXIT_FAILURE);
  } else {
    argv[0] = shell_contents;
  }

  execv(shell_contents, argv);
  exit(EXIT_FAILURE);
}
