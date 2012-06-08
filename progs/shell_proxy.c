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

#include <fcntl.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "hardened-shadow.h"

int main(UNUSED int argc, char **argv) {
  /* Launch an even smaller executable to read the shell path
   * from /etc/hardened-shadow (regular users can't access it).
   * Use separate executable to minimize risk of launching the shell
   * with elevated privileges. */

  int fds[2];
  if (pipe(fds) != 0)
    exit(EXIT_FAILURE);

  pid_t fork_rv = fork();
  if (fork_rv == -1)
    exit(EXIT_FAILURE);

  if (fork_rv == 0) {
    /* Child. */

    close(fds[0]);  /* Close unused read end. */

    /* Write standard output to the pipe. */
    if (dup2(fds[1], STDOUT_FILENO) == -1)
      _exit(EXIT_FAILURE);

    execl(HARDENED_SHADOW_ROOT_PREFIX "/bin/get_shell", "get_shell", NULL);
    _exit(EXIT_FAILURE);
  }

  /* Parent. */

  close(fds[1]);  /* Close unused write end. */

  char *shell_contents = NULL;
  bool result = hardened_shadow_read_contents(fds[0], &shell_contents, NULL);

  int status = -1;
  if (waitpid(fork_rv, &status, 0) != fork_rv)
    exit(EXIT_FAILURE);

  if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS)
    exit(EXIT_FAILURE);

  if (!result)
    exit(EXIT_FAILURE);

  /* Make sure we do not pass unnecessary file descriptors to the child. */
  if (!hardened_shadow_closefrom(STDERR_FILENO + 1))
    exit(EXIT_FAILURE);

  /* Simulate as closely as possible launching of the target shell,
   * including environment and argv contents. */
  if (setenv("SHELL", shell_contents, 1) != 0)
    exit(EXIT_FAILURE);
  if (!argv[0])
    exit(EXIT_FAILURE);
  if (argv[0][0] == '-') {
    /* This is important to handle login shells correctly, see login.c. */
    if (asprintf(&argv[0], "-%s", basename(shell_contents)) < 0)
      exit(EXIT_FAILURE);
  } else {
    argv[0] = basename(shell_contents);
  }

  execv(shell_contents, argv);
  exit(EXIT_FAILURE);
}
