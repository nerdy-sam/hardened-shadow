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
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "hardened-shadow.h"

static void usage(void) {
  fputs("Usage: pwunconv\n", stderr);
  exit(EXIT_FAILURE);
}

int main(int argc, char **argv UNUSED) {
  if (lckpwdf() != 0)
    err(EXIT_FAILURE, "lckpwdf");

  if (argc != 1)
    usage();

  if (!hardened_shadow_update_passwd_undo_shell_proxy())
    errx(EXIT_FAILURE, "hardened_shadow_update_passwd_undo_shell_proxy failed");

  char tmp_path[] = "/etc/.hardened-shadow.XXXXXX";
  int tmp_fd = mkostemp(tmp_path, O_CLOEXEC);
  if (tmp_fd < 0)
    err(EXIT_FAILURE, "mkostemp");

  FILE *tmp_file = fdopen(tmp_fd, "w");
  if (!tmp_file) {
    warn("fdopen");
    goto error;
  }

  struct spwd *spw = NULL;
  setspent();
  while ((spw = getspent())) {
    if (putspent(spw, tmp_file) != 0) {
      warn("putspent");
      goto error;
    }
  }
  endspent();

  if (rename(tmp_path, "/etc/shadow") != 0) {
    warn("rename");
    goto error;
  }

  if (ulckpwdf() != 0)
    warn("ulckpwdf");

  return EXIT_SUCCESS;

error:
  unlink(tmp_path);
  return EXIT_FAILURE;
}
