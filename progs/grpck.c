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

#include <err.h>
#include <getopt.h>
#include <grp.h>
#include <shadow.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "hardened-shadow.h"

static void usage(void) {
  fputs("Usage: grpck [-r]\n", stderr);
  exit(EXIT_FAILURE);
}

static bool flag_read_only = false;

static void parse_args(int argc, char **argv) {
  int c;
  while ((c = getopt(argc, argv, "r")) != -1) {
    switch (c) {
      case 'r':
        flag_read_only = true;
        break;
      default:
        usage();
    }
  }
}

int main(int argc, char **argv) {
  if (lckpwdf() != 0)
    err(EXIT_FAILURE, "lckpwdf");

  parse_args(argc, argv);

  bool result = hardened_shadow_grpck(flag_read_only);
  if (!result)
    warnx("group check failed");

  hardened_shadow_flush_nscd("group");

  if (ulckpwdf() != 0)
    warn("ulckpwdf");

  return (result) ? EXIT_SUCCESS : EXIT_FAILURE;
}
