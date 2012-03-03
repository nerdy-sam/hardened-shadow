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
#include <grp.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "hardened-shadow.h"

static bool is_on_list(char **list, const char *member) {
  while (*list) {
    if (strcmp(*list, member) == 0)
      return true;
    list++;
  }

  return false;
}

static void print_current_groups(void) {
  gid_t *groups;
  size_t ngroups;

  if (!hardened_shadow_getgroups(&groups, &ngroups))
    errx(EXIT_FAILURE, "hardened_shadow_getgroups failed");

  size_t i;
  for (i = 0; i < ngroups; i++) {
    struct group *gr = getgrgid(groups[i]);
    if (gr)
      printf("%s ", gr->gr_name);
    else
      printf("%ju ", (uintmax_t) groups[i]);
  }
  printf("\n");

  free(groups);

  exit(EXIT_SUCCESS);
}

static void print_groups(const char *username) {
  if (!getpwnam(username))
    errx(EXIT_FAILURE, "unknown user %s", username);

  struct group *gr;
  setgrent();
  while ((gr = getgrent())) {
    if (is_on_list(gr->gr_mem, username))
      printf("%s ", gr->gr_name);
  }
  endgrent();
  printf("\n");

  exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
  if (argc == 1)
    print_current_groups();

  if (argc == 2)
    print_groups(argv[1]);

  fputs("Usage: groups [user]\n", stderr);
  exit(EXIT_FAILURE);
}
