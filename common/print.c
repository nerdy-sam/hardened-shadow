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

#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <utmp.h>

const char hardened_shadow_lastlog_header[] =  "Username         Port     From             Latest";

bool hardened_shadow_asprintf_lastlog(char **result, const char *username, const struct lastlog *entry) {
  struct tm *tm = localtime(&entry->ll_time);
  if (!tm)
    return false;
  char ptime[80];
  if (entry->ll_time == 0)
    strncpy(ptime, "**Never logged in**", sizeof(ptime) - 1);
  else
    strftime(ptime, sizeof(ptime), "%a %b %e %H:%M:%S %z %Y", tm);

  if (asprintf(result, "%-16s %-8.8s %-16.16s %s\n", username, entry->ll_line, entry->ll_host, ptime) == -1)
    return false;

  return true;
}

static const char *pw_status(const char *pass) {
  if (*pass == '*' || strcmp(pass, HARDENED_SHADOW_LOCKED_PASSWD) == 0)
    return "L";
  if (*pass == '\0')
    return "NP";
  return "P";
}

bool hardened_shadow_asprintf_date(char **result, time_t date) {
  char buffer[128];

  struct tm *tm = gmtime(&date);
  if (!tm)
    return false;

  if (strftime(buffer, sizeof(buffer), "%Y-%m-%d", tm) <= 0)
    return false;

  if (asprintf(result, "%s", buffer) < 0)
    return false;

  return true;
}

bool hardened_shadow_asprintf_password_status(char **result, const char *username) {
  struct spwd *sp = getspnam(username);
  if (sp) {
    static char buf[80];
    time_t last_change = sp->sp_lstchg * 24 * 3600;
    struct tm *tm = gmtime(&last_change);
    if (!tm)
      return false;
    if (strftime(buf, sizeof(buf), "%m/%d/%Y", tm) <= 0)
      return false;
    if (asprintf(result, "%s %s %s %ld %ld %ld %ld\n",
                 username,
                 pw_status(sp->sp_pwdp),
                 buf,
                 sp->sp_min,
                 sp->sp_max,
                 sp->sp_warn,
                 sp->sp_inact) == -1) {
      return false;
    }
  } else {
    struct passwd *pw = getpwnam(username);
    if (!pw)
      return false;
    if (asprintf(result, "%s %s\n", username, pw_status(pw->pw_passwd)) == -1)
      return false;
  }
  return true;
}

bool hardened_shadow_asprintf_shadow(char **result, const struct spwd *spwd) {
  if (asprintf(result,
               "%s:%ld:\n",
               spwd->sp_pwdp,
               spwd->sp_lstchg) == -1) {
    return false;
  }
  return true;
}

bool hardened_shadow_asprintf_aging(char **result, const struct spwd *spwd) {
  if (asprintf(result,
               "%ld:%ld:%ld:%ld:%ld:\n",
               spwd->sp_min,
               spwd->sp_max,
               spwd->sp_warn,
               spwd->sp_inact,
               spwd->sp_expire) == -1) {
    return false;
  }
  return true;
}
