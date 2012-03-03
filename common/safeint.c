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

bool hardened_shadow_ucast_ok(intmax_t a, uintmax_t max) {
  return a > 0 && (uintmax_t)a < max;
}

bool hardened_shadow_scast_ok(uintmax_t a, intmax_t max) {
  return a < (uintmax_t)max;
}

bool hardened_shadow_uadd_ok(uintmax_t a, uintmax_t b, uintmax_t max) {
  if (a > max || b > max)
    return false;
  return max - a >= b;
}

bool hardened_shadow_usub_ok(uintmax_t a, uintmax_t b, uintmax_t max UNUSED) {
  return a >= b;
}

bool hardened_shadow_umul_ok(uintmax_t a, uintmax_t b, uintmax_t max) {
  if (a > max || b > max)
    return false;
  return a <= max / b;
}

bool hardened_shadow_sadd_ok(intmax_t a, intmax_t b, intmax_t min, intmax_t max) {
  if (a > max || b > max || a < min || b < min)
    return false;
  if (b > 0 && a > (max - b))
    return false;
  if (b < 0 && a < (min - b))
    return false;
  return true;
}

bool hardened_shadow_ssub_ok(intmax_t a, intmax_t b, intmax_t min, intmax_t max) {
  if (a > max || b > max || a < min || b < min)
    return false;
  if (b > 0 && a < (min + b))
    return false;
  if (b < 0 && a > (max + b))
    return false;
  return true;
}

bool hardened_shadow_smul_ok(intmax_t a, intmax_t b, intmax_t min, intmax_t max) {
  if (a > max || b > max || a < min || b < min)
    return false;
  if (a > 0) {
    if (b > 0 && a > (max / b))
      return false;
    if (b < 0 && b < (min / a))
      return false;
  } else {
    if (b > 0 && a < (min / b))
      return false;
    if (b < 0 && a != 0 && b < (max / a))
      return false;
  }
  return true;
}

bool hardened_shadow_sdiv_ok(intmax_t a, intmax_t b, intmax_t min, intmax_t max) {
  if (a > max || b > max || a < min || b < min)
    return false;
  if (b == 0)
    return false;
  if (a == min && b == -1)
    return false;
  return true;
}
