#ifndef _PAM_UNIX_SUPPORT_H
#define _PAM_UNIX_SUPPORT_H

#include <pwd.h>
#include <shadow.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>

#include <security/_pam_types.h>

enum {
  UNIX__IAMROOT = 0,
  UNIX_AUDIT,
  UNIX_USE_FIRST_PASS,
  UNIX_TRY_FIRST_PASS,
  UNIX_NOT_SET_PASS,
  UNIX__NONULL,
  UNIX__QUIET,
  UNIX_USE_AUTHTOK,
  UNIX__NULLOK,
  UNIX_DEBUG,
  UNIX_NODELAY,
};

#define _ALL_ON_  (~0U)
static const struct {
  const char *token;
  unsigned int mask;
  unsigned int flag;
} unix_args[] = {
/* symbol                  token name          ctrl mask             ctrl     *
 * ----------------------- ------------------- --------------------- -------- */

/* UNIX__IAMROOT */        {NULL,              _ALL_ON_,                  04},
/* UNIX_AUDIT */           {"audit",           _ALL_ON_,                 010},
/* UNIX_USE_FIRST_PASS */  {"use_first_pass",  _ALL_ON_^(060),           020},
/* UNIX_TRY_FIRST_PASS */  {"try_first_pass",  _ALL_ON_^(060),           040},
/* UNIX_NOT_SET_PASS */    {"not_set_pass",    _ALL_ON_,                0100},
/* UNIX__NONULL */         {NULL,              _ALL_ON_,               01000},
/* UNIX__QUIET */          {NULL,              _ALL_ON_,               02000},
/* UNIX_USE_AUTHTOK */     {"use_authtok",     _ALL_ON_,               04000},
/* UNIX__NULLOK */         {"nullok",          _ALL_ON_^(01000),           0},
/* UNIX_DEBUG */           {"debug",           _ALL_ON_,              040000},
/* UNIX_NODELAY */         {"nodelay",         _ALL_ON_,             0100000},
};

inline static bool on(int arg, unsigned int ctrl) {
  return ((unix_args[arg].flag & ctrl) != 0);
}

inline static bool off(int arg, unsigned int ctrl) {
  return !on(arg, ctrl); }

inline static void set(int arg, unsigned int *ctrl) { *ctrl = ((*ctrl & unix_args[arg].mask) | unix_args[arg].flag); }
inline static void unset(int arg, unsigned int *ctrl) { *ctrl &= ~(unix_args[arg].flag); }

/* use this to free strings. ESPECIALLY password strings */
#define _pam_delete(xx)		\
do {				\
	_pam_overwrite(xx);	\
	_pam_drop(xx);		\
} while(0)

extern int _make_remark(pam_handle_t *pamh, unsigned int ctrl, int type, const char *text);
extern unsigned int _set_ctrl(pam_handle_t *pamh, int flags, int argc, const char **argv, const char **prefix);
extern int _unix_blankpasswd(pam_handle_t *pamh, const char *name);
extern int _unix_verify_password(pam_handle_t *pamh, const char *name, const char *p, unsigned int ctrl);
extern int _unix_read_password(pam_handle_t * pamh, unsigned int ctrl, int authtok_flag, const char *prompt1, const char *prompt2, const char *data_name, char **pass);
extern int get_account_info(pam_handle_t *pamh, const char *name, struct passwd **pwd, struct spwd **spwdent);
extern int check_shadow_expiry(pam_handle_t *pamh, struct spwd *spent, int *daysleft);

#endif /* _PAM_UNIX_SUPPORT_H */
