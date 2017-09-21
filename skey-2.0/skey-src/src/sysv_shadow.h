#include <shadow.h>
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <sys/resource.h>
#include <time.h>
struct spwd *spwd;

static struct passwd *fix_getpwnam(char *u){
    struct passwd *pwd = 0;

    if ((spwd = getspnam(u)) && (pwd = getpwnam(u)))
	pwd->pw_passwd = spwd->sp_pwdp;
    return pwd;
}


#define getpwnam fix_getpwnam
extern sysv_expire(struct spwd *);
