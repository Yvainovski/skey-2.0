/*
 * S/KEY v1.1b (skey.h)
 *
 * Authors:
 *          Neil M. Haller <nmh@thumper.bellcore.com>
 *          Philip R. Karn <karn@chicago.qualcomm.com>
 *          John S. Walden <jsw@thumper.bellcore.com>
 *
 * Modifications:
 *          Scott Chasin <chasin@crimelab.com>
 *          Yifang Cao <yifang.cao@stonybrook.edu>
 * Main client header
 */
#ifndef _SKEY_H_
#define _SKEY_H_ 1
#include "config.h"


#ifdef HAVE_STDLIB_H 
#include <stdlib.h>
#else
#include <sys/types.h>
#endif

#ifdef stty
# undef stty
#endif
 
#ifdef gtty
# undef gtty
#endif

//#define HAVE_TERMIOS_H 1
#ifndef HAVE_TERMIO_H
  #ifdef HAVE_TERMIOS_H
    #include <termios.h>
    #include <sys/ioctl.h>
    #define TTYSTRUCT termios
    #define TCSETS 0x00005402
    #define TCGETS 0x00005401
    #define stty(fd,buf) ioctl((fd),TCSETS,(buf))
    #define gtty(fd,buf) ioctl((fd),TCGETS,(buf))
    struct termios newtty;
    struct termios oldtty;
  #else
    #include <sgtty.h>
    #define TTYSTRUCT sgttyb
    #define stty(fd,buf) ioctl((fd),TIOCSETN,(buf))
    #define gtty(fd,buf) ioctl((fd),TIOCGETP,(buf))
        struct sgttyb newtty;
        struct sgttyb oldtty;
        struct tchars chars;
  #endif
#else
  #include <termio.h>
  #define TTYSTRUCT termio
  #define stty(fd,buf) ioctl((fd),TCSETA,(buf))
  #define gtty(fd,buf) ioctl((fd),TCGETA,(buf))
      struct termio newtty;
      struct termio oldtty;
#endif


#ifdef  HAVE_DOS_H
#include <dos.h>
#else       /* Assume BSD unix */
#include <fcntl.h>
#ifdef HAVE_TERMIOS_H
    #include <termios.h>
#else
  #include <termio.h>
#endif
#endif


//for OX X-like
#ifndef HAVE_DQHASHSHIFT
      #undef HAVE_SYS_QUOTA_H
#endif


#ifdef  HAVE_SYS_QUOTA_H
#include <sys/quota.h>
#endif



/*
*#ifdef BEHAVE_LIKE_SVR4
*#include <sys/systeminfo.h>
*#include <unistd.h>
*#include <shadow.h>
*#include "sysv_shadow.h"
*#endif 
**/

#ifdef HAVE_SHADOW_H
      #ifdef HAVE_SYS_SYSTEMINFO_H 
        #ifdef HAVE_UNISTD_H 
          #include <sys/systeminfo.h>
          #include <unistd.h>
          #include <shadow.h>
          #include "sysv_shadow.h"
        #endif
      #endif
#endif

#ifndef WORDS_BIGENDIAN 
      #define IS_LITTLE_ENDIAN 1
      #define LOWBYTEFIRST 1
#else
      #undef IS_LITTLE_ENDIAN
      #undef LOWBYTEFIRST
#endif

/*
#ifdef HAVE_TERMINO_H
    struct termio newtty;
    struct termio oldtty;
#else
    struct sgttyb newtty;
    struct sgttyb oldtty;
    struct tchars chars;
#endif
*/
/*
#if	defined(__TURBOC__) || defined(__STDC__) || defined(LATTICE)
#define	ANSIPROTO	1
#endif

#ifndef	__ARGS
  #ifdef	ANSIPROTO
  #define	__ARGS(x)	x
  #else
  #define	__ARGS(x)	()
  #endif
#endif
*/
/*
 *#ifdef SOLARIS
 *#define setpriority(x,y,z)      z
 *#endif
*/

/* Server-side data structure for reading keys file during login */

struct skey
{
  FILE *keyfile;
  char buf[256];
  char *logname;
  int n;
  char *seed;
  char *val;
  long recstart;		/* needed so reread of buffer is efficient */


};

/* Client-side structure for scanning data stream for challenge */
struct mc
{
  char buf[256];
  int skip;
  int cnt;
};

void f (char *x);
int keycrunch (char *result, char *seed, char *passwd);
char *btoe (char *engout, char *c);
char *put8 (char *out, char *s);
int etob (char *out, char *e);
void rip (char *buf);
int skeychallenge (struct skey * mp, char *name, char *ss);
int skeylookup (struct skey * mp, char *name);
int skeyverify (struct skey * mp, char *response);

int dflag ;
char logfilename[256];
int lflag ;


#endif 
/* _SKEY_H_  */
