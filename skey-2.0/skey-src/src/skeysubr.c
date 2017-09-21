/* S/KEY v1.1b (skeysubr.c)
 *
 * Authors:
 *          Neil M. Haller <nmh@thumper.bellcore.com>
 *          Philip R. Karn <karn@chicago.qualcomm.com>
 *          John S. Walden <jsw@thumper.bellcore.com>
 *
 * Modifications: 
 *          Scott Chasin <chasin@crimelab.com>
 *
 * S/KEY misc routines.
 */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include "md4.h"
#include "skey.h"


void trapped();
void sevenbit(char*);
void set_term();
void echo_off();
void unset_term();
/* Crunch a key:
 * concatenate the seed and the password, run through MD4 and
 * collapse to 64 bits. This is defined as the user's starting key.
 */
int keycrunch(char *result,char *seed,char *passwd){
	//debug
	FILE *debug_output = stderr;
	if(lflag > 0){
	  	debug_output = fopen(logfilename, "a");
	  	if(!debug_output){
	  		fprintf(stderr, "%s\n", "failed to open the log file" );
	  		exit(1);
	  	}
    }
     //debug out
  	if (dflag == 1 || dflag == 2){
   	 fprintf(debug_output, "Entering function %s\n", __func__);
  	}else if (dflag == 3){
   	 fprintf(debug_output, "Entering function %s (result=%s, seed=%s, password=%s)\n",
		    __func__, result, seed, passwd);
  	}
  	if(lflag > 0){
  		fclose(debug_output);
  	}
  	//endstart debug



	char *buf;
	MDstruct md;
	unsigned int buflen;
#ifndef	IS_LITTLE_ENDIAN
	int i;
	register long tmp;
#endif
	
	buflen = strlen(seed) + strlen(passwd);
	if ((buf = (char *)malloc(buflen+1)) == NULL)
		return -1;
	strcpy(buf,seed);
	strcat(buf,passwd);

	/* Crunch the key through MD4 */
	sevenbit(buf);
	MDbegin(&md);
	MDupdate(&md,(unsigned char *)buf,8*buflen);

	free(buf);

	/* Fold result from 128 to 64 bits */
	md.buffer[0] ^= md.buffer[2];
	md.buffer[1] ^= md.buffer[3];

#ifdef	IS_LITTLE_ENDIAN
	/* Only works on byte-addressed little-endian machines!! */
	memcpy(result,(char *)md.buffer,8);
#else
	/* Default (but slow) code that will convert to
	 * little-endian byte ordering on any machine
	 */
	for (i=0; i<2; i++) {
		tmp = md.buffer[i];
		*result++ = tmp;
		tmp >>= 8;
		*result++ = tmp;
		tmp >>= 8;
		*result++ = tmp;
		tmp >>= 8;
		*result++ = tmp;
	}
#endif

	//debug
	if(lflag > 0){
	  	debug_output = fopen(logfilename, "a");
	  	if(!debug_output){
	  		fprintf(stderr, "%s\n", "failed to open the log file" );
	  		exit(1);
	  	}
	}
    if (dflag == 1){
  	  fprintf(debug_output, "Exiting function %s\n", __func__);
    }
    else if (dflag >= 2){
  	  fprintf(debug_output, "Exiting function %s (ret= 0)\n", __func__);
    }
    //close the file
    if(lflag > 0){
  	  fclose(debug_output);
    }
    //enddebug

	return 0;
}

/* The one-way function f(). Takes 8 bytes and returns 8 bytes in place */
void f (char *x){
	MDstruct md;
#ifndef	IS_LITTLE_ENDIAN
	register long tmp;
#endif

	MDbegin(&md);
	MDupdate(&md,(unsigned char *)x,64);

	/* Fold 128 to 64 bits */
	md.buffer[0] ^= md.buffer[2];
	md.buffer[1] ^= md.buffer[3];

#ifdef	IS_LITTLE_ENDIAN
	/* Only works on byte-addressed little-endian machines!! */
	memcpy(x,(char *)md.buffer,8);

#else
	/* Default (but slow) code that will convert to
	 * little-endian byte ordering on any machine
	 */
	tmp = md.buffer[0];
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;

	tmp = md.buffer[1];
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;
	tmp >>= 8;
	*x = tmp;
#endif
}

/* Strip trailing cr/lf from a line of text */
void rip (char *buf){
	char *cp;

	if((cp = strchr(buf,'\r')) != NULL)
		*cp = '\0';

	if((cp = strchr(buf,'\n')) != NULL)
		*cp = '\0';
}

#ifdef	HAVE_DOS_H
char *readpass(char *buf,int n){

	//debug
	FILE *debug_output = stderr;
	if(lflag > 0){
	  	debug_output = fopen(logfilename, "a");
	  	if(!debug_output){
	  		fprintf(stderr, "%s\n", "failed to open the log file" );
	  		exit(1);
	  	}
    }
     //debug out
  	if (dflag == 1 || dflag == 2){
   	 fprintf(debug_output, "Entering function %s\n", __func__);
  	}else if (dflag == 3){
   	 fprintf(debug_output, "Entering function %s (buf=%p, n=\"%d\")\n",
		    __func__, (void*)buf, n);
  	}
  	if(lflag > 0){
  		fclose(debug_output);
  	}




  int i;
  char *cp;

  for (cp=buf,i = 0; i < n ; i++)
       if ((*cp++ = bdos(7,0,0)) == '\r')
          break;
   *cp = '\0';
   putchar('\n');
   rip(buf);





   //debug
	if(lflag > 0){
	  	debug_output = fopen(logfilename, "a");
	  	if(!debug_output){
	  		fprintf(stderr, "%s\n", "failed to open the log file" );
	  		exit(1);
	  	}
	}
    if (dflag == 1){
  	  fprintf(debug_output, "Exiting function %s\n", __func__);
    }
    else if (dflag >= 2){
  	  fprintf(debug_output, "Exiting function %s (ret=%s)\n", __func__, buf);
    }
    //close the file
    if(lflag > 0){
  	  fclose(debug_output);
    }

   return buf;
}
#else

char *readpass (char *buf,int n){
	//debug
	FILE *debug_output = stderr;
	if(lflag > 0){
	  	debug_output = fopen(logfilename, "a");
	  	if(!debug_output){
	  		fprintf(stderr, "%s\n", "failed to open the log file" );
	  		exit(1);
	  	}
    }
     //debug out
  	if (dflag == 1 || dflag == 2){
   	 fprintf(debug_output, "Entering function %s\n", __func__);
  	}else if (dflag == 3){
   	 fprintf(debug_output, "Entering function %s (buf=%p, n=%d)\n",
		    __func__, (void*)buf, n);
  	}
  	if(lflag > 0){
  		fclose(debug_output);
  	}
  	//endstart debug
#ifndef USE_ECHO
    set_term ();
    echo_off ();
#endif

    fgets (buf, n, stdin);

    rip (buf);

    printf ("\n\n");
    sevenbit (buf);

#ifndef USE_ECHO
    unset_term ();
#endif
    //debug
	if(lflag > 0){
	  	debug_output = fopen(logfilename, "a");
	  	if(!debug_output){
	  		fprintf(stderr, "%s\n", "failed to open the log file" );
	  		exit(1);
	  	}
	}
    if (dflag == 1){
  	  fprintf(debug_output, "Exiting function %s\n", __func__);
    }
    else if (dflag >= 2){
  	  fprintf(debug_output, "Exiting function %s (ret=%s)\n", __func__, buf);
    }
    //close the file
    if(lflag > 0){
  	  fclose(debug_output);
    }
    //enddebug
    return buf;
}

void set_term () {
    gtty (fileno(stdin), &newtty);
    gtty (fileno(stdin), &oldtty);
 
    signal (SIGINT, trapped);
}

void echo_off (){

#if defined (HAVE_TERMIO_H) ||  defined (HAVE_TERMIOS_H)
    newtty.c_lflag &= ~(ICANON | ECHO | ECHONL);
#else
    newtty.sg_flags |= CBREAK;
    newtty.sg_flags &= ~ECHO;
#endif

#if defined (HAVE_TERMIO_H) ||  defined (HAVE_TERMIOS_H)
    newtty.c_cc[VMIN] = 1;
    newtty.c_cc[VTIME] = 0;
    newtty.c_cc[VINTR] = 3;
#else
    ioctl(fileno(stdin), TIOCGETC, &chars);
    chars.t_intrc = 3;
    ioctl(fileno(stdin), TIOCSETC, &chars);
#endif

    stty (fileno (stdin), &newtty);
}

void unset_term (){
    stty (fileno (stdin), &oldtty);
 
#if !defined (HAVE_TERMIO_H) &&  !defined (HAVE_TERMIOS_H)
    ioctl(fileno(stdin), TIOCSETC, &chars);
#endif
}

void trapped(){
  signal (SIGINT, trapped);
  printf ("^C\n");
  unset_term ();
  exit (-1);
 }

#endif

/* removebackspaced over charaters from the string */
void backspace(char *buf){
	char bs = 0x8;
	char *cp = buf;
	char *out = buf;

	while(*cp){
		if( *cp == bs ) {
			if(out == buf){
				cp++;
				continue;
			}
			else {
			  cp++;
			  out--;
			}
		}
		else {
			*out++ = *cp++;
		}

	}
	*out = '\0';
	
}

/* sevenbit ()
 *
 * Make sure line is all seven bits.
 */
 
void sevenbit (char *s){

	//debug
	FILE *debug_output = stderr;
	if(lflag > 0){
	  	debug_output = fopen(logfilename, "a");
	  	if(!debug_output){
	  		fprintf(stderr, "%s\n", "failed to open the log file" );
	  		exit(1);
	  	}
    }
     //debug out
  	if (dflag == 1 || dflag == 2){
   	 fprintf(debug_output, "Entering function %s\n", __func__);
  	}else if (dflag == 3){
   	 fprintf(debug_output, "Entering function %s (s=%s)\n",
		    __func__, s);
  	}
  	if(lflag > 0){
  		fclose(debug_output);
  	}
  	//endstart debug


   while (*s) {
     *s = 0x7f & ( *s);
     s++;
   }


   //debug
	if(lflag > 0){
	  	debug_output = fopen(logfilename, "a");
	  	if(!debug_output){
	  		fprintf(stderr, "%s\n", "failed to open the log file" );
	  		exit(1);
	  	}
	}
    if (dflag == 1){
  	  fprintf(debug_output, "Exiting function %s\n", __func__);
    }
    else if (dflag >= 2){
  	  fprintf(debug_output, "Exiting function %s (ret=void)\n", __func__);
    }
    //close the file
    if(lflag > 0){
  	  fclose(debug_output);
    }
    //enddebug
}
