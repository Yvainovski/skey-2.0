/*
 * S/KEY v1.1b (skey.c)
 *
 * Authors:
 *          Neil M. Haller <nmh@thumper.bellcore.com>
 *          Philip R. Karn <karn@chicago.qualcomm.com>
 *          John S. Walden <jsw@thumper.bellcore.com>
 *          Scott Chasin <chasin@crimelab.com>
 *
 *
 * Stand-alone program for computing responses to S/Key challenges.
 * Takes the iteration count and seed as command line args, prompts
 * for the user's key, and produces both word and hex format responses.
 *
 * Usage example:
 *	>skey 88 ka9q2
 *	Enter password:
 *	OMEN US HORN OMIT BACK AHOY
 *	>
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
//#include "skeyversion.h"
#include "md4.h"
#include "skey.h"

char *readpass ();
void usage (char *s);
void printVersion();



int main (int argc,  char *argv[]){
  int n, cnt, i, pass = 0;
  char passwd[256], key[8], buf[33], *seed, *slash;
  //-h -v -d and -l flag
  int hflag = 0;
  int vflag = 0;
  FILE *debug_output = stderr;
  dflag =0;
  lflag =0;

  cnt = 1;

  while ((i = getopt (argc, argv, "n:p:hdl:v")) != EOF)
  {
    switch (i)
    {
    case 'n':
      cnt = atoi (optarg);
      break;
    case 'p':
      strcpy (passwd, optarg);
      pass = 1;
      break;
    case 'h':
      hflag++;
      break;
    case 'v':
      vflag++;
      break;
    case 'd':
      dflag++;
      break;
    case 'l':
      lflag++;
      strcpy (logfilename, optarg);
      break;
    }
  }

  /* print usage message and exit*/	
  if(hflag > 0){
  	usage(argv[0]);
  	exit(0);
  }

  if(dflag > 3 ){
  	dflag = 3;
  }
  //print debugging level if there is one
  if(dflag > 0){
  	printf("Debugging level----------> %d\n",dflag );
  }

  //if -l flag exists, change debug output to the specific file
  if(lflag > 0){
  	printf("Logs append to ----------> %s\n",logfilename );
  	debug_output = fopen(logfilename, "a");
  	if(!debug_output){
  		fprintf(stderr, "%s\n", "failed to open the log file" );
  		exit(1);
  	}
  	//print current time
  	time_t current_time;
    char* c_time_string;
    current_time = time(NULL);
    c_time_string = ctime(&current_time);
    fprintf(debug_output, "%s", c_time_string);
    
  }
  

  //debug out
  if (dflag == 1 || dflag == 2){
    fprintf(debug_output, "Entering function %s\n", __func__);
  }else if (dflag == 3){
  	int i;
  	char ss[256] = " ";
  	for( i =0; argv[i] != '\0'; i++){
  		strcat(ss,argv[i]);
  		strcat(ss," ");
  	}
    fprintf(debug_output, "Entering function %s (i=%d, s=\"%s\")\n",
	    __func__, argc, ss);
  }
  if(lflag > 0){
  	fclose(debug_output);
  }


  /* print current version */
  if(vflag > 0){
  	printVersion();
  }

  /* could be in the form <number>/<seed> */

  if (argc <= optind + 1)
  {
    /* look for / in it */
    if (argc <= optind)
    {
      usage (argv[0]);
      exit (1); 
    }

    slash = strchr (argv[optind], '/');
    if (slash == NULL)
    {
      usage (argv[0]);
      exit (1);
    }
    *slash++ = '\0';
    seed = slash;

    if ((n = atoi (argv[optind])) < 0)
    {
      printf ("%s not positive\n", argv[optind]);
      usage (argv[0]);
      exit (1);
    }
  }
  else
  {

    if ((n = atoi (argv[optind])) < 0)
    {
      printf ("%s not positive\n", argv[optind]);
      usage (argv[0]);
      exit (1);
    }
    seed = argv[++optind];
  }

  /* Get user's secret password */
  if (!pass)
  {
    printf ("Enter secret password: ");
    readpass (passwd, sizeof (passwd));
  }

  rip (passwd);

  /* Crunch seed and password into starting key */
  if (keycrunch (key, seed, passwd) != 0)
  {
    fprintf (stderr, "%s: key crunch failed\n", argv[0]);
    exit (1);
  }
  if (cnt == 1)
  {
    while (n-- != 0)
      f (key);
    printf ("%s\n", btoe (buf, key));
#ifdef	HEXIN
    printf ("%s\n", put8 (buf, key));
#endif
   }
  else
  {
    for (i = 0; i <= n - cnt; i++)
      f (key);
    for (; i <= n; i++)
    {
#ifdef	HEXIN
      printf ("%d: %-29s  %s\n", i, btoe (buf, key), put8 (buf, key));
#else
      printf ("%d: %-29s\n", i, btoe (buf, key));
#endif
      f (key);
    }
  }

  if(lflag > 0){
  	debug_output = fopen(logfilename, "a");
  	if(!debug_output){
  		fprintf(stderr, "%s\n", "failed to open the log file" );
  		exit(1);
  	}
  }
  //debug out
  if (dflag == 1){
    fprintf(debug_output, "Exiting function %s\n\n", __func__);
  }
  else if (dflag >= 2){
    fprintf(debug_output, "Exiting function %s (ret=%d)\n\n", __func__, 0);
  }
  //close the file
  if(lflag > 0){
  	fclose(debug_output);
  }

  exit (0);
}

void usage (char *s){
  printf ("Usage: %s [ flags ][ count ] [ password ] <sequence #>[/] <key> \n", s);
  printf("%s\n", "Use any following flag before [count] and [password].");
  printf("%s\n", "[-h] : only print usage message.");
  printf("%s\n", "[-v] : print current version.");
  printf("%s\n", "[-d] : Increase debugging level by one.  May be specified multiple times.");
  printf("%s\n", "Debugging level 1 will show entry/exit point of every function.");
  printf("%s\n", "Level 2 will also show return values about to be returned from" );
  printf("%s\n", "functions.  Level 3 will also show arguments passed to functions." );
  printf("%s\n", "If declare more than 3 times, it will be the same as Level 3.");
}

void printVersion(){
	//if -l flag exists, change debug output to the specific file

    FILE *debug_output = stderr;
    if(lflag > 0){
	  	debug_output = fopen(logfilename, "a+");
		if(!debug_output){
	  		fprintf(stderr, "%s\n", "failed to open the log file" );
	  		exit(1);
  		}
    }
    //debug out
    if (dflag == 1 || dflag == 2){
      fprintf(debug_output, "Entering function %s\n", __func__);
    }else if (dflag == 3){
    	fprintf(debug_output, "Entering function %s ()\n",__func__);
    }

	printf("S/Key version - %s\n", PACKAGE_VERSION);


	//debug out
	if (dflag == 1){
	   fprintf(debug_output, "Exiting function %s\n", __func__);
	}
	else if (dflag >= 2){
	   fprintf(debug_output, "Exiting function %s (ret = void)\n", __func__);
	}
	if(lflag > 0){
		fclose(debug_output);
	}
	  
}



