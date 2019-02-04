/*
 * redirect.c
 *
 *  Created on: 06 Dec 2016
 *      Author: hein
 */

#include <stdio.h>
#include <unistd.h>
#include <time.h>

void init_dir(void);

void redirect_stdio(void)
{
  static int current_mday = 100;

  fflush(stdout);
  fflush(stderr);

  if (getppid() == 1)  // daemon - so we redirect stdout and stderr
  {
    char debug_filename[100];
    char error_filename[100];

    time_t now;
    struct tm *date;

    init_dir();

    time(&now);
    date = localtime(&now);

    if ( date->tm_mday != current_mday ) // date change event
    {
      int i;

      sprintf( debug_filename, "./log/debug_%04d_%02d_%02d.txt", date->tm_year + 1900, date->tm_mon + 1, date->tm_mday );
      sprintf( error_filename, "./log/error_%04d_%02d_%02d.txt", date->tm_year + 1900, date->tm_mon + 1, date->tm_mday );

      if ( freopen(debug_filename, "a", stdout) ) fprintf(stdout,"redirect starts here\n");
      if ( freopen(error_filename, "a", stderr) ) fprintf(stderr,"redirect starts here\n");

      current_mday = date->tm_mday;

      time(&now);

      now -= 60 * 60 * 24 * 360; // time - seconds * minutes * hours * 360 days

      for ( i = 0; i < 100; i++ )  // wipe logs backward starting 360 days back ending 460 days back
      {
        date = localtime(&now);

        sprintf( debug_filename, "./log/debug_%04d_%02d_%02d.txt", date->tm_year + 1900, date->tm_mon + 1, date->tm_mday );
        sprintf( error_filename, "./log/error_%04d_%02d_%02d.txt", date->tm_year + 1900, date->tm_mon + 1, date->tm_mday );

        remove(debug_filename);
        remove(error_filename);

        now -= 60 * 60 * 24; // time - seconds * minutes * hours * 1 day
      }
    }
  }
}

