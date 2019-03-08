/*
 ============================================================================
 Name        : OpenwrtTest.c
 Author      : Hein
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include "init.h"
#include "loop.h"

//#include <ctype.h>
//#include <stdio.h>
#include <stdlib.h>

//#include "log.h"

int main (int argc, char *argv[])
{
//  if (argc != 2)
//  {
//    DEBUG_PRINTF("Incorrect arguments - [Listen port] [Monitor port] [Monitor port 2]");
//    DEBUG_PRINTF("Incorrect arguments - [Listen port] [Monitor port]");
//    printf("missing config file");
//    exit(EXIT_FAILURE);
//  }

  init (argc, argv);

  while (1)
    server_poll ();

  return EXIT_SUCCESS;
}
