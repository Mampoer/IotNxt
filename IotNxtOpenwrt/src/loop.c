/*
 * loop.c
 *
 *  Created on: 04 Feb 2019
 *      Author: hein
 */

#include <stdint.h>
//#include <stdbool.h>

#include "io.h"
#include "timer.h"
#include "redirect.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>


void server_poll(void)
{
  Timer_Check ();
  check_events();
  redirect_stdio();
}
