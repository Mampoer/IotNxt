/*
 * signals.c
 *
 *  Created on: 04 Feb 2019
 *      Author: hein
 */

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "utils.h"
#include "io.h"


//**********************************************************************************
bool signal_quit = false;

char **app_argv = NULL;

//**********************************************************************************
void SignalHandler(int signal)
{
//  uint64_t            poll;
//  extern int          timing_r_index, timing_w_index;
//  extern uint64_t     system_start[100];

//  DEBUG_PRINTF("SignalHandler %d - ", signal);

  switch (signal)
  {
    case SIGHUP:
//      DEBUG_PRINTF("SIGHUP");
      return;     /* Hangup (POSIX).                        */
    case SIGINT:
//      DEBUG_PRINTF("SIGINT");
      break;      /* Interrupt (ANSI).                      */
    case SIGQUIT:
//      DEBUG_PRINTF("SIGQUIT");
      break;      /* Quit (POSIX).                          */
    case SIGILL:
//      DEBUG_PRINTF("SIGILL");
      break;      /* Illegal instruction (ANSI).            */
    case SIGTRAP:
//      DEBUG_PRINTF("SIGTRAP");
      break;      /* Trace trap (POSIX).                    */
    case SIGABRT:
//      DEBUG_PRINTF("SIGABRT");
      break;      /* Abort (ANSI).                          */
                  /* IOT trap (4.2 BSD).                    */
    case SIGBUS:
//      DEBUG_PRINTF("SIGBUS");
      break;      /* BUS error (4.2 BSD).                   */
    case SIGFPE:
//      DEBUG_PRINTF("SIGFPE");
      break;      /* Floating-point exception (ANSI).       */
    case SIGKILL:
//      DEBUG_PRINTF("SIGKILL");
      break;      /* Kill, unblockable (POSIX).             */
    case SIGUSR1:
//      DEBUG_PRINTF("SIGUSR1");
      break;      /* User-defined signal 1 (POSIX).         */
    case SIGSEGV:
//      DEBUG_PRINTF("SIGSEGV");
      break;      /* Segmentation violation (ANSI).         */
    case SIGUSR2:
//      DEBUG_PRINTF("SIGUSR2");
      break;      /* User-defined signal 2 (POSIX).         */
    case SIGPIPE:
//      DEBUG_PRINTF("SIGPIPE");
      return;     /* Broken pipe (POSIX).                   */
    case SIGALRM:
//      DEBUG_PRINTF("SIGALRM");
      break;      /* Alarm clock (POSIX).                   */
    case SIGTERM:
//      DEBUG_PRINTF("SIGTERM");
      break;      /* Termination (ANSI).                    */
    case SIGSTKFLT:
//      DEBUG_PRINTF("SIGSTKFLT");
      break;      /* Stack fault.                           */
//    case SIGCLD:  /* Same as SIGCHLD (System V).            */
//                    if ( timing_w_index || timing_r_index )
//                    {
//                      poll = GetUcTimeStamp() - system_start[timing_r_index++];
//                      timing_r_index %= (sizeof(system_start)/sizeof(system_start[0]));
//                      DEBUG_PRINTF ("SIGCLD %f", (float)poll/1000000);
//                    }
//                    else
//                      DEBUG_PRINTF ("SIGCLD");
//      return;
    case SIGCONT:
//      DEBUG_PRINTF("SIGCONT");
      return;     /* Continue (POSIX).                      */
    case SIGSTOP:
//      DEBUG_PRINTF("SIGSTOP");
      break;      /* Stop, unblockable (POSIX).             */
    case SIGTSTP:
//      DEBUG_PRINTF("SIGTSTP");
      return;     /* Keyboard stop (POSIX).                 */
    case SIGTTIN:
//      DEBUG_PRINTF("SIGTTIN");
      return;     /* Background read from tty (POSIX).      */
    case SIGTTOU:
//      DEBUG_PRINTF("SIGTTOU");
      return;     /* Background write to tty (POSIX).       */
    case SIGURG:
//      DEBUG_PRINTF("SIGURG");
      return;     /* Urgent condition on socket (4.2 BSD).  */
    case SIGXCPU:
//      DEBUG_PRINTF("SIGXCPU");
      break;      /* CPU limit exceeded (4.2 BSD).          */
    case SIGXFSZ:
//      DEBUG_PRINTF("SIGXFSZ");
      break;      /* File size limit exceeded (4.2 BSD).    */
    case SIGVTALRM:
//      DEBUG_PRINTF("SIGVTALRM");
      return;     /* Virtual alarm clock (4.2 BSD).         */
    case SIGPROF:
//      DEBUG_PRINTF("SIGPROF");
      return;     /* Profiling alarm clock (4.2 BSD).       */
    case SIGWINCH:
//      DEBUG_PRINTF("SIGWINCH");
      return;     /* Window size change (4.3 BSD, Sun).     */
    case SIGPOLL:
//      DEBUG_PRINTF("SIGPOLL");
      return;     /* Pollable event occurred (System V).    */
                  /* I/O now possible (4.2 BSD).            */
    case SIGPWR:
//      DEBUG_PRINTF("SIGPWR");
      break;      /* Power failure restart (System V).      */
    case SIGSYS:
//      DEBUG_PRINTF("SIGSYS");
      break;      /* Bad system call.                       */
  }

//  DEBUG_PRINTF("EXIT");

  if ((signal == SIGINT) || (signal == SIGKILL) || (signal == SIGTERM))
  {
    // todo check end point mem allocs
    // if busy dont term, return

    signal_quit = true;
  }

  exit(0);
}

//**********************************************************************************
void cleanup(void)
{
  close_sockets();

  DEBUG_PRINTF("shutdown")

  if (!signal_quit)
  {
#if !DEBUG
    DEBUG_PRINTF("restarting");
    execl(app_argv[0], app_argv[0], NULL);
#endif
  }

  fclose(stdout);
  fclose(stderr);

  sleep(5); // to get sockets to close properly
}

//**********************************************************************************
void setup_signals(char *argv[])
{
  signal (SIGPIPE, SIG_IGN);

  struct sigaction sigact;

  sigact.sa_flags = SA_RESTART | SA_SIGINFO;

  sigaction (SIGSEGV, &sigact, (struct sigaction *) NULL);

  /*-- Catch signals so we exit cleanly -------------------------------*/
  (void) signal(SIGHUP, SignalHandler);     /* Hangup (POSIX).                        */
  (void) signal(SIGINT, SignalHandler);     /* Interrupt (ANSI).                      */ // ctrl-c
  (void) signal(SIGQUIT, SignalHandler);    /* Quit (POSIX).                          */
  (void) signal(SIGILL, SignalHandler);     /* Illegal instruction (ANSI).            */
  (void) signal(SIGTRAP, SignalHandler);    /* Trace trap (POSIX).                    */
  (void) signal(SIGABRT, SignalHandler);    /* Abort (ANSI).                          */
  (void) signal(SIGIOT, SignalHandler);     /* IOT trap (4.2 BSD).                    */
  (void) signal(SIGBUS, SignalHandler);     /* BUS error (4.2 BSD).                   */
  (void) signal(SIGFPE, SignalHandler);     /* Floating-point exception (ANSI).       */
  (void) signal(SIGKILL, SignalHandler);    /* Kill, unblockable (POSIX).             */
  (void) signal(SIGUSR1, SignalHandler);    /* User-defined signal 1 (POSIX).         */
//  (void) signal(SIGSEGV, SignalHandler);    /* Segmentation violation (ANSI).         */
  (void) signal(SIGUSR2, SignalHandler);    /* User-defined signal 2 (POSIX).         */
//  (void) signal(SIGPIPE, SignalHandler);    /* Broken pipe (POSIX).                   */
  (void) signal(SIGALRM, SignalHandler);    /* Alarm clock (POSIX).                   */
  (void) signal(SIGTERM, SignalHandler);    /* Termination (ANSI).                    */
  (void) signal(SIGCHLD, SignalHandler);    /* Child status has changed (POSIX).      */ // called by system() command wh
  (void) signal(SIGSTKFLT, SignalHandler);  /* Stack fault.                           */
  (void) signal(SIGCONT, SignalHandler);    /* Continue (POSIX).                      */
  (void) signal(SIGSTOP, SignalHandler);    /* Stop, unblockable (POSIX).             */
  (void) signal(SIGTSTP, SignalHandler);    /* Keyboard stop (POSIX).                 */
  (void) signal(SIGTTIN, SignalHandler);    /* Background read from tty (POSIX).      */
  (void) signal(SIGTTOU, SignalHandler);    /* Background write to tty (POSIX).       */
  (void) signal(SIGURG, SignalHandler);     /* Urgent condition on socket (4.2 BSD).  */
  (void) signal(SIGXCPU, SignalHandler);    /* CPU limit exceeded (4.2 BSD).          */
  (void) signal(SIGXFSZ, SignalHandler);    /* File size limit exceeded (4.2 BSD).    */
  (void) signal(SIGVTALRM, SignalHandler);  /* Virtual alarm clock (4.2 BSD).         */
  (void) signal(SIGPROF, SignalHandler);    /* Profiling alarm clock (4.2 BSD).       */
  (void) signal(SIGWINCH, SignalHandler);   /* Window size change (4.3 BSD, Sun).     */
  (void) signal(SIGIO, SignalHandler);      /* I/O now possible (4.2 BSD).            */
  (void) signal(SIGPOLL, SignalHandler);    /* Pollable event occurred (System V).    */
  (void) signal(SIGPWR, SignalHandler);     /* Power failure restart (System V).      */
  (void) signal(SIGSYS, SignalHandler);     /* Bad system call.                       */

  atexit(&cleanup);

  app_argv = argv;
}

