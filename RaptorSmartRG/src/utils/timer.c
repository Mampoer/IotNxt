//**********************************************************************************
/*
 * timer.c
 *
 *  Created on: Jan 6, 2015
 *      Author: hein
 */

//**********************************************************************************
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <signal.h>
#include <time.h>

#include "timer.h"
#include "utils.h"


//**********************************************************************************
#define INITIAL_TIMERS          1000
#define MORE_TIMERS             1000

//**********************************************************************************
typedef struct
{
  Timer_Callback CallBack;
  t_ShotType Type;

  int Interval;
  int Time_Left;

  void *UserData;
} tTimers;

tTimers *Timers;
int Max_Timers = 0;

//int Timer_Events;

#define freq_nanosecs ( 1 * 100000000 )  // 100 msec
//bool clear_poll_tick = true;
//int poll_tick = 0;

//**********************************************************************************
void Timer_Tick(int sig, siginfo_t *si, void *uc)
{
  int i;

  for (i = 0; i < Max_Timers; i++)
    if (Timers[i].CallBack != NULL) if (Timers[i].Time_Left > 0) --Timers[i].Time_Left;
//     if ( --Timers[i].Time_Left == 0 )
//      Timer_Events++;

  //printf ("tick\n");
}

//**********************************************************************************
#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)

//**********************************************************************************
void Timer_Init(void)
{
  timer_t timerid;
  struct sigaction sa;
  struct sigevent sev;
  struct itimerspec its;
  sigset_t mask;

  //Timer_Events = 0;

  Timers = malloc(INITIAL_TIMERS * sizeof(tTimers));

  if (Timers == NULL)
  {
    DEBUG_PRINTF("Panic - not enough mem for %d timer", INITIAL_TIMERS);
    exit(EXIT_FAILURE);
  }

  Max_Timers = INITIAL_TIMERS;

  memset((char*) Timers, 0, Max_Timers * sizeof(tTimers));

  //for ( i = 0; i < Max_Timers ; i++ )
  //  {
  //  Timers[i].CallBack = NULL;
  //  Timers[i].UserData = NULL;
  //  }

  // Establish handler for timer signal

  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = Timer_Tick;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGALRM, &sa, NULL) == -1)  // this signal does not interrupt the GDB debugger
  //if ( sigaction(SIGRTMIN, &sa, NULL) == -1 )
  errExit("sigaction");

  // Block timer signal temporarily

  sigemptyset(&mask);
  sigaddset(&mask, SIGALRM);
  //sigaddset(&mask, SIGRTMIN);
  if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1)
  errExit("sigprocmask");

  // Create the timer

  sev.sigev_notify = SIGEV_SIGNAL;
  sev.sigev_signo = SIGALRM;
  //sev.sigev_signo  = SIGRTMIN;
  sev.sigev_value.sival_ptr = &timerid;
  if (timer_create(CLOCK_REALTIME, &sev, &timerid) == -1)
  errExit("timer_create");

  // Start the timer

  its.it_value.tv_sec = freq_nanosecs / 1000000000;
  its.it_value.tv_nsec = freq_nanosecs % 1000000000;
  its.it_interval.tv_sec = its.it_value.tv_sec;
  its.it_interval.tv_nsec = its.it_value.tv_nsec;

  if (timer_settime(timerid, 0, &its, NULL) == -1)
  errExit("timer_settime");

  // Unlock the timer signal, so that timer notification can be delivered

  if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1)
  errExit("sigprocmask");
}

//**********************************************************************************
int Timer_Add(int Interval, t_ShotType Type, Timer_Callback CallBack, void *UserData)
{
  int i;

  tTimers *More_Timers;

  if (CallBack == NULL) return false;

  if (Interval <= 0)
  {
    Timer_Remove(CallBack, UserData);
    return false;
  }

  if (Interval > 2000) Interval = 2000;

  if (Interval == 1) if (Type != MultiShot) Interval = 2;

  for (i = 0; i < Max_Timers; i++)
    if ((CallBack == Timers[i].CallBack) && (UserData == Timers[i].UserData))
    {
      Timers[i].Interval = Interval;
      Timers[i].Time_Left = Interval;
      Timers[i].Type = Type;
      return true;
    }

  for (i = 0; i < Max_Timers; i++)
    if (Timers[i].CallBack == NULL)
    {
      Timers[i].CallBack = CallBack;
      Timers[i].Interval = Interval;
      Timers[i].Time_Left = Interval;
      Timers[i].Type = Type;
      Timers[i].UserData = UserData;
      return true;
    }

  More_Timers = calloc(sizeof(tTimers), (Max_Timers + MORE_TIMERS));

  if (More_Timers)
  {
    memcpy(More_Timers, Timers, Max_Timers * sizeof(tTimers));

    free(Timers);

    Timers = More_Timers;

    Timers[Max_Timers].CallBack = CallBack;
    Timers[Max_Timers].Interval = Interval;
    Timers[Max_Timers].Time_Left = Interval;
    Timers[Max_Timers].Type = Type;
    Timers[Max_Timers].UserData = UserData;

    Max_Timers += MORE_TIMERS;

    DEBUG_PRINTF("New Max Timers = %d", Max_Timers);

    return true;
  }
  else
  {
    DEBUG_PRINTF("Panic - cant allocate %d more timers (%zd), Max Timers = %d", MORE_TIMERS, (sizeof(tTimers) * 10000), Max_Timers);
    return false;
  }
}

//**********************************************************************************
int Timer_Running(Timer_Callback CallBack, void * UserData)
{
  int i;
  int TimeLeft;

  if ( CallBack == NULL )
    return 0;

  for( i = 0; i < Max_Timers; i++ )
  {
    if ( ( CallBack == Timers[i].CallBack ) && ( UserData == Timers[i].UserData ) )
    {
      TimeLeft = Timers[i].Time_Left;
      return TimeLeft;
    }
  }

  return 0;
}

//**********************************************************************************
int Timer_Remove(Timer_Callback CallBack, void *UserData)
{
  int i;
  int TimeLeft;

  if (CallBack == NULL) return 0;

  for (i = 0; i < Max_Timers; i++)
    if ((CallBack == Timers[i].CallBack) && (UserData == Timers[i].UserData))
    {
      TimeLeft = Timers[i].Time_Left;
      Timers[i].CallBack = NULL;
      Timers[i].UserData = NULL;
      return TimeLeft;
    }

  return 0;
}
//**********************************************************************************
void Timer_Cleanup(void *UserData)
{
  int i;

  for (i = 0; i < Max_Timers; i++)
    if ((UserData == Timers[i].UserData))
    {
      Timers[i].CallBack = NULL;
      Timers[i].UserData = NULL;
    }
}

//**********************************************************************************
void Timer_Check(void)
{
  int i;
  Timer_Callback tCallBack;
  void *tUserData;

  for (i = 0; i < Max_Timers; i++)
    if (Timers[i].CallBack != NULL) if (Timers[i].Time_Left == 0)
    {
      //Timer_Events--;
      tCallBack = Timers[i].CallBack;
      tUserData = Timers[i].UserData;

      if (Timers[i].Type == MultiShot) Timers[i].Time_Left = Timers[i].Interval;
      else Timers[i].CallBack = NULL;

      tCallBack(tUserData);
    }

  //Timer_Events = 0;
}

//**********************************************************************************
//**********************************************************************************
//**********************************************************************************
