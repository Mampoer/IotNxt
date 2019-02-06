//**********************************************************************************
/*
 * timer.h
 *
 *  Created on: 17 Sep 2014
 *      Author: hein
 */

//**********************************************************************************
#ifndef TIMER_H_
#define TIMER_H_

//**********************************************************************************
typedef void (*Timer_Callback)(void *UserData);

typedef enum
{
  SingleShot,
  MultiShot
} t_ShotType;

//**********************************************************************************
void Timer_Init (void);
int Timer_Add (int Interval, t_ShotType Type, Timer_Callback CallBack, void *UserData);
void Timer_Add_Fast (int Interval, t_ShotType Type, Timer_Callback CallBack, void *UserData);
int Timer_Remove (Timer_Callback CallBack, void *UserData);
int Timer_Running (Timer_Callback CallBack, void * UserData);

void Timer_Cleanup (void *UserData);

void Timer_Check (void);

#define ONE_SECOND      10
#define ONE_MINUTE      60 * ONE_SECOND
#define ONE_HOUR        60 * ONE_MINUTE

//**********************************************************************************
#endif /* TIMER_H_ */
//**********************************************************************************
