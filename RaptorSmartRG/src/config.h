#ifndef CONFIG_H_
#define CONFIG_H_

#include "stdlib.h"

typedef struct config {
  char *api_host;
  char *api_user;
  char *api_pass;
} config_t;

extern config_t config;

#endif /* CONFIG_H_ */
