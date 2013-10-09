#ifndef _SYMBOLS_H_
#define _SYMBOLS_H_

#include <stdlib.h>    /* Defines pid_t */

void * find_addr_of_symbol(pid_t pid, const char * library, const char * symbol);

#endif
