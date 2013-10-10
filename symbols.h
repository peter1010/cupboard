#ifndef _SYMBOLS_H_
#define _SYMBOLS_H_

#include <stdlib.h>    /* Defines pid_t */
#include <stdbool.h>   /* Defines bool */

#define MAX_NUM_ADDRS_PER_SYM 5

/**
 * Information about the symbol we are looking for 
 * When calling only name is required. On return
 * cnt and values will be filled in
 */
struct Symbol_s
{
    const char * name;
    int cnt;                                 /* Number found */
    void * values[MAX_NUM_ADDRS_PER_SYM];    /* Symbol values, to be filled in when found */
};

typedef struct Symbol_s Symbol_t;

void find_addr_of_symbol(pid_t pid, const char * library, Symbol_t * symbol);


#define MAX_NUM_SYMS_PER_ADDR 5

struct Address_s
{
    void * value;
    int cnt;                                  /* Number found */
    char names[MAX_NUM_SYMS_PER_ADDR*100];    /* Symbol values, to be filled in when found */
};

typedef struct Address_s Address_t;

void find_closest_symbol(pid_t pid, Address_t * addr);

#endif
