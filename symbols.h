#ifndef _SYMBOLS_H_
#define _SYMBOLS_H_

#include <stdlib.h>    /* Defines pid_t */
#include <stdbool.h>   /* Defines bool */

typedef unsigned char * MemPtr_t;

#define MAX_NUM_ADDRS_PER_SYM 5

/**
 * Information about the symbol we are looking for 
 * When calling only name is required. On return
 * cnt and values will be filled in
 */
struct Symbol_s
{
    /* IN */
    const char * name;

    /* OUT */
    int cnt;                                 /* Number found */
    MemPtr_t values[MAX_NUM_ADDRS_PER_SYM];    /* Symbol values, to be filled in when found */
};

typedef struct Symbol_s Symbol_t;

void find_addr_of_symbol(pid_t pid, const char * library, Symbol_t * symbol);

#define MAX_SYMBOL_NAME_LEN   (256)

struct Address_s
{
    /* IN */
    MemPtr_t value;                           /* The Address to search for */

    /* OUT */
    int distance;
    char name[MAX_SYMBOL_NAME_LEN];           /* Symbol name, to be filled in when found */
};

typedef struct Address_s Address_t;

void find_closest_symbol(pid_t pid, Address_t * addr);

#endif
