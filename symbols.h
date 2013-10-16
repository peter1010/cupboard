#ifndef _SYMBOLS_H_
#define _SYMBOLS_H_

#include <stdlib.h>    /* Defines pid_t */

typedef unsigned char * MemPtr_t;

#define MAX_NUM_ADDRS_PER_SYM 5

/**
 * Information about the symbol we are looking for 
 * When calling only name is required. On return
 * cnt and values will be filled in
 */
struct Sym2Addr_s
{
    /* IN */
    const char * name;

    /* OUT */
    int cnt;                                 /* Number found */
    MemPtr_t values[MAX_NUM_ADDRS_PER_SYM];    /* Symbol values, to be filled in when found */
};

typedef struct Sym2Addr_s Sym2Addr_t;

void find_addr_of_symbol(pid_t pid, const char * library, Sym2Addr_t * symbol);

#define MAX_SYMBOL_NAME_LEN   (256)

struct Addr2Sym_s
{
    /* IN */
    MemPtr_t value;                           /* The Address to search for */

    /* OUT */
    int distance;
    char name[MAX_SYMBOL_NAME_LEN];           /* Symbol name, to be filled in when found */
};

typedef struct Addr2Sym_s Addr2Sym_t;

void find_closest_symbol(pid_t pid, Addr2Sym_t * addr);

#endif
