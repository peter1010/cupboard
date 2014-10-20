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
class Sym2Addr
{
public:
    Sym2Addr(const char * name);

    void reset();

    bool match(const char * symbol_name) const;

    bool add_value(MemPtr_t value);

    bool full() const {return (m_cnt >= MAX_NUM_ADDRS_PER_SYM);};

    void print(pid_t tgt_pid) const;

private:
    /* IN */
    const char * m_name;

    /* OUT */
    int m_cnt;                                 /* Number found */
    MemPtr_t m_values[MAX_NUM_ADDRS_PER_SYM];    /* Symbol values, to be filled in when found */
};

void find_addr_of_symbol(pid_t pid, const char * library, Sym2Addr * symbol);

#define MAX_SYMBOL_NAME_LEN   (256)

class Addr2Sym
{
public:
    Addr2Sym(unsigned value);

    void reset();

    bool update(MemPtr_t value, const char * symbol_name);

    MemPtr_t value() const { return m_value; };

    void print(pid_t tgt_pid) const;
private:
    /* IN */
    MemPtr_t m_value;                           /* The Address to search for */

    /* OUT */
    int m_distance;
    char m_name[MAX_SYMBOL_NAME_LEN];           /* Symbol name, to be filled in when found */
};

void find_closest_symbol(pid_t pid, Addr2Sym * addr);

#endif
