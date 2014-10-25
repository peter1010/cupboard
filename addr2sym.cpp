/**
 */

#include <stdio.h>
#include <string.h>
#include <limits.h>

#include "symbols.h"
#include "logging.h"

Addr2Sym::Addr2Sym(unsigned value)
{
    m_value = reinterpret_cast<MemPtr_t>(value);
    m_distance = INT_MAX;
    m_name[0] = '\0';
}

/**
 * Initialise the Addr2Sym structure to have no found values
 *
 */
void Addr2Sym::reset()
{
    MemPtr_t addr_ = m_value;
    memset(this, 0, sizeof(Addr2Sym));
    m_value = addr_;
    m_distance = INT_MAX;
}

bool Addr2Sym::update(MemPtr_t value, const char * symbol_name)
{
    int offset = m_value - value;
    if((offset < 0) || (offset > m_distance) || !symbol_name)
    {
        return false;
    }

    m_distance = offset;
    strncpy(m_name, symbol_name, MAX_SYMBOL_NAME_LEN);
    return true;
}

void Addr2Sym::print(pid_t tgt_pid) const
{
    printf("In process %i; %p is close to %s [+%i]\n", tgt_pid, m_value, m_name, m_distance);
}
 
