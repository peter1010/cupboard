/**
 *
 */

#include <stdio.h>
#include <string.h>

#include "symbols.h"
#include "logging.h"

/**
 * Constructor
 *
 * @param[in] The name of the symbol
 */
Sym2Addr::Sym2Addr(const char * name)
{
    m_name = name;
    m_cnt = 0;
}

void Sym2Addr::reset()
{
    m_cnt = 0;
}

bool Sym2Addr::match(const char * symbol_name) const
{
    return (strcmp(m_name, symbol_name) == 0);
}

bool Sym2Addr::add_value(MemPtr_t value)
{
    int i;
    for(i = 0; i < m_cnt; i++)
    {
        if( m_values[i] == value)
        {
            LOG_DEBUG("Duplicate");
            break;
        }
    }
    if(i == m_cnt)
    {
        m_values[m_cnt++] = value;
        return true;
    }
    return false;
}

void Sym2Addr::print(pid_t tgt_pid) const
{
    int i;
    for(i = 0; i < m_cnt; i++)
    {
        printf("In process %i; %s = %p\n", tgt_pid, m_name, m_values[i]);
    }
}
