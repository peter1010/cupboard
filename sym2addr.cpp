/**
 * Some of the ideas and concepts are borrowed from reading code written
 * by Victor Zandy <zandy[at]cs.wisc.edu> for getting values of symbols
 * from inspecting the /proc/xxx/maps virtual file and contents of
 * refered ELF files. To better understand ELF files I felt the need to
 * implement my own version.
 */

#include <stdio.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/mman.h>

#include "symbols.h"
#include "logging.h"

Sym2Addr::Sym2Addr(const char * name)
{
    m_name = name;
}

/**
 * Initialise the Sym2Addr structure to have no found values
 */
void Sym2Addr::reset()
{
    const char * symbol = m_name;
    memset(this, 0, sizeof(Sym2Addr));
    m_name = symbol;
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
