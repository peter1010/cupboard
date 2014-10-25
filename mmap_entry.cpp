/**
 * Some of the ideas and concepts are borrowed from reading code written
 * by Victor Zandy <zandy[at]cs.wisc.edu> for getting values of symbols
 * from inspecting the /proc/xxx/maps virtual file and contents of
 * refered ELF files. To better understand ELF files I felt the need to
 * implement my own version.
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>

#include "symbols.h"
#include "logging.h"
#include "mmap_entry.h"


#define XSTR(x) STR(x)
#define STR(x) #x
#define MAX_PERMISSIONS_CHARS 5

/**
 * Constructor
 */
Map_entry::Map_entry()
    : m_start_address(0), m_end_address(0), m_permissions(0), m_pathname(0)
{
}

/**
 * Parse an entry in the /proc/xxx/map output
 *
 * @param[in] linebuf A line of text from /proc/xxx/maps
 *
 * @return Allocated memory containing the Map_entry structure
 */
Map_entry * Map_entry::parse_map_entry(const char * linebuf)
{
    Map_entry * entry = new Map_entry;

    unsigned long start_address = 0;
    unsigned long end_address = 0;
    char permissions[MAX_PERMISSIONS_CHARS+1] = {0};
    const int num_parsed = sscanf(linebuf, "%lx-%lx %" XSTR(MAX_PERMISSIONS_CHARS) "s %lx %*x:%*x %*u %ms",
			                   &start_address,
                                           &end_address,
                                           permissions,
                                           &entry->m_offset_into_file,
                                           &entry->m_pathname);
    if(num_parsed < 4)
    {
        LOG_ERROR("Failed to parse memory map line '%s' (%i)", linebuf, num_parsed);
        exit(EXIT_FAILURE);
    }

    entry->m_start_address = reinterpret_cast<MemPtr_t>(start_address);
    entry->m_end_address = reinterpret_cast<MemPtr_t>(end_address);
    entry->m_permissions = 0;

    char * p = permissions;
    for(; *p; p++)
    {
        switch(*p)
        {
            case 'r':
                entry->m_permissions |= PROT_READ;
                break;

            case 'w':
                entry->m_permissions |= PROT_WRITE;
                break;

            case 'x':
                entry->m_permissions |= PROT_EXEC;
                break;

            case '-':
            case 'p':
            case 's':
                break;

            default:
                LOG_ERROR("Invalid character '%c' found in memory map entry '%s'", *p, linebuf);
                exit(EXIT_FAILURE);
                break;
        }
    }
    LOG_DEBUG("%8p-%8p %s %08lx %s",
			     entry->m_start_address,
                             entry->m_end_address,
                             permissions,
                             entry->m_offset_into_file,
                             entry->m_pathname);
    return entry;
}

/**
 * Copy pathname into a buffer provided
 *
 * @param[out] buffer
 * @param[in] max_len
 *
 * @return true if copy happened
 */
bool Map_entry::copy_pathname(char * buffer, int max_len) const
{
    if(m_pathname)
    {
        strncpy(buffer, m_pathname, max_len);
        return true;
    }
    return false;
}

/**
 * Are the pathnames the same
 *
 * @param[in] other The other Map entry
 *
 * @return true if same
 */
bool Map_entry::same_pathname(const Map_entry * other) const
{
    if(m_pathname)
    {
        if(other->m_pathname)
        {
            return strcmp(m_pathname, other->m_pathname) == 0;
        }
    }
    else if(other->m_pathname == NULL)
    {
        return true;
    }
    return false;
}

/**
 * Does the to_find library match the one we have found.
 *
 * @param[in] to_find The string to find
 *
 * @return true if match
 */
bool Map_entry::match_library(const char * to_find) const
{
    if((m_pathname == NULL) || (*m_pathname == '\0'))
    {
        return false;
    }
    if(to_find == NULL)
    {
        return true;
    }

    const char * start = strrchr(m_pathname, '/');
    start = (start == NULL) ? m_pathname : &start[1];
    const char * end = strchr(start, '-');
    const unsigned len = (end == NULL) ? strlen(start) : static_cast<unsigned>(end-start);

    bool success = (strncmp(start, to_find, len) == 0) ? true : false;
    if(!success)
    {
        LOG_DEBUG("ignoring '%s' != '%s'", to_find, m_pathname);
    }
    return success;
}

/**
 * Open the corresponding Elf file
 *
 * @return the file descriptor or -1
 */
int Map_entry::open_elf() const
{
    int fd = -1;
    if(m_pathname)
    {
        fd = open(m_pathname, O_RDONLY);
    }
    return fd;
}

/**
 * print some debug info
 */
void Map_entry::debug_print() const
{
    LOG_DEBUG("Mem_map => %8p - %8p", m_start_address, m_end_address);
    LOG_DEBUG("offset into file => %08lx", m_offset_into_file);
}

/**
 * destructor
 */
Map_entry::~Map_entry()
{
    delete [] m_pathname;
}
