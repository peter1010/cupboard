/**
 */

#include <unistd.h>
#include <string.h>
#include <sys/mman.h>

#include <stdint.h>

#include "logging.h"
#include "elf_info.h"
#include "elf32_info.h"
#include "elf64_info.h"
#include "mmap_entry.h"

/**
 * Debug function that converts a section headr type to a string
 *
 * @param[in] sh_type Section header type
 *
 * @return Pointer to const string
 */
static const char * shtype2str(int sh_type)
{
    const char * retval = "UNKNOWN";
    switch(sh_type)
    {
        case SHT_NULL:           /* Section header table entry unused */
            retval = "NULL";
            break;

        case SHT_PROGBITS:      /* Program data */
            retval = "PROGBITS";
            break;

        case SHT_SYMTAB:        /* Symbol table */
            retval = "SYMTAB";
            break;

        case SHT_STRTAB:        /* String table */
            retval = "STRTAB";
            break;

        case SHT_HASH:	    /* Symbol hash table */
            retval = "HASH";
            break;

        case SHT_NOTE:          /* Notes */
            retval = "NOTE";
            break;

        case SHT_NOBITS:        /* Program space with no data (bss) */
            retval = "NOBITS";
            break;

        case SHT_DYNSYM:        /* Dynamic linker symbol table (subset of symbol table) */
            retval = "DYNSYM";
            break;

        case SHT_REL:           /* Relocation entries, no addends */
            retval = "RELOC";
            break;

        case SHT_INIT_ARRAY:    /* Array of constructors */
            retval = "INIT_ARRAY";
            break;

        case SHT_FINI_ARRAY:   /* Array of destructors */
            retval = "FINI_ARRAY";
            break;

        case SHT_DYNAMIC:      /* Dynamic linking information */
            retval = "DYNAMIC";
            break;

        case SHT_GNU_HASH:     /* GNU-style hash table.  */
            retval = "GNU_HASH";
            break;

        case SHT_GNU_verdef:   /* Version definition section.  */
            retval = "GNU_verdef";
            break;

        case SHT_GNU_versym:   /* Version symbol table.  */
            retval = "GNU_versym";
            break;

        case SHT_GNU_verneed:  /* Version needs section.  */
            retval = "GNU_verneed";
            break;

        default:
//            LOG_ERROR("Unknown sh_type %i(%x)", sh_type, sh_type);
            retval = "unknown";
            break;
    }
    return retval;
}


/**
 * Initialse the Elf_into_t structure
 *
 * @param[in] elf_info
 */
Elf_info::Elf_info() :
    m_mem_map(0), m_fd(-1), m_num_of_sections(0), 
    m_section_entry_size(0), m_e_shoff(0), m_e_shstrndx(0),
    m_shdr(0), m_shstrtab(0)
{
    LOG_DEBUG("Elf_info() called");
}

/**
 * Parse the Elf header
 *
 * @param[in] fd The open file descriptor for the ELF file
 * @param[in] pathname The name of the Elf file
 *
 * @return True if this indeed is an Elf file
 */
static Elf_info * parse_elf_header(int fd, Map_entry * mem_map)
{
    uint8_t buf[sizeof(Elf64_Ehdr)];
    Elf_info * retVal = NULL;
    const unsigned int num = read(fd, buf, sizeof(buf));
    if(num < EI_NIDENT)
    {
        LOG_ERROR("Failed to read ELF ident");
        return retVal;
    }
    if(memcmp(ELFMAG, buf, SELFMAG) != 0)
    {
        LOG_ERROR("No ELF Magic seen for '%s'", mem_map->pathname());
        return retVal;
    }
    switch(buf[EI_CLASS])
    {
        case ELFCLASS32:
            {
                const Elf32_Ehdr * ehdr = (const Elf32_Ehdr *)buf;

                if((sizeof(Elf32_Ehdr) <= ehdr->e_ehsize) && (sizeof(Elf32_Ehdr) <= num))
                {
                    retVal = new Elf32_info(ehdr);
                }
            }
            break;
        case ELFCLASS64:
            {
                const Elf64_Ehdr * ehdr = (const Elf64_Ehdr *)buf;

                if((sizeof(Elf64_Ehdr) <= ehdr->e_ehsize) && (sizeof(Elf64_Ehdr) <= num))
                {
                    retVal = new Elf64_info(ehdr);
                }
            }
            break;

        default:
            LOG_ERROR("Unknown class type");
            return false;
    }
    return retVal;
}


Elf_info * Elf_info::create(Map_entry * map)
{
    Elf_info * elf_info = NULL;
    const int fd = map->open_elf();
    if(fd  > 0)
    {
        elf_info = parse_elf_header(fd, map);
        if(elf_info)
        {
            elf_info->m_fd = fd;
        }
        else
        {
            close(fd);
        }
    }
    return elf_info;
}

void Elf_info::switch_map(Map_entry * map)
{
    m_mem_map = map;
}

/**
 * Free the elf info structure
 *
 */
Elf_info::~Elf_info()
{
    if(m_fd >= 0)
    {
        close(m_fd);
        m_fd = -1;
    }

    free(m_shdr);
    m_shdr = NULL;

    free(m_shstrtab);
    m_shstrtab = NULL;
}

/**
 * Get section header from elf file
 *
 * @return True on success
 */
bool Elf_info::get_elf_section_header_table()
{
    const ssize_t size = m_section_entry_size * m_num_of_sections;
    uint8_t * buf = new uint8_t[size];
    if( pread(m_fd, buf, size, m_e_shoff) != size)
    {
        LOG_ERROR("Failed to Read ELF section header table");
        delete [] buf;
        exit(0);
    }
    m_shdr = static_cast<uint8_t *>(buf);

    char * shstrtab = static_cast<char *>(get_elf_section(m_e_shstrndx));
    if( shstrtab == NULL)
    {
        LOG_ERROR("Failed to Read ELF section header table section names");
        delete [] buf;
        m_shdr = NULL;
        exit(0);
    }

    m_shdr = static_cast<uint8_t *>(buf);
    m_shstrtab = shstrtab;
    return true;
}

/**
 * Get the index of table and string tables in the section header table
 *
 * @param[in] print_shdr_tab Print the section header info
 * @param[in] _typ The table type
 *
 * @return The index of in the section table
 */
int Elf_info::get_section_idx(unsigned typ_to_find, bool print_shdr_tab) const
{
    int retVal = -1;

    /* Look through the section header table */
    unsigned idx = 0;
    for(; idx < m_num_of_sections; idx++)
    {
        char * section_name = get_section_name(idx);

        unsigned _typ = get_section_type(idx);

        if(print_shdr_tab)
        {
            LOG_DEBUG("ELF Shdr[%02u] %19s %11s ", idx, section_name, shtype2str(_typ));
//            LOG_DEBUG_APPEND("%08lx %08lx-%08lx", (unsigned long) pShdr->sh_addr,
//                                             (unsigned long) pShdr->sh_offset,
//                                      (unsigned long) pShdr->sh_offset+pShdr->sh_size);
        }
        if(_typ == typ_to_find)
        {
            retVal = idx;
        }
    }
    return retVal;
}


