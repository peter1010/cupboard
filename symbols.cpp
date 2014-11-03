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
#include "mmap_entry.h"
#include "elf_info.h"



/**
 * Get the Value of the symbol
 *
 * @param[in] elf_info Elf file info
 * @param[in] symbols Pointer to section containing the symbols
 * @param[in] idx The index in section header of the section to get
 * @param[out] pValue Place to put the value
 *
 * @return true if value has been found
 */
static bool get_symbol_value(const Elf_info * elf_info, const void * symbols, int idx, MemPtr_t * pValue)
{

    /* Not interested in symbols that are not data or code */
    switch(elf_info->get_symbol_type(symbols, idx))
    {
        case STT_FUNC:
            if(!elf_info->m_mem_map->is_executable())
            {
                return false;
            }
            break;

        case STT_OBJECT:
            if(!elf_info->m_mem_map->is_accessable())
            {
                return false;
            }
            break;

        default:
            return false;
    }

    unsigned st_shndx = elf_info->get_symbol_section(symbols, idx);
    /* Not interested in symbols that are undefined */
    if(st_shndx == 0)
    {
        return false;
    }

    MemPtr_t value;
    if(st_shndx == SHN_ABS)
    {
        value = elf_info->get_raw_symbol_value(symbols, idx);
        /* Is this is not mapped into the memory map entry we are searching */
        if(!elf_info->m_mem_map->contains(value))
        {
            return false;
        }
    }
    else if(st_shndx >= elf_info->m_num_of_sections)
    {
//        char  * symstr = (char *) elf_info->get_elf_section(strtab_idx);
//        WARN_MSG("CHECK %s %u", &symstr[pSym->st_name], pSym->st_shndx);
//        free(symstr);
        return false;
    }
    else /* Get the section that this symbol can be found in */
    {
        unsigned sh_offset = elf_info->get_section_offset(st_shndx);

        MemPtr_t temp = elf_info->m_mem_map->foffset2addr(sh_offset);

        /* Is this section mapped into the memory map entry we are searching */
        if(!elf_info->m_mem_map->contains(temp))
        {
            return false;
        }
        unsigned sh_addr = elf_info->get_section_address(st_shndx);

        value = temp + (unsigned) elf_info->get_raw_symbol_value(symbols, idx) - sh_addr;
//        LOG_DEBUG("ELF Shdr, %08lx %08lx-%08lx", (unsigned long) sh_addr,
//                                                 (unsigned long) sh_offset,
//                                                 (unsigned long) sh_offset+shdr->sh_size);
    }
    *pValue = value;
    return true;
}

/**
 * Search through the section looking for the symbol we are interesting
 *
 * @param[in] elf_info Structure containing Elf information (like a class this pointer)
 * @param[in] symtab_idx Index of Symbol table section header in section header table
 * @param[in] strtab_idx Index of String table section header in section header table
 * @param[in,out] sym_to_find Pointer to structure containing info about symbol we are looking for
 *
 * @return True if any found
 *
 */
static bool search_elf_symbol_section_for_sym(const Elf_info * elf_info, int symtab_idx, int strtab_idx, Sym2Addr * sym_to_find)
{
    bool found = false;
    int num_of_symbols = elf_info->get_number_of_symbols(symtab_idx);
    if(num_of_symbols == 0)
    {
        return found;
    }

    void * symbols = elf_info->get_elf_section(symtab_idx);
    char * symstr = static_cast<char *>(elf_info->get_elf_section(strtab_idx));

    int i;
    for(i = 0; i < num_of_symbols; i++)
    {
        LOG_DEBUG("HEREA");
        MemPtr_t value;
        if(!get_symbol_value(elf_info, symbols, i, &value))
        {
            continue;
        }
        LOG_DEBUG("HEREB");

        const char * symbol_name = elf_info->get_symbol_name(symbols, i, symstr);
        LOG_DEBUG("HEREC");

        Elf32_Sym * pSym = &((Elf32_Sym *)symbols)[i];
        LOG_DEBUG("%08lx => %s (%i) {%i}", (unsigned long) pSym->st_value, symbol_name, pSym->st_size, pSym->st_shndx);
        if(sym_to_find->match(symbol_name))
        {
            found = true;
            LOG_DEBUG("++++++ Matched %s ++++++ ", symbol_name);
            if(sym_to_find->add_value(value))
            {
                LOG_DEBUG("%p => %s", value, symbol_name);
                elf_info->m_mem_map->debug_print();
                LOG_DEBUG("++++++  ++++++ ");
                if(sym_to_find->full())
                {
                    break;
                }
            }
        }
    }
    free(symstr);
    return found;
}

/**
 * Search through the section looking for the symbol we are interesting
 *
 * @param[in] elf_info Structure containing Elf information (like a class this pointer)
 * @param[in] symtab_idx Index of Symbol table section header in section header table
 * @param[in] strtab_idx Index of String table section header in section header table
 * @param[in,out] addr_to_find Pointer to structure containing info about address we are looking for
 *
 * @return True if any found
 *
 */
static void search_elf_symbol_section_for_addr(const Elf_info * elf_info, int symtab_idx, int strtab_idx, Addr2Sym * addr_to_find)
{
    int num_of_symbols = elf_info->get_number_of_symbols(symtab_idx);
    if(num_of_symbols == 0)
    {
        return;
    }
    void * symbols = elf_info->get_elf_section(symtab_idx);

    char * symstr = static_cast<char *>(elf_info->get_elf_section(strtab_idx));

    int i;
    for(i = 0; i < num_of_symbols; i++)
    {
        MemPtr_t value;
        if(!get_symbol_value(elf_info, symbols, i, &value))
        {
            continue;
        }

        const char * symbol_name = elf_info->get_symbol_name(symbols, i, symstr);

        Elf32_Sym * pSym = &((Elf32_Sym *)symbols)[i];
        LOG_DEBUG("%08lx => %s (%i) {%i}", (unsigned long) pSym->st_value, symbol_name, pSym->st_size, pSym->st_shndx);

        if(addr_to_find->update(value, symbol_name))
        {
            LOG_DEBUG("++++++ Best matched %s ++++++ ", symbol_name);
            LOG_DEBUG("%p => %s", value, symbol_name);
            elf_info->m_mem_map->debug_print();
            LOG_DEBUG("++++++  ++++++ ");
        }

    }
    free(symstr);
}

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
 * Get the indexes of symbol table and string tables in the section header table
 *
 * @param[in] elf_info Structure containing Elf information (like a class this pointer)
 * @param[in] print_shdr_tab Print the section header info
 * @param[out] symtab_idx[2] Index of Symbol tablei/ strings section header in section header table
 * @param[out] dynSym_idx[2]_idx Index of String table/ strings section header in section header table
 */
static void get_symbol_table_sections(const Elf_info * elf_info, bool print_shdr_tab, int * symtab_idx, int * dynSym_idx)
{
    /* Look through the section header table */
    unsigned idx = 0;
    for(; idx < elf_info->m_num_of_sections; idx++)
    {
        char * section_name = elf_info->get_section_name(idx);

        unsigned _typ = elf_info->get_section_type(idx);

        if(print_shdr_tab)
        {
            LOG_DEBUG("ELF Shdr[%02u] %19s %11s ", idx, section_name, shtype2str(_typ));
//            LOG_DEBUG_APPEND("%08lx %08lx-%08lx", (unsigned long) pShdr->sh_addr,
//                                             (unsigned long) pShdr->sh_offset,
//                                      (unsigned long) pShdr->sh_offset+pShdr->sh_size);
        }
        switch(_typ)
        {
            case SHT_SYMTAB:        /* Symbol table */
                symtab_idx[0] = idx;
                break;

            case SHT_STRTAB:        /* String table */
		if(strncmp(section_name, ".strtab", 7) == 0)
                {
                    symtab_idx[1] = idx;
                }
		else if (strncmp(section_name, ".dynstr", 7) == 0)
                {
                    dynSym_idx[1] = idx;
                }
                break;

            case SHT_DYNSYM:        /* Dynamic linker symbol table (subset of symbol table) */
                dynSym_idx[0] = idx;
                break;
        }
    }
}


/**
 * Look through ELF sections looking for the symbol we are interesting
 *
 * @param[in] elf_info Like a this pointer contains ELF file info
 * @param[in,out] sym_to_find The symbol we are looking for
 * @param[in] print_shdr_table If this is the first time this table is read then print it via logging
 *    functions
 */
static void search_elf_sections_for_symbol(const Elf_info * elf_info, Sym2Addr * sym_to_find, bool print_shdr_tab)
{
    bool found_some = false;

    /* Look through the section header table */
    LOG_DEBUG("HERE1");
    int idx = elf_info->get_section_idx(SHT_DYNSYM, print_shdr_tab);
    if(idx > 0)
    {
        unsigned symstr_idx = elf_info->get_section_link(idx);
        found_some = search_elf_symbol_section_for_sym(elf_info, idx, symstr_idx, sym_to_find);
    }

    if(!found_some)
    {
        idx = elf_info->get_section_idx(SHT_SYMTAB);
        if(idx > 0)
        {
            unsigned symstr_idx = elf_info->get_section_link(idx);
            found_some = search_elf_symbol_section_for_sym(elf_info, idx, symstr_idx, sym_to_find);
        }
    }
    LOG_DEBUG("HERE3");
}

/**
 * Look through ELF sections looking for the address we are interesting
 *
 * @param[in] elf_info Like a this pointer contains ELF file info
 * @param[in,out] sym_to_find The symbol we are looking for
 * @param[in] print_shdr_table If this is the first time this table is read then print it via logging
 *    functions
 */
static void search_elf_sections_for_address(const Elf_info * elf_info, Addr2Sym * addr_to_find, bool print_shdr_tab)
{
    /* Look through the section header table */
    int symtab_idx[2] = {-1,-1};
    int dynSym_idx[2] = {-1,-1};

    get_symbol_table_sections(elf_info, print_shdr_tab, &symtab_idx[0], &dynSym_idx[0]);

    /* Look in the Dynamic symbol table first as they never get stripped */
    if((dynSym_idx[0] >= 0) && (dynSym_idx[1] >= 0))
    {
        search_elf_symbol_section_for_addr(elf_info, dynSym_idx[0], dynSym_idx[1], addr_to_find);
    }
    if((symtab_idx[0] >= 0) && (symtab_idx[1] >= 0))
    {
        search_elf_symbol_section_for_addr(elf_info, symtab_idx[0], symtab_idx[1], addr_to_find);
    }
}


/**
 * Look in the elf file specificied and find the symbol we are after
 *
 * @param[in] elf_info The this pointer to structure containg elf info
 * @param[in,out] sym_to_find The symbol to find
 */
static void find_symbol_in_elf(Elf_info * elf_info, Sym2Addr * sym_to_find)
{
    bool just_opened = false;
    if(!elf_info->m_shdr)
    {
        elf_info->get_elf_section_header_table();
        just_opened = true;
    }
    if(elf_info->m_shdr)
    {
        search_elf_sections_for_symbol(elf_info, sym_to_find, just_opened);
    }
}

static void find_closest_symbol_in_elf(Elf_info * elf_info, Addr2Sym * addr_to_find)
{
    bool just_opened = false;
    if(!elf_info->m_shdr)
    {
        elf_info->get_elf_section_header_table();
        just_opened = true;
    }
    if(elf_info->m_shdr)
    {
        search_elf_sections_for_address(elf_info, addr_to_find, just_opened);
    }
}

static FILE * open_memory_map(pid_t pid)
{
    char memory_map[50];
    snprintf(memory_map, sizeof(memory_map), "/proc/%i/maps", pid);
    return fopen(memory_map, "r");
}

/**
 * Find the symbol in the process by looking up in the ELF files that
 * make up the process memory map space
 *
 * @param[in] pid The process to inspect
 * @param[in] library Optional library
 * @param[in,out] symbol Structure containg symbol info
 */
void find_addr_of_symbol(pid_t pid, const char * library, Sym2Addr * sym_to_find)
{

    sym_to_find->reset();

    FILE * mem_fp = open_memory_map(pid);
    if(mem_fp)
    {
        Elf_info * elf_info = NULL;

        char linebuf[256];
        while(fgets(linebuf, sizeof(linebuf), mem_fp) != NULL)
        {
            Map_entry * next_map_entry = Map_entry::parse_map_entry(linebuf);

            if(!next_map_entry->has_permissions() || !next_map_entry->match_library(library))
            {
                delete next_map_entry;
                continue;
            }
            if(!elf_info)
            {
                elf_info = Elf_info::create(next_map_entry);
            }
            else if(!elf_info->m_mem_map->same_pathname(next_map_entry))
            {
                delete elf_info;
                elf_info = Elf_info::create(next_map_entry);
            }
            else
            {
                elf_info->switch_map(next_map_entry);
            }
            find_symbol_in_elf(elf_info, sym_to_find);
        }
        fclose(mem_fp);
        delete elf_info;
    }
}


/**
 * Find the closest symbol to the address ain the Addr2Sym and fill
 * that structure with the matching symbols(s)
 *
 * @param[in] pid The Process to find the symbol in
 * @param[in,out] addr_to_find Structure containg the details of
 *       the match
 */
void find_closest_symbol(pid_t pid, Addr2Sym * addr_to_find)
{
    addr_to_find->reset();

    FILE * mem_fp = open_memory_map(pid);
    if(mem_fp)
    {
        Elf_info * elf_info = NULL;
        char linebuf[256];
        while(fgets(linebuf, sizeof(linebuf), mem_fp) != NULL)
        {
            Map_entry * next_map_entry = Map_entry::parse_map_entry(linebuf);

            if(!next_map_entry->has_permissions() ||
                    !next_map_entry->contains(addr_to_find->value()))
            {
                delete next_map_entry;
                continue;
            }

            LOG_DEBUG("Address in %s", next_map_entry->pathname());

            /* Initially add the library as the symbol */
            addr_to_find->update(next_map_entry->start_address(), next_map_entry->pathname());

            if(!elf_info)
            {
                elf_info = Elf_info::create(next_map_entry);
            }
            else if(!elf_info->m_mem_map->same_pathname(next_map_entry))
            {
                delete elf_info;
                elf_info = Elf_info::create(next_map_entry);
            }
            else
            {
                elf_info->switch_map(next_map_entry);
            }
            
            find_closest_symbol_in_elf(elf_info, addr_to_find);

        }
        fclose(mem_fp);
        delete elf_info;
    }
}
