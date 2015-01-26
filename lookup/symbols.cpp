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

    const unsigned ele_size = elf_info->get_section_element_size(symtab_idx);
    void * symbols = elf_info->load_elf_section(symtab_idx);
    char * symstr = static_cast<char *>(elf_info->load_elf_section(strtab_idx));

    int i;
    for(i = 0; i < num_of_symbols; i++)
    {
        symbols = &((uint8_t *)symbols)[ele_size];

        MemPtr_t value;
        if(!elf_info->get_symbol_value(symbols, &value))
        {
            continue;
        }

        const char * symbol_name = elf_info->get_symbol_name(symbols, symstr);

        if(sym_to_find->match(symbol_name))
        {
            found = true;
            LOG_DEBUG("++++++ Matched %s ++++++ ", symbol_name);
            if(sym_to_find->add_value(value))
            {
                LOG_DEBUG("%p => %s", value, symbol_name);
                elf_info->debug_print();
                LOG_DEBUG("++++++  ++++++ ");
                if(sym_to_find->full())
                {
                    break;
                }
            }
        }
    }
    delete [] symstr;
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

    const unsigned ele_size = elf_info->get_section_element_size(symtab_idx);
    void * symbols = elf_info->load_elf_section(symtab_idx);
    char * symstr = static_cast<char *>(elf_info->load_elf_section(strtab_idx));

    int i;
    for(i = 0; i < num_of_symbols; i++)
    {
        symbols = &((uint8_t *)symbols)[ele_size];

        MemPtr_t value;
        if(!elf_info->get_symbol_value(symbols, &value))
        {
            continue;
        }

        const char * symbol_name = elf_info->get_symbol_name(symbols, symstr);

        Elf32_Sym * pSym = &((Elf32_Sym *)symbols)[i];
        LOG_DEBUG("%08lx => %s (%i) {%i}", (unsigned long) pSym->st_value, symbol_name, pSym->st_size, pSym->st_shndx);

        if(addr_to_find->update(value, symbol_name))
        {
            LOG_DEBUG("++++++ Best matched %s ++++++ ", symbol_name);
            LOG_DEBUG("%p => %s", value, symbol_name);
            elf_info->debug_print();
            LOG_DEBUG("++++++  ++++++ ");
        }

    }
    delete [] symstr;
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
    int idx = elf_info->get_section_idx(SHT_DYNSYM, print_shdr_tab);
    if(idx > 0)
    {
        unsigned symstr_idx = elf_info->get_section_link(idx);
        search_elf_symbol_section_for_addr(elf_info, idx, symstr_idx, addr_to_find);
    }
    idx = elf_info->get_section_idx(SHT_SYMTAB);
    if(idx > 0)
    {
        unsigned symstr_idx = elf_info->get_section_link(idx);
        search_elf_symbol_section_for_addr(elf_info, idx, symstr_idx, addr_to_find);
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
    if(elf_info->load_elf_section_header_table(&just_opened))
    {
        search_elf_sections_for_symbol(elf_info, sym_to_find, just_opened);
    }
}

static void find_closest_symbol_in_elf(Elf_info * elf_info, Addr2Sym * addr_to_find)
{
    bool just_opened = false;
    if(elf_info->load_elf_section_header_table(&just_opened))
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
            else if(!elf_info->same_pathname(next_map_entry))
            {
                delete elf_info;
                elf_info = Elf_info::create(next_map_entry);
            }
            else
            {
                elf_info->switch_map(next_map_entry);
            }
            if(elf_info)
            {
                find_symbol_in_elf(elf_info, sym_to_find);
            }
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
            else if(!elf_info->same_pathname(next_map_entry))
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
