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

/**
 * Information collected as the Elf file associated with Map_entry is parsed
 */
struct Elf_info_s
{
    Map_entry * mem_map;
    int fd;

    int arch_size;
    unsigned int num_of_sections;
    unsigned int section_entry_size;
    unsigned int e_shoff;
    unsigned int e_shstrndx;

    uint8_t * shdr;     /* Elf section header table */
    char * shstrtab;
};

typedef struct Elf_info_s Elf_info_t;


/**
 * Test if the ELF info is for a 32bit Elf file
 *
 * @paran[in] elf_info The Elf info data
 *
 * @return true if 32bit ELF
 */
static bool is_elf_32bit(const Elf_info_t * elf_info)
{
    return (elf_info->arch_size == 32) ? true : false;
}

/**
 * Test if the ELF info is for a 64bit Elf file
 *
 * @paran[in] elf_info The Elf info data
 *
 * @return true if 64bit ELF
 */
static bool is_elf_64bit(const Elf_info_t * elf_info)
{
    return (elf_info->arch_size == 64) ? true : false;
}


/**
 * Get contents of elf section
 *
 * @paran[in] elf_info The Elf info data
 * @param[in] shndx The index in section header of the section to get
 *
 * @return Section contents in a malloced memory block
 */
static void * get_elf_section(const Elf_info_t * elf_info, int shndx)
{
    size_t size = 0;
    unsigned long offset = 0;
    uint8_t * p = &elf_info->shdr[shndx * elf_info->section_entry_size];

    if(is_elf_32bit(elf_info))
    {
        const Elf32_Shdr * shdr = (const Elf32_Shdr *)p;

        size = shdr->sh_size;
        offset = shdr->sh_offset;
    }
    else
    {
        const Elf64_Shdr * shdr = (const Elf64_Shdr *)p;

        size = shdr->sh_size;
        offset = shdr->sh_offset;

    }
    uint8_t * section = new uint8_t[size];
    if( pread(elf_info->fd, section, size, offset) != (int) size)
    {
        LOG_ERROR("Failed to read section table");
        delete [] section;
        exit(0);
    }
    return section;
}

/**
 * Get the number of symbols in symbol table
 *
 * @param[in] elf_info Details about the Elf file
 * @param[in] symtab_idx The index in the Section header table of symbol table in question
 *
 * @return The number of symbols
 */
static int get_number_of_symbols(const Elf_info_t * elf_info, int symtab_idx)
{
    unsigned size = 0;
    unsigned ele_size = 0;
    uint8_t * p = &elf_info->shdr[symtab_idx * elf_info->section_entry_size];

    if(is_elf_32bit(elf_info))
    {
        const Elf32_Shdr * symtab = (const Elf32_Shdr *)p;
        size = symtab->sh_size;
        ele_size = symtab->sh_entsize;
        assert(sizeof(Elf32_Sym) <= ele_size);
    }
    else
    {
        const Elf64_Shdr * symtab = (const Elf64_Shdr *)p;
        size = symtab->sh_size;
        ele_size = symtab->sh_entsize;
        assert(sizeof(Elf64_Sym) <= ele_size);
    }
    int num_of_symbols = size / ele_size;
    LOG_DEBUG("Number of symbols is %i", num_of_symbols);
    return num_of_symbols;
}

/**
 * Get the section offset value for the section sprcified by the
 * index
 *
 * @param[in] elf_info The Elf info data
 * @param[in] shndx The index in section header of the section to get
 *
 * @return the offset
 */
static unsigned get_section_offset(const Elf_info_t * elf_info, int shndx)
{
    unsigned offset = 0;
    uint8_t * p = &elf_info->shdr[shndx * elf_info->section_entry_size];

    if(is_elf_32bit(elf_info))
    {
        const Elf32_Shdr * shdr = (const Elf32_Shdr *)p;
        offset = shdr->sh_offset;
    }
    else
    {
        const Elf64_Shdr * shdr = (const Elf64_Shdr *)p;
        offset = shdr->sh_offset;
    }
    return offset;
}

/**
 * Get the section address value for the section sprcified by the
 * index
 *
 * @param[in] elf_info The Elf info data
 * @param[in] shndx The index in section header of the section to get
 *
 * @return the address
 */
static unsigned get_section_address(const Elf_info_t * elf_info, int shndx)
{
    unsigned address = 0;
    uint8_t * p = &elf_info->shdr[shndx * elf_info->section_entry_size];
    if(is_elf_32bit(elf_info))
    {
        const Elf32_Shdr * shdr = (const Elf32_Shdr *)p;
        address = shdr->sh_addr;
    }
    else
    {
        const Elf64_Shdr * shdr = (const Elf64_Shdr *)p;
        address = shdr->sh_addr;
    }
    return address;
}

/**
 * Get the symbol type value for the symbol specified by the
 * index
 *
 * @param[in] elf_info The Elf info data
 * @param[in] symbols Pointer to section containing the symbols
 * @param[in] idx The index in section header of the section to get
 *
 * @return the type
 */
static unsigned get_symbol_type(const Elf_info_t * elf_info, const void * symbols, int idx)
{
    unsigned _typ = 0;
    if(is_elf_32bit(elf_info))
    {
        const Elf32_Sym * pSym = &((const Elf32_Sym *)symbols)[idx];
        _typ = ELF32_ST_TYPE(pSym->st_info);
    }
    else
    {
        const Elf64_Sym * pSym = &((const Elf64_Sym *)symbols)[idx];
        _typ = ELF64_ST_TYPE(pSym->st_info);
    }
    return _typ;
}

/**
 * Get the symbol section value for the symbol specified by the
 * index
 *
 * @param[in] elf_info The Elf info data
 * @param[in] symbols Pointer to section containing the symbols
 * @param[in] idx The index in section header of the section to get
 *
 * @return the section index
 */
static unsigned get_symbol_section(const Elf_info_t * elf_info, const void * symbols, int idx)
{
    unsigned shndx = 0;
    if(is_elf_32bit(elf_info))
    {
        const Elf32_Sym * pSym = &((const Elf32_Sym *)symbols)[idx];
        shndx = pSym->st_shndx;
    }
    else
    {
        const Elf64_Sym * pSym = &((const Elf64_Sym *)symbols)[idx];
        shndx = pSym->st_shndx;
    }
    return shndx;
}

/**
 * Get the symbol value for the symbol specified by the
 * index
 *
 * @param[in] elf_info The Elf info data
 * @param[in] symbols Pointer to section containing the symbols
 * @param[in] idx The index in section header of the section to get
 *
 * @return the section index
 */
static MemPtr_t get_raw_symbol_value(const Elf_info_t * elf_info, const void * symbols, int idx)
{
    MemPtr_t value = 0;
    if(is_elf_32bit(elf_info))
    {
        const Elf32_Sym * pSym = &((const Elf32_Sym *)symbols)[idx];
        value = (MemPtr_t) (pSym->st_value);
    }
    else
    {
        const Elf64_Sym * pSym = &((const Elf64_Sym *)symbols)[idx];
        value = (MemPtr_t) (pSym->st_value);
    }
    return value;
}


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
static bool get_symbol_value(const Elf_info_t * elf_info, const void * symbols, int idx, MemPtr_t * pValue)
{

    /* Not interested in symbols that are not data or code */
    switch(get_symbol_type(elf_info, symbols, idx))
    {
        case STT_FUNC:
            if(!elf_info->mem_map->is_executable())
            {
                return false;
            }
            break;

        case STT_OBJECT:
            if(!elf_info->mem_map->is_accessable())
            {
                return false;
            }
            break;

        default:
            return false;
    }

    unsigned st_shndx = get_symbol_section(elf_info, symbols, idx);
    /* Not interested in symbols that are undefined */
    if(st_shndx == 0)
    {
        return false;
    }

    MemPtr_t value;
    if(st_shndx == SHN_ABS)
    {
        value = get_raw_symbol_value(elf_info, symbols, idx);
        /* Is this is not mapped into the memory map entry we are searching */
        if(!elf_info->mem_map->contains(value))
        {
            return false;
        }
    }
    else if(st_shndx >= elf_info->num_of_sections)
    {
//        char  * symstr = (char *) get_elf_section(elf_info, strtab_idx);
//        WARN_MSG("CHECK %s %u", &symstr[pSym->st_name], pSym->st_shndx);
//        free(symstr);
        return false;
    }
    else /* Get the section that this symbol can be found in */
    {
        unsigned sh_offset = get_section_offset(elf_info, st_shndx);

        MemPtr_t temp = elf_info->mem_map->foffset2addr(sh_offset);

        /* Is this section mapped into the memory map entry we are searching */
        if(!elf_info->mem_map->contains(temp))
        {
            return false;
        }
        unsigned sh_addr = get_section_address(elf_info, st_shndx);

        value = temp + (unsigned) get_raw_symbol_value(elf_info, symbols, idx) - sh_addr;
//        LOG_DEBUG("ELF Shdr, %08lx %08lx-%08lx", (unsigned long) sh_addr,
//                                                 (unsigned long) sh_offset,
//                                                 (unsigned long) sh_offset+shdr->sh_size);
    }
    *pValue = value;
    return true;
}

/**
 * Get the name of the symbol
 *
 * @param[in] elf_info Elf file info
 * @param[in] symbols Pointer to section containing the symbols
 * @param[in] idx The index in section header of the section to get
 * @param[in] symstr The string table
 *
 * @return The symbol name
 */
static const char * get_symbol_name(const Elf_info_t * elf_info, const void * symbols, int idx, const char * symstr)
{
    int name_idx = 0;
    if(is_elf_32bit(elf_info))
    {
        const Elf32_Sym * pSym = &((const Elf32_Sym *)symbols)[idx];
        name_idx = pSym->st_name;
    }
    else
    {
        const Elf64_Sym * pSym = &((const Elf64_Sym *)symbols)[idx];
        name_idx = pSym->st_name;
    }
    return &(symstr[name_idx]);
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
static bool search_elf_symbol_section_for_sym(const Elf_info_t * elf_info, int symtab_idx, int strtab_idx, Sym2Addr * sym_to_find)
{
    bool found = false;
    int num_of_symbols = get_number_of_symbols(elf_info, symtab_idx);
    if(num_of_symbols == 0)
    {
        return found;
    }

    void * symbols = get_elf_section(elf_info, symtab_idx);
    char * symstr = (char *) get_elf_section(elf_info, strtab_idx);

    int i;
    for(i = 0; i < num_of_symbols; i++)
    {
        MemPtr_t value;
        if(!get_symbol_value(elf_info, symbols, i, &value))
        {
            continue;
        }

        const char * symbol_name = get_symbol_name(elf_info, symbols, i, symstr);

        Elf32_Sym * pSym = &((Elf32_Sym *)symbols)[i];
        LOG_DEBUG("%08lx => %s (%i) {%i}", (unsigned long) pSym->st_value, symbol_name, pSym->st_size, pSym->st_shndx);
        if(sym_to_find->match(symbol_name))
        {
            found = true;
            LOG_DEBUG("++++++ Matched %s ++++++ ", symbol_name);
            if(sym_to_find->add_value(value))
            {
                LOG_DEBUG("%p => %s", value, symbol_name);
                elf_info->mem_map->debug_print();
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
static void search_elf_symbol_section_for_addr(const Elf_info_t * elf_info, int symtab_idx, int strtab_idx, Addr2Sym * addr_to_find)
{
    int num_of_symbols = get_number_of_symbols(elf_info, symtab_idx);
    if(num_of_symbols == 0)
    {
        return;
    }
    void * symbols = get_elf_section(elf_info, symtab_idx);

    char * symstr = (char *) get_elf_section(elf_info, strtab_idx);

    int i;
    for(i = 0; i < num_of_symbols; i++)
    {
        MemPtr_t value;
        if(!get_symbol_value(elf_info, symbols, i, &value))
        {
            continue;
        }

        const char * symbol_name = get_symbol_name(elf_info, symbols, i, symstr);

        Elf32_Sym * pSym = &((Elf32_Sym *)symbols)[i];
        LOG_DEBUG("%08lx => %s (%i) {%i}", (unsigned long) pSym->st_value, symbol_name, pSym->st_size, pSym->st_shndx);

        if(addr_to_find->update(value, symbol_name))
        {
            LOG_DEBUG("++++++ Best matched %s ++++++ ", symbol_name);
            LOG_DEBUG("%p => %s", value, symbol_name);
            elf_info->mem_map->debug_print();
            LOG_DEBUG("++++++  ++++++ ");
        }

    }
    free(symstr);
}

/**
 * Get section header from elf file
 *
 * @param[in] elf_info Elf info
 *
 * @return True on success
 */
static bool get_elf_section_header_table(Elf_info_t * elf_info)
{
    const ssize_t size = elf_info->section_entry_size * elf_info->num_of_sections;
    uint8_t * buf = new uint8_t[size];
    if( pread(elf_info->fd, buf, size, elf_info->e_shoff) != size)
    {
        LOG_ERROR("Failed to Read ELF section header table");
        delete [] buf;
        exit(0);
    }
    elf_info->shdr = static_cast<uint8_t *>(buf);

    char * shstrtab = (char *) get_elf_section(elf_info, elf_info->e_shstrndx);
    if( shstrtab == NULL)
    {
        LOG_ERROR("Failed to Read ELF section header table section names");
        delete [] buf;
        elf_info->shdr = NULL;
        exit(0);
    }

    elf_info->shdr = static_cast<uint8_t *>(buf);
    elf_info->shstrtab = shstrtab;

    return true;
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
 * Get the section name value for the section specified by the
 * index
 *
 * @param[in] elf_info The Elf info data
 * @param[in] shndx The index in section header of the section to get
 *
 * @return the section name
 */
static char * get_section_name(const Elf_info_t * elf_info, int shndx)
{
    int name_idx;
    if(is_elf_32bit(elf_info))
    {
        const Elf32_Shdr * shdr = &((const Elf32_Shdr *)elf_info->shdr)[shndx];
        name_idx = shdr->sh_name;
    }
    else
    {
        const Elf64_Shdr * shdr = &((const Elf64_Shdr *)elf_info->shdr)[shndx];
        name_idx = shdr->sh_name;
    }
    return &elf_info->shstrtab[name_idx];
}

/**
 * Get the section type value for the section specified by the
 * index
 *
 * @param[in] elf_info The Elf info data
 * @param[in] shndx The index in section header of the section to get
 *
 * @return the section name
 */
static unsigned get_section_type(const Elf_info_t * elf_info, int shndx)
{
    unsigned _typ = 0;
    if(is_elf_32bit(elf_info))
    {
        const Elf32_Shdr * shdr = &((const Elf32_Shdr *)elf_info->shdr)[shndx];
        _typ = shdr->sh_type;
    }
    else if(is_elf_64bit(elf_info))
    {
        const Elf64_Shdr * shdr = &((const Elf64_Shdr *)elf_info->shdr)[shndx];
        _typ = shdr->sh_type;
    }
    else
    {
        LOG_ERROR("Bad Elf bit size");
        exit(EXIT_FAILURE);
    }
    return _typ;
}


/**
 * Get the indexes of symbol table and string tables in the section header table
 *
 * @param[in] elf_info Structure containing Elf information (like a class this pointer)
 * @param[in] print_shdr_tab Print the section header info
 * @param[out] symtab_idx[2] Index of Symbol tablei/ strings section header in section header table
 * @param[out] dynSym_idx[2]_idx Index of String table/ strings section header in section header table
 */
static void get_symbol_table_sections(const Elf_info_t * elf_info, bool print_shdr_tab, int * symtab_idx, int * dynSym_idx)
{
    /* Look through the section header table */
    unsigned idx = 0;
    for(; idx < elf_info->num_of_sections; idx++)
    {
        char * section_name = get_section_name(elf_info, idx);

        unsigned _typ = get_section_type(elf_info, idx);

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
static void search_elf_sections_for_symbol(const Elf_info_t * elf_info, Sym2Addr * sym_to_find, bool print_shdr_tab)
{
    bool found_some = false;

    /* Look through the section header table */
    int symtab_idx[2] = {-1, -1};
    int dynSym_idx[2] = {-1, -1};

    get_symbol_table_sections(elf_info, print_shdr_tab, &symtab_idx[0], &dynSym_idx[0]);

    /* Look in the Dynamic symbol table first as they never get stripped */
    if((dynSym_idx[0] >= 0) && (dynSym_idx[1] >= 0))
    {
        found_some = search_elf_symbol_section_for_sym(elf_info, dynSym_idx[0], dynSym_idx[1], sym_to_find);
    }
    if((symtab_idx[0] >= 0) && (symtab_idx[1] >= 0) && !found_some)
    {
        search_elf_symbol_section_for_sym(elf_info, symtab_idx[0], symtab_idx[1], sym_to_find);
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
static void search_elf_sections_for_address(const Elf_info_t * elf_info, Addr2Sym * addr_to_find, bool print_shdr_tab)
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
 * Parse the Elf header
 *
 * @param[in] fd The open file descriptor for the ELF file
 * @param[in] pathname The name of the Elf file
 *
 * @return True if this indeed is an Elf file
 */
static bool parse_elf_header(Elf_info_t * elf_info)
{
    uint8_t buf[sizeof(Elf64_Ehdr)];
    bool good = false;
    const unsigned int num = read(elf_info->fd, buf, sizeof(buf));
    if(num < EI_NIDENT)
    {
        LOG_ERROR("Failed to read ELF ident");
        return false;
    }
    if(memcmp(ELFMAG, buf, SELFMAG) != 0)
    {
        LOG_ERROR("No ELF Magic seen for '%s'", elf_info->mem_map->pathname());
        return false;
    }
    switch(buf[EI_CLASS])
    {
        case ELFCLASS32:
            {
                const Elf32_Ehdr * ehdr = (const Elf32_Ehdr *)buf;

                if((sizeof(Elf32_Ehdr) <= ehdr->e_ehsize) && (sizeof(Elf32_Ehdr) <= num))
                {
                    good = true;
                    elf_info->arch_size = 32;
                    elf_info->num_of_sections = ehdr->e_shnum;
                    elf_info->section_entry_size = ehdr->e_shentsize;
                    elf_info->e_shoff = ehdr->e_shoff;
                    elf_info->e_shstrndx = ehdr->e_shstrndx;
                }
            }
            break;
        case ELFCLASS64:
            {
                const Elf64_Ehdr * ehdr = (const Elf64_Ehdr *)buf;

                if((sizeof(Elf64_Ehdr) <= ehdr->e_ehsize) && (sizeof(Elf64_Ehdr) <= num))
                {
                    good = true;
                    elf_info->arch_size = 64;
                    elf_info->num_of_sections = ehdr->e_shnum;
                    elf_info->section_entry_size = ehdr->e_shentsize;
                    elf_info->e_shoff = ehdr->e_shoff;
                    elf_info->e_shstrndx = ehdr->e_shstrndx;
                }
            }
            break;

        default:
            LOG_ERROR("Unknown class type");
            return false;
    }
    return good;
}

/**
 * Free the elf info structure
 *
 * @param[in] elf_info
 */
static void free_elf_info_struct(Elf_info_t * elf_info)
{
    if(elf_info->fd >= 0)
    {
        close(elf_info->fd);
        elf_info->fd = -1;
    }

    free(elf_info->shdr);
    elf_info->shdr = NULL;

    free(elf_info->shstrtab);
    elf_info->shstrtab = NULL;
}


/**
 * Open the ELF file and fill in some details into the elf_info struct
 *
 * @param[in,out] elf_info Like a this pointer contains ELF file info
 */
static void open_elf_file(Elf_info_t * elf_info)
{
    bool success = false;
    const int fd = elf_info->mem_map->open_elf();
    if( fd  > 0)
    {
        elf_info->fd = fd;
        if(parse_elf_header(elf_info))
        {
            success = get_elf_section_header_table(elf_info);
        }
    }
    if(!success)
    {
        free_elf_info_struct(elf_info);
    }
}

/**
 * Look in the elf file specificied and find the symbol we are after
 *
 * @param[in] elf_info The this pointer to structure containg elf info
 * @param[in,out] sym_to_find The symbol to find
 */
static void find_symbol_in_elf(Elf_info_t * elf_info, Sym2Addr * sym_to_find)
{
    bool just_opened = false;
    if(elf_info->fd < 0)
    {
        open_elf_file(elf_info);
        just_opened = true;
    }
    if(elf_info->fd >= 0)
    {
        search_elf_sections_for_symbol(elf_info, sym_to_find, just_opened);
    }
}

static void find_closest_symbol_in_elf(Elf_info_t * elf_info, Addr2Sym * addr_to_find)
{
    bool just_opened = false;
    if(elf_info->fd < 0)
    {
        open_elf_file(elf_info);
        just_opened = true;
    }
    if(elf_info->fd >= 0)
    {
        search_elf_sections_for_address(elf_info, addr_to_find, just_opened);
    }
}

/**
 * Initialse the Elf_into_t structure
 *
 * @param[in] elf_info
 */
static void init_elf_info_struct(Elf_info_t * elf_info)
{
    memset(elf_info, 0, sizeof(Elf_info_t));
    elf_info->fd = -1;
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
    Elf_info_t elf_info;
    init_elf_info_struct(&elf_info);

    sym_to_find->reset();

    FILE * mem_fp = open_memory_map(pid);
    if(mem_fp)
    {
        char linebuf[256];
        while(fgets(linebuf, sizeof(linebuf), mem_fp) != NULL)
        {
            Map_entry * next_map_entry = Map_entry::parse_map_entry(linebuf);

            if(!next_map_entry->has_permissions() || !next_map_entry->match_library(library))
            {
                delete next_map_entry;
                continue;
            }
            if(elf_info.mem_map)     /* Is there a previous map_entry? */
            {
                /* But it's a different ELF file */
                if(!elf_info.mem_map->same_pathname(next_map_entry))
                {
                    free_elf_info_struct(&elf_info);
                }
                else
                {
                    delete elf_info.mem_map;
                    elf_info.mem_map = NULL;
                }
            }
            elf_info.mem_map = next_map_entry;
            find_symbol_in_elf(&elf_info, sym_to_find);
        }
        fclose(mem_fp);
    }
    free_elf_info_struct(&elf_info);
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
    Elf_info_t elf_info;
    init_elf_info_struct(&elf_info);

    addr_to_find->reset();

    FILE * mem_fp = open_memory_map(pid);
    if(mem_fp)
    {
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

            if(elf_info.mem_map)     /* Is there a previous map_entry? */
            {
                /* But it's a different ELF file */
                if(!elf_info.mem_map->same_pathname(next_map_entry))
                {
                    free_elf_info_struct(&elf_info);
                }
                else
                {
                    delete elf_info.mem_map;
                    elf_info.mem_map = NULL;
                }
            }
            elf_info.mem_map = next_map_entry;
            /* Initially add the library as the symbol */
            addr_to_find->update(next_map_entry->start_address(), next_map_entry->pathname());

            find_closest_symbol_in_elf(&elf_info, addr_to_find);
        }
        fclose(mem_fp);
    }
    free_elf_info_struct(&elf_info);
}
