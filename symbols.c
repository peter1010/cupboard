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

INIT_LOGGING;

/**
 * Structure containing a parsed text line from the memory map proc file
 */
struct Map_entry_s
{
    MemPtr_t start_address;
    MemPtr_t end_address;
    int permissions;                  /* r/w/x/p */
    unsigned long offset_into_file;   /* if region mapped from file, the offset into file */
    char pathname[256];               /* if region mapped from file, the file pathname */ 
};

typedef struct Map_entry_s Map_entry_t;

/**
 * Information collected as the Elf file associated with Map_entry is parsed
 */
struct Elf_info_s
{
    Map_entry_t * mem_map;
    int fd;

    unsigned int e_shnum;  /* Number of entrie in section header table */
    unsigned int e_shentsize;
    unsigned int e_shoff;
    unsigned int e_shstrndx;
 
    void * shdr;     /* Elf section header table */
    char * shstrtab;
};

typedef struct Elf_info_s Elf_info_t;

/**
 * Version of malloc that terminates the program when we run out of
 * memory.
 *
 * @param[in] size The size of memory to allocate
 *
 * @return Pointer to the allocated memory
 */
static void * xalloc(size_t size)
{
    void * mem = malloc(size);
    if(mem == NULL) 
    {
        ERROR_MSG("Out of memory");
	exit(1);
    }
    return mem;
}

/**
 * Parse an entry in the /proc/xxx/map output
 *
 * @param[in] linebuf A line of text from /proc/xxx/maps
 *
 * @return Allocated memory containing the Map_entry structure
 */
static Map_entry_t * parse_map_entry(const char * linebuf)
{
    Map_entry_t * entry = xalloc(sizeof(Map_entry_t));

    unsigned long start_address = 0;
    unsigned long end_address = 0;
    char permissions[10] = {0};
    unsigned short dev_major;
    unsigned short dev_minor;
    unsigned long file_inode;
    const int num_parsed = sscanf(linebuf, "%lx-%lx %5s %lx %hu:%hu %lu %256s",
			                   &start_address, 
                                           &end_address, 
                                           &permissions[0],
                                           &entry->offset_into_file,
                                           &dev_major,
                                           &dev_minor,
                                           &file_inode,
                                           &entry->pathname[0]);
    if(num_parsed == 7)
    {
        entry->pathname[0] = '\0';
    }
    else if(num_parsed != 8)
    {
        ERROR_MSG("Failed to correctly read memory map");
        exit(1);
    }
  
    entry->start_address = (MemPtr_t) start_address;
    entry->end_address = (MemPtr_t) end_address;
    entry->permissions = 0;

    char * p = permissions;
    for(; *p; p++)
    {
        switch(*p)
        {
            case 'r':
                entry->permissions |= PROT_READ;
                break;

            case 'w':
                entry->permissions |= PROT_WRITE;
                break;

            case 'x':
                entry->permissions |= PROT_EXEC;
                break;

            case '-':
            case 'p':
            case 's':
                break;

            default:
                ERROR_MSG("Invalid character '%c' found in memory map entry '%s'", *p, linebuf);
                exit(EXIT_FAILURE);
                break;
        }
    }
    DEBUG_MSG("%8p-%8p %s %08lx %s", 
			     entry->start_address, 
                             entry->end_address, 
                             permissions,
                             entry->offset_into_file,
                             entry->pathname);
    return entry;
}

/**
 * Does the to_find library match the one we have found.
 *
 * @param[in] to_find The string to find
 * @param[in] poss A possible library to test against
 *
 * @return true if match
 */
static bool match_library(const char * to_find, const char * poss)
{
    if(*poss == '\0')
    {
        return false;
    }
    if(to_find == NULL)
    {
        return true;
    }

    const char * start = strrchr(poss, '/');
    start = (start == NULL) ? poss : &start[1];
    const char * end = strchr(start, '-');
    const int len = (end == NULL) ? strlen(start) : end-start;

    bool success = (strncmp(start, to_find, len) == 0) ? true : false;
    if(!success)
    {
        DEBUG_MSG("ignoring '%s' != '%s'", to_find, poss);
    }
    return success;
}

/**
 * Test if the ELF info is for a 32bit Elf file
 *
 * @paran[in] elf_info The Elf info data
 *
 * @return true if 32bit ELF
 */
static bool is_elf_32bit(const Elf_info_t * elf_info)
{
    return (elf_info->e_shentsize == sizeof(Elf32_Shdr)) ? true : false;
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
    return (elf_info->e_shentsize == sizeof(Elf64_Shdr)) ? true : false;
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

    if(is_elf_32bit(elf_info))
    {
        const Elf32_Shdr * shdr = &((const Elf32_Shdr *)elf_info->shdr)[shndx];

        size = shdr->sh_size;
        offset = shdr->sh_offset;
    }
    else
    {
        const Elf64_Shdr * shdr = &((const Elf64_Shdr *)elf_info->shdr)[shndx];

        size = shdr->sh_size;
        offset = shdr->sh_offset;
 
    }
    void * section = xalloc(size);
    if( pread(elf_info->fd, section, size, offset) != size)
    {
        ERROR_MSG("Failed to read section table");
        free(section);
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
    if(is_elf_32bit(elf_info))
    {
        const Elf32_Shdr * symtab = &((const Elf32_Shdr *)elf_info->shdr)[symtab_idx];
        size = symtab->sh_size;
        ele_size = symtab->sh_entsize;
        assert(sizeof(Elf32_Sym) == ele_size);
    }
    else
    {
        const Elf64_Shdr * symtab = &((const Elf64_Shdr *)elf_info->shdr)[symtab_idx];
        size = symtab->sh_size;
        ele_size = symtab->sh_entsize;
        assert(sizeof(Elf32_Sym) == ele_size);
    }
    int num_of_symbols = size / ele_size;
    DEBUG_MSG("Number of symbols is %i", num_of_symbols);
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
    if(is_elf_32bit(elf_info))
    {
        const Elf32_Shdr * shdr = &((const Elf32_Shdr *)elf_info->shdr)[shndx];
        offset = shdr->sh_offset;
    }
    else
    {
        const Elf64_Shdr * shdr = &((const Elf64_Shdr *)elf_info->shdr)[shndx];
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
    if(is_elf_32bit(elf_info))
    {
        const Elf32_Shdr * shdr = &((const Elf32_Shdr *)elf_info->shdr)[shndx];
        address = shdr->sh_addr;
    }
    else
    {
        const Elf64_Shdr * shdr = &((const Elf64_Shdr *)elf_info->shdr)[shndx];
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
            if((elf_info->mem_map->permissions & PROT_EXEC) == 0)
            {
                return false;
            }
            break;

        case STT_OBJECT:
            if((elf_info->mem_map->permissions & (PROT_WRITE | PROT_READ)) == 0)
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
        if((value >= elf_info->mem_map->end_address) || (value < elf_info->mem_map->start_address))
        {
            return false;
        }
    }
    else if(st_shndx >= elf_info->e_shnum)
    {
//        char  * symstr = (char *) get_elf_section(elf_info, strtab_idx);
//        WARN_MSG("CHECK %s %u", &symstr[pSym->st_name], pSym->st_shndx);
//        free(symstr);
        return false;
    }
    else /* Get the section that this symbol can be found in */
    {
        unsigned sh_offset = get_section_offset(elf_info, st_shndx);

        /* Is this section mapped into the memory map entry we are searching */
        if((sh_offset < elf_info->mem_map->offset_into_file)
                              || (sh_offset >= elf_info->mem_map->offset_into_file 
                                    + (elf_info->mem_map->end_address - elf_info->mem_map->start_address)))
        {
            return false;
        }
        unsigned sh_addr = get_section_address(elf_info, st_shndx);

        value = (MemPtr_t) get_raw_symbol_value(elf_info, symbols, idx)
                            + (unsigned long) elf_info->mem_map->start_address 
                            - sh_addr - elf_info->mem_map->offset_into_file + sh_offset;
//        DEBUG_MSG("ELF Shdr, %08lx %08lx-%08lx", (unsigned long) sh_addr,
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
const static char * get_symbol_name(const Elf_info_t * elf_info, const void * symbols, int idx, const char * symstr)
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
static bool search_elf_symbol_section_for_sym(const Elf_info_t * elf_info, int symtab_idx, int strtab_idx, Sym2Addr_t * sym_to_find)
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
        DEBUG_MSG("%08lx => %s (%i) {%i}", (unsigned long) pSym->st_value, symbol_name, pSym->st_size, pSym->st_shndx);
        if(strcmp(sym_to_find->name, symbol_name) == 0)
        {
            found = true;
            DEBUG_MSG("++++++ Matched %s ++++++ ", symbol_name);
            int i;
            for(i = 0; i < sym_to_find->cnt; i++)
            {
                if( sym_to_find->values[i] == value)
                {
                    DEBUG_MSG("Duplicate");
                    break;
                }
            }
            if(i == sym_to_find->cnt)
            {
                sym_to_find->values[sym_to_find->cnt] = value;
            
                DEBUG_MSG("%p => %s", value, symbol_name);
                DEBUG_MSG("Mem_map => %8p - %8p", elf_info->mem_map->start_address, elf_info->mem_map->end_address);
                DEBUG_MSG("offset into file => %08lx", elf_info->mem_map->offset_into_file);
                DEBUG_MSG("++++++  ++++++ ");
                if(++sym_to_find->cnt >= MAX_NUM_ADDRS_PER_SYM)
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
static void search_elf_symbol_section_for_addr(const Elf_info_t * elf_info, int symtab_idx, int strtab_idx, Addr2Sym_t * addr_to_find)
{
    int distance = addr_to_find->distance;
    int num_of_symbols = get_number_of_symbols(elf_info, symtab_idx);
    if(num_of_symbols == 0)
    {   
        return;
    }
    void * symbols = get_elf_section(elf_info, symtab_idx);

    char * symstr = (char *) get_elf_section(elf_info, strtab_idx);

    int bestIdx = -1;
    MemPtr_t bestValue = NULL;

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
        DEBUG_MSG("%08lx => %s (%i) {%i}", (unsigned long) pSym->st_value, symbol_name, pSym->st_size, pSym->st_shndx);
        int offset = addr_to_find->value - value;
        if((offset >= 0) && (offset < distance))
        {
            distance = offset;
            bestIdx = i;
            bestValue = value;
        }
    }

    if(bestIdx >= 0)
    {
        const char * symbol_name = get_symbol_name(elf_info, symbols, bestIdx, symstr);

        DEBUG_MSG("++++++ Best matched %s ++++++ ", symbol_name);
            
        DEBUG_MSG("%p => %s", bestValue, symbol_name);
        DEBUG_MSG("Mem_map => %8p - %8p", elf_info->mem_map->start_address, elf_info->mem_map->end_address);
        DEBUG_MSG("offset into file => %08lx", elf_info->mem_map->offset_into_file);
        DEBUG_MSG("++++++  ++++++ ");

        addr_to_find->distance = distance;
        strncpy(addr_to_find->name, symbol_name, MAX_SYMBOL_NAME_LEN);
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
    size_t size = elf_info->e_shentsize * elf_info->e_shnum;
    void * buf = xalloc(size);
    if( pread(elf_info->fd, buf, size, elf_info->e_shoff) != size)
    {
        ERROR_MSG("Failed to Read ELF section header table");
        free(buf);
        exit(0);
    }
    elf_info->shdr = buf;

    char * shstrtab = (char *) get_elf_section(elf_info, elf_info->e_shstrndx);
    if( shstrtab == NULL)
    {
        ERROR_MSG("Failed to Read ELF section header table section names");
        free(buf);
        elf_info->shdr = NULL;
        exit(0);
    }

    elf_info->shdr = buf;
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
            ERROR_MSG("Unknown sh_type %i(%x)", sh_type, sh_type);
            exit(0);
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
    else
    {
        const Elf64_Shdr * shdr = &((const Elf64_Shdr *)elf_info->shdr)[shndx];
        _typ = shdr->sh_type;
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
    int idx = 0;
    for(; idx < elf_info->e_shnum; idx++)
    {
        char * section_name = get_section_name(elf_info, idx);

        unsigned _typ = get_section_type(elf_info, idx);

        if(print_shdr_tab)
        {
            DEBUG_MSG("ELF Shdr[%02u] %19s %11s ", idx, section_name, shtype2str(_typ));
//            DEBUG_MSG_APPEND("%08lx %08lx-%08lx", (unsigned long) pShdr->sh_addr, 
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
static void search_elf_sections_for_symbol(const Elf_info_t * elf_info, Sym2Addr_t * sym_to_find, bool print_shdr_tab)
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
static void search_elf_sections_for_address(const Elf_info_t * elf_info, Addr2Sym_t * addr_to_find, bool print_shdr_tab)
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
 * Get the Elf header
 *
 * @param[in] fd The open file descriptor for the ELF file
 * @param[in] pathname The name of the Elf file
 *
 * @return True if this indeed is an Elf file
 */
static bool parse_elf_header(Elf_info_t * elf_info)
{
    bool good = false;
    void * buf = xalloc(sizeof(Elf64_Ehdr));
    const unsigned int num =  read(elf_info->fd, buf, sizeof(Elf64_Ehdr));
    
    if(num >= sizeof(Elf32_Ehdr))
    {
        Elf32_Ehdr * ehdr = buf;
	if( (memcmp(ELFMAG, ehdr->e_ident, SELFMAG) == 0)
               && (sizeof(Elf32_Ehdr) == ehdr->e_ehsize)
                  && (sizeof(Elf32_Shdr) == ehdr->e_shentsize))
        {
            good = true;
            elf_info->e_shnum = ehdr->e_shnum;
            elf_info->e_shentsize = ehdr->e_shentsize;
            elf_info->e_shoff = ehdr->e_shoff;
            elf_info->e_shstrndx = ehdr->e_shstrndx;
        }
    }

    if(!good && (num >= sizeof(Elf64_Ehdr)))
    {
        Elf64_Ehdr * ehdr = buf;
	if( (memcmp(ELFMAG, ehdr->e_ident, SELFMAG) == 0)
               && (sizeof(Elf64_Ehdr) == ehdr->e_ehsize)
                  && (sizeof(Elf64_Shdr) == ehdr->e_shentsize))
        {
            good = true;
            elf_info->e_shnum = ehdr->e_shnum;
            elf_info->e_shentsize = ehdr->e_shentsize;
            elf_info->e_shoff = ehdr->e_shoff;
            elf_info->e_shstrndx = ehdr->e_shstrndx;
        }
    }

    free(buf);
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
    int fd = open(elf_info->mem_map->pathname, O_RDONLY);
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
static void find_symbol_in_elf(Elf_info_t * elf_info, Sym2Addr_t * sym_to_find)
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

static void find_closest_symbol_in_elf(Elf_info_t * elf_info, Addr2Sym_t * addr_to_find)
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

/**
 * Initialise the Sym2Addr_t structure to have no found values
 *
 * @param[in,out] sym The structure containg symbol name and values
 */
static void init_symbol_struct(Sym2Addr_t * sym)
{
    if(sym == NULL)
    {
        ERROR_MSG("Null pointer for Sym2Addr_t");
        exit(EXIT_FAILURE);
    }

    const char * symbol = sym->name;
    memset(sym, 0, sizeof(Sym2Addr_t));
    sym->name = symbol;
}

/**
 * Initialise the Addr2Sym_t structure to have no found values
 *
 * @param[in,out] addr The structure containg symbol name and values
 */
static void init_address_struct(Addr2Sym_t * addr)
{
    if(addr == NULL)
    {
        ERROR_MSG("Null pointer for Addr2Sym_t");
        exit(EXIT_FAILURE);
    }

    MemPtr_t addr_ = addr->value;
    memset(addr, 0, sizeof(Addr2Sym_t));
    addr->value = addr_;
    addr->distance = INT_MAX;
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
void find_addr_of_symbol(pid_t pid, const char * library, Sym2Addr_t * sym_to_find)
{
    Elf_info_t elf_info;
    init_elf_info_struct(&elf_info);

    init_symbol_struct(sym_to_find);

    FILE * mem_fp = open_memory_map(pid);
    if(mem_fp)
    {
        char linebuf[256];
        while(fgets(linebuf, sizeof(linebuf), mem_fp) != NULL)
        {
            Map_entry_t * next_map_entry = parse_map_entry(linebuf);

            if((next_map_entry->permissions == 0) || !match_library(library, next_map_entry->pathname))
            {
                free(next_map_entry);
                continue;
            }
            if(elf_info.mem_map)     /* Is there a previous map_entry? */
            {
                /* But it's a different ELF file */
                if(strcmp(elf_info.mem_map->pathname, next_map_entry->pathname) != 0)
                {
                    free_elf_info_struct(&elf_info);
                }
                else
                {
                    free(elf_info.mem_map); 
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
 * Find the closest symbol to the address ain the Addr2Sym_t and fill
 * that structure with the matching symbols(s)
 *
 * @param[in] pid The Process to find the symbol in
 * @param[in,out] addr_to_find Structure containg the details of
 *       the match
 */
void find_closest_symbol(pid_t pid, Addr2Sym_t * addr_to_find)
{
    Elf_info_t elf_info;
    init_elf_info_struct(&elf_info);
    
    init_address_struct(addr_to_find);

    FILE * mem_fp = open_memory_map(pid);
    if(mem_fp)
    {
        char linebuf[256];
        while(fgets(linebuf, sizeof(linebuf), mem_fp) != NULL)
        {
            Map_entry_t * next_map_entry = parse_map_entry(linebuf);

            if((next_map_entry->permissions == 0) ||
                    (addr_to_find->value < next_map_entry->start_address) 
                                 || (addr_to_find->value >= next_map_entry->end_address))
            {
                free(next_map_entry);
                continue;
            }

            DEBUG_MSG("Address in %s", next_map_entry->pathname);

            if(elf_info.mem_map)     /* Is there a previous map_entry? */
            {
                /* But it's a different ELF file */
                if(strcmp(elf_info.mem_map->pathname, next_map_entry->pathname) != 0)
                {
                    free_elf_info_struct(&elf_info);
                }
                else
                {
                    free(elf_info.mem_map); 
                    elf_info.mem_map = NULL;
                }
            }
            elf_info.mem_map = next_map_entry;
            int distance = addr_to_find->value - next_map_entry->start_address;
            if(distance < addr_to_find->distance)
            {
                strncpy(addr_to_find->name, next_map_entry->pathname, MAX_SYMBOL_NAME_LEN);
                addr_to_find->distance = distance;
            }
            find_closest_symbol_in_elf(&elf_info, addr_to_find);
        }
        fclose(mem_fp);
    }
    free_elf_info_struct(&elf_info);
}
