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
    unsigned short dev_major;         /* if region mapped from file, the major/minor dev where file lives */
    unsigned short dev_minor;         
    unsigned long file_inode;         /* if region mapped from file, the file inode number */ 
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
    Elf32_Ehdr * ehdr;
    Elf32_Shdr * shdr;     /* Elf section header table */
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
    const int num_parsed = sscanf(linebuf, "%lx-%lx %5s %lx %hu:%hu %lu %256s",
			                   &start_address, 
                                           &end_address, 
                                           &permissions[0],
                                           &entry->offset_into_file,
                                           &entry->dev_major,
                                           &entry->dev_minor,
                                           &entry->file_inode,
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
                break;

            default:
                ERROR_MSG("Invalid character '%c' found in memory map entry", *p);
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
 * Get contents of elf section
 *
 * @param[in] shdr A Section header from section header table
 * @parms[in] fd
 *
 * @return Section contents in a malloced memory block
 */
static void * get_elf_section(const Elf32_Shdr * shdr, int fd)
{
    void * section = xalloc(shdr->sh_size);
    if( pread(fd, section, shdr->sh_size, shdr->sh_offset) != shdr->sh_size)
    {
        ERROR_MSG("Failed to read section table");
        free(section);
        exit(0);
    }
    return section;
}

/**
 * Get the symbol table
 *
 * @param[in] elf_info Details about the Elf file
 * @param[in] symtab_idx The index in the Section header table of symbol table in question
 * @param[out] pNum_of_symbols The number of symbols found
 *
 * @return Allocated memory containing the symbols
 */
static Elf32_Sym * get_symbol_table(const Elf_info_t * elf_info, int symtab_idx, int * pNum_of_symbols)
{
    Elf32_Shdr * symtab = &elf_info->shdr[symtab_idx];
    int num_of_symbols = symtab->sh_size / sizeof(Elf32_Sym);
    assert(sizeof(Elf32_Sym) == symtab->sh_entsize);
    DEBUG_MSG("Number of symbols is %i", num_of_symbols);
    if(num_of_symbols <= 0)
    {   
        return NULL;
    }

    *pNum_of_symbols = num_of_symbols;
    return (Elf32_Sym *) get_elf_section(symtab, elf_info->fd);
}

/**
 * Get the Value of the symbol 
 *
 * @param[in] elf_info Elf file info
 * @param[in] pSym Pointer to the symbol in the symbol section
 * @param[out] pValue Place to put the value
 *
 * @return true if value has been found
 */
static bool get_symbol_value(const Elf_info_t * elf_info, const Elf32_Sym * pSym, MemPtr_t * pValue)
{
    /* Not interested in symbols that are not data or code */
    switch(ELF32_ST_TYPE(pSym->st_info))
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

    /* Not interested in symbols that are undefined */
    if(pSym->st_shndx == 0)
    {
        return false;
    }

    MemPtr_t value;
    if(pSym->st_shndx == SHN_ABS)
    {
        value = (MemPtr_t) pSym->st_value;
        /* Is this is not mapped into the memory map entry we are searching */
        if((value >= elf_info->mem_map->end_address) || (value < elf_info->mem_map->start_address))
        {
            return false;
        }
    }
    else if(pSym->st_shndx >= elf_info->ehdr->e_shnum)
    {
//        char  * symstr = (char *) get_elf_section(&elf_info->shdr[strtab_idx], elf_info->fd);
//        WARN_MSG("CHECK %s %u", &symstr[pSym->st_name], pSym->st_shndx);
//        free(symstr);
        return false;
    }
    else /* Get the section that this symbol can be found in */
    {
        Elf32_Shdr * shdr = &elf_info->shdr[pSym->st_shndx];
        /* Is this section mapped into the memory map entry we are searching */
        if((shdr->sh_offset < elf_info->mem_map->offset_into_file)
                              || (shdr->sh_offset >= elf_info->mem_map->offset_into_file 
                                    + (elf_info->mem_map->end_address - elf_info->mem_map->start_address)))
        {
            return false;
        }
        value = (MemPtr_t) pSym->st_value + (unsigned long) elf_info->mem_map->start_address 
                                                    - shdr->sh_addr - elf_info->mem_map->offset_into_file + shdr->sh_offset;
//        DEBUG_MSG("ELF Shdr, %08lx %08lx-%08lx", (unsigned long) shdr->sh_addr,
//                                                 (unsigned long) shdr->sh_offset, 
//                                                 (unsigned long) shdr->sh_offset+shdr->sh_size);
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
static bool search_elf_symbol_section_for_sym(const Elf_info_t * elf_info, int symtab_idx, int strtab_idx, Symbol_t * sym_to_find)
{
    bool found = false;

    int num_of_symbols;
    Elf32_Sym * symbols = get_symbol_table(elf_info, symtab_idx, &num_of_symbols);
    if(!symbols)
    {   
        return found;
    }

    char * symstr = NULL;  // (char *) get_elf_section(&elf_info->shdr[strtab_idx], elf_info->fd);

    Elf32_Sym * pSym = &symbols[0];
    for(; pSym < &symbols[num_of_symbols]; pSym++)
    {
        MemPtr_t value;
        if(!get_symbol_value(elf_info, pSym, &value))
        {
            continue;
        }

        if(symstr == NULL)
        {
            symstr = (char *) get_elf_section(&elf_info->shdr[strtab_idx], elf_info->fd);
        }
        char * symbol_name = &symstr[pSym->st_name];

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
static void search_elf_symbol_section_for_addr(const Elf_info_t * elf_info, int symtab_idx, int strtab_idx, Address_t * addr_to_find)
{
    int distance = addr_to_find->distance;

    int num_of_symbols;
    Elf32_Sym * symbols = get_symbol_table(elf_info, symtab_idx, &num_of_symbols);
    if(!symbols)
    {   
        return;
    }

    char * symstr = NULL;  // (char *) get_elf_section(&elf_info->shdr[strtab_idx], elf_info->fd);

    Elf32_Sym * pSym = &symbols[0];
    Elf32_Sym * pBestSym = NULL;
    MemPtr_t bestValue = NULL;
    for(; pSym < &symbols[num_of_symbols]; pSym++)
    {
        MemPtr_t value;
        if(!get_symbol_value(elf_info, pSym, &value))
        {
            continue;
        }
        
        if(symstr == NULL) 
        {
            symstr = (char *) get_elf_section(&elf_info->shdr[strtab_idx], elf_info->fd);
        }
        char * symbol_name = &symstr[pSym->st_name];

        DEBUG_MSG("%08lx => %s (%i) {%i}", (unsigned long) pSym->st_value, symbol_name, pSym->st_size, pSym->st_shndx);
        int offset = addr_to_find->value - value;
        if((offset >= 0) && (offset < distance))
        {
            distance = offset;
            pBestSym = pSym;
            bestValue = value;
        }
    }

    if(pBestSym)
    {
        char * symbol_name = &symstr[pBestSym->st_name];
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
 * @param[in] ehdr Elf header
 * @param[in] fd
 *
 * @return ELF section header table
 */
static Elf32_Shdr * get_elf_section_header_table(const Elf32_Ehdr * ehdr, int fd)
{
    size_t size = ehdr->e_shentsize * ehdr->e_shnum;
    Elf32_Shdr * shdr = (Elf32_Shdr *) xalloc(size);
    if( pread(fd, shdr, size, ehdr->e_shoff) != size)
    {
        ERROR_MSG("Failed to Read ELF section header table");
        free(shdr);
        exit(0);
    }
    return shdr;
}

/*
 * Get section header string table 
 *
 * @param[in] shdr Pointer to section header of section with section header table stings
 * @parma[in] fd File descriptor of ELF file
 *
 * @return Allocated memory that contains the strings
 */

static char * get_section_header_strings(const Elf32_Shdr * shdr, int fd)
{
//    assert((shdr->sh_flags & SHF_STRINGS) != 0);
    size_t size = shdr->sh_size;
    char * shstrtab = (char *) xalloc(size);
    if( pread(fd, shstrtab, size, shdr->sh_offset) != size)
    {
        ERROR_MSG("Failed to Read ELF section header table section names");
        free(shstrtab);
        exit(0);
    }
    return shstrtab;
}

/**
 * Debug function that converts a section headr type to a string
 *
 * @param[in] sh_type Section header type
 *
 * @return Pointer to const string
 */
const char * shtype2str(int sh_type)
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
    for(; idx < elf_info->ehdr->e_shnum; idx++)
    {
        Elf32_Shdr * pShdr = &elf_info->shdr[idx];
        char * section_name = &elf_info->shstrtab[pShdr->sh_name];

        if(print_shdr_tab)
        {
            DEBUG_MSG("ELF Shdr[%02u] %19s %11s ", idx, section_name, shtype2str(pShdr->sh_type));
            DEBUG_MSG_APPEND("%08lx %08lx-%08lx", (unsigned long) pShdr->sh_addr, 
                                                  (unsigned long) pShdr->sh_offset, 
                                                  (unsigned long) pShdr->sh_offset+pShdr->sh_size);
        }
        switch(pShdr->sh_type)
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
static void search_elf_sections_for_symbol(const Elf_info_t * elf_info, Symbol_t * sym_to_find, bool print_shdr_tab)
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
static void search_elf_sections_for_address(const Elf_info_t * elf_info, Address_t * addr_to_find, bool print_shdr_tab)
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
 * @return Allocated memory containg the elf header
 */
static Elf32_Ehdr * get_elf_header(int fd, const char * pathname)
{
    bool good = false;
    Elf32_Ehdr * ehdr = xalloc(sizeof(Elf32_Ehdr));
    if( read(fd, ehdr, sizeof(Elf32_Ehdr)) == sizeof(Elf32_Ehdr))
    {
	if( memcmp(ELFMAG, ehdr->e_ident, SELFMAG) != 0)
        {
	    INFO_MSG("No ELF magic found so not an ELF file  %s", pathname);
	}
        else if(sizeof(Elf32_Ehdr) != ehdr->e_ehsize)
        {
            WARN_MSG("Elf header size incorrect");
        }
        else if (sizeof(Elf32_Shdr) != ehdr->e_shentsize) 
        {
	    WARN_MSG("elf error");
	}
        else
        {
            good = true;
        }
    }

    if(!good)
    {
        free(ehdr);
        ehdr = NULL;
    }
    return ehdr;
}

/**
 * Open the ELF file and fill in some details into the elf_info struct
 *
 * @param[in,out] elf_info Like a this pointer contains ELF file info
 */
static void open_elf_file(Elf_info_t * elf_info)
{
    int fd = open(elf_info->mem_map->pathname, O_RDONLY);
    if( fd  > 0) 
    {
	Elf32_Ehdr * ehdr = get_elf_header(fd, elf_info->mem_map->pathname);
        Elf32_Shdr * shdr = NULL;
        char * shstrtab = NULL;

        if(ehdr)
        {
            shdr = get_elf_section_header_table(ehdr, fd);
            if(shdr)
            {
                shstrtab = get_section_header_strings(&shdr[ehdr->e_shstrndx], fd);
                if(shstrtab)
                {
                    elf_info->fd = fd;
                    elf_info->ehdr = ehdr;
                    elf_info->shdr = shdr;
                    elf_info->shstrtab = shstrtab;
                }
            }
        }

        if(elf_info->fd < 0)
        {
            free(shdr);
            free(ehdr);
            free(shstrtab);
            close(fd);
        }
    }
}

/**
 * Look in the elf file specificied and find the symbol we are after
 *
 * @param[in] elf_info The this pointer to structure containg elf info
 * @param[in,out] sym_to_find The symbol to find
 */
static void find_symbol_in_elf(Elf_info_t * elf_info, Symbol_t * sym_to_find)
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

static void find_closest_symbol_in_elf(Elf_info_t * elf_info, Address_t * addr_to_find)
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
void init_elf_info_struct(Elf_info_t * elf_info)
{
    memset(elf_info, 0, sizeof(Elf_info_t));
    elf_info->fd = -1;
}

/**
 * Free the elf info structure
 *
 * @param[in] elf_info
 */
void free_elf_info_struct(Elf_info_t * elf_info)
{
    if(elf_info->fd >= 0)
    {
        close(elf_info->fd);  
        elf_info->fd = -1;
    }
    free(elf_info->ehdr);  
    elf_info->ehdr = NULL;

    free(elf_info->shdr);  
    elf_info->shdr = NULL;

    free(elf_info->shstrtab);  
    elf_info->shstrtab = NULL;
}

/**
 * Initialise the Symbol_t structure to have no found values
 *
 * @param[in,out] sym The structure containg symbol name and values
 */
void init_symbol_struct(Symbol_t * sym)
{
    if(sym == NULL)
    {
        ERROR_MSG("Null pointer for Symbol_t");
        exit(EXIT_FAILURE);
    }

    const char * symbol = sym->name;
    memset(sym, 0, sizeof(Symbol_t));
    sym->name = symbol;
}

/**
 * Initialise the Address_t structure to have no found values
 *
 * @param[in,out] addr The structure containg symbol name and values
 */
void init_address_struct(Address_t * addr)
{
    if(addr == NULL)
    {
        ERROR_MSG("Null pointer for Address_t");
        exit(EXIT_FAILURE);
    }

    MemPtr_t addr_ = addr->value;
    memset(addr, 0, sizeof(Address_t));
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
void find_addr_of_symbol(pid_t pid, const char * library, Symbol_t * sym_to_find)
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
 * Find the closest symbol to the address ain the Address_t and fill
 * that structure with the matching symbols(s)
 *
 * @param[in] pid The Process to find the symbol in
 * @param[in,out] addr_to_find Structure containg the details of
 *       the match
 */
void find_closest_symbol(pid_t pid, Address_t * addr_to_find)
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
