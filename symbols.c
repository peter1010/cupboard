#include <stdio.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

#include "symbols.h"
#include "logging.h"

INIT_LOGGING;

/**
 * Structure containing a parsed text line from the memory map proc file
 */
struct Map_entry_s
{
    unsigned long start_address;
    unsigned long end_address;
    char permissions[5];              /* r/w/x/p */
    unsigned long offset_into_file;   /* if region mapped from file, the offset into file */
    unsigned short dev_major;         /* if region mapped from file, the major/minor dev where file lives */
    unsigned short dev_minor;         
    unsigned long file_inode;         /* if region mapped from file, the file inode number */ 
    char pathname[256];               /* if region mapped from file, the file pathname */ 
};

typedef struct Map_entry_s Map_entry_t;

#define MAX_NUM_ADDRS_PER_SYM 5

/**
 * Information about the symbol we are looking for 
 */
struct Symbol_s
{
    const char * name;
    int cnt;
    Elf32_Addr values[MAX_NUM_ADDRS_PER_SYM];	     /* Symbol values, to be filled in when found */
};

typedef struct Symbol_s Symbol_t;

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
 * @param[out] entry Filled in with parsed info
 * @param[in] linebuf A line of text from /proc/xxx/maps
 *
 * @return Allocated memory containing the Map_entry structure
 */
static Map_entry_t * parse_map_entry(const char * linebuf)
{
    Map_entry_t * entry = xalloc(sizeof(Map_entry_t));

    const int num_parsed = sscanf(linebuf, "%lx-%lx %5s %lx %hu:%hu %lu %256s",
			                   &entry->start_address, 
                                           &entry->end_address, 
                                           &entry->permissions[0],
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
  
    DEBUG_MSG("%08lx-%08lx %s %08lx %s", 
			     entry->start_address, 
                             entry->end_address, 
                             entry->permissions,
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
    if(to_find == NULL)
        return true;

    if(*poss == '\0')
        return false;

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
 * @return Section contains in a malloced memory block
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
 * Search through the section looking for the symbol we are interesting
 *
 * @param[in] symtab Pointer to Symbol table section header
 * @param[in] strtab Pointer to corresponding string table header
 * @param[in,out] sym_to_find Pointer to structure conating info about symbol we are looking for
 * @param[in] fd The open file descriptor of elf file that we are searching
 *
 * @return True on success
 *
 */
static bool search_elf_symbol_section(const Elf_info_t * elf_info, int symtab_idx, int strtab_idx, Symbol_t * sym_to_find)
{
    bool found = false;

    Elf32_Shdr * symtab = &elf_info->shdr[symtab_idx];
    int num_of_symbols = symtab->sh_size / sizeof(Elf32_Sym);
    assert(sizeof(Elf32_Sym) == symtab->sh_entsize);
    DEBUG_MSG("Number of symbols is %i", num_of_symbols);
    if(num_of_symbols <= 0)
    {   
        return found;
    }

    Elf32_Sym * symbols = (Elf32_Sym *) get_elf_section(symtab, elf_info->fd);

    char * symstr = NULL;  // (char *) get_elf_section(&elf_info->shdr[strtab_idx], elf_info->fd);

    Elf32_Sym * pSym = &symbols[0];
    for(; pSym < &symbols[num_of_symbols]; pSym++)
    {

        /* Not interested in symbols that are not data or code */
        unsigned int _typ = ELF32_ST_TYPE(pSym->st_info);
        if((_typ != STT_FUNC) && (_typ != STT_OBJECT))
        {
            continue;
        }

        /* Not interested in symbols that are undefined */
        if(pSym->st_shndx == 0)
        {
            continue;
        }

        Elf32_Addr value;
        Elf32_Shdr * shdr = NULL;
        if(pSym->st_shndx == SHN_ABS)
        {
            /* Is this is not mapped into the memory map entry we are searching */
            if((pSym->st_value >= elf_info->mem_map->end_address) || (pSym->st_value < elf_info->mem_map->start_address))
            {
                continue;
            }
            value = pSym->st_value;
        }
        else if(pSym->st_shndx >= elf_info->ehdr->e_shnum)
        {
            if(symstr == NULL) 
                symstr = (char *) get_elf_section(&elf_info->shdr[strtab_idx], elf_info->fd);
            WARN_MSG("CHECK %s %u", &symstr[pSym->st_name], pSym->st_shndx);
            continue;
        }
        else /* Get the section that this symbol can be found in */
        {
            shdr = &elf_info->shdr[pSym->st_shndx];
            /* Is this section mapped into the memory map entry we are searching */
            if((shdr->sh_offset < elf_info->mem_map->offset_into_file)
                              || (shdr->sh_offset >= elf_info->mem_map->offset_into_file 
                                    + elf_info->mem_map->end_address - elf_info->mem_map->start_address))
            {
                continue;
            }
            value  = pSym->st_value + elf_info->mem_map->start_address 
                                                    - shdr->sh_addr - elf_info->mem_map->offset_into_file + shdr->sh_offset;
        }
        if(symstr == NULL) 
            symstr = (char *) get_elf_section(&elf_info->shdr[strtab_idx], elf_info->fd);
        char * symbol_name = &symstr[pSym->st_name];

        DEBUG_MSG("%08lx => %s (%i) {%i}", (unsigned long) pSym->st_value, symbol_name, pSym->st_size, pSym->st_shndx);
        if(strcmp(sym_to_find->name, symbol_name) == 0)
        {
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
            
                DEBUG_MSG("%08lx => %s", (unsigned long) value, symbol_name);
                DEBUG_MSG("Mem_map => %08lx - %08lx", elf_info->mem_map->start_address, elf_info->mem_map->end_address);
                DEBUG_MSG("offset into file => %08lx", elf_info->mem_map->offset_into_file);
                if(shdr)
                    DEBUG_MSG("ELF Shdr, %08lx %08lx-%08lx", (unsigned long) shdr->sh_addr,
                                                     (unsigned long) shdr->sh_offset, 
                                                     (unsigned long) shdr->sh_offset+shdr->sh_size);
                DEBUG_MSG("++++++  ++++++ ");
                if(++sym_to_find->cnt >= MAX_NUM_ADDRS_PER_SYM)
                {
                    found = true;
                    break;
                }
            }
        }
    }
    free(symstr);
    return found;
}

/**
 * Get section header from elf file
 *
 * @param[in] ehdr Elf header
 * @param[in] fd
 *
 * @return ELF section header table
 */
static Elf32_Shdr * get_elf_section_header_table(Elf32_Ehdr * ehdr, int fd)
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

static char * get_section_header_strings(Elf32_Shdr * shdr, int fd)
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
 * Look through ELF sections looking for the symbol we are interesting
 *
 * @param[in] ehdr Pointer to ELF file header
 * @param[in,out] sym_to_find The symbol we are looking for
 *
 * @param[in] fd The open file descriptor of elf file that we are searching
 */
static bool search_elf_sections(Elf_info_t * elf_info, Symbol_t * sym_to_find, bool print_shdr_tab)
{
    bool found = false;
    
    /* Look through the section header table */
    int symtab_idx = -1;
    int symtabStr_idx = -1;
    int dynSym_idx = -1;
    int dynSymStr_idx = -1;

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
                symtab_idx = idx;
                break;

            case SHT_STRTAB:        /* String table */
		if(strncmp(section_name, ".strtab", 7) == 0) 
                {
                    symtabStr_idx = idx;
                }
		else if (strncmp(section_name, ".dynstr", 7) == 0) 
                {
                    dynSymStr_idx = idx;
                }
                break;
 
            case SHT_DYNSYM:        /* Dynamic linker symbol table (subset of symbol table) */
                dynSym_idx = idx;
                break;
        }
    }

    /* Look in the Dynamic symbol table first as they never get stripped */
    if((dynSym_idx >= 0) && (dynSymStr_idx >= 0))
    {
        if(search_elf_symbol_section(elf_info, dynSym_idx, dynSymStr_idx, sym_to_find))
        {
            found = true;
        }
    }
    if((symtab_idx >= 0) && (symtabStr_idx >= 0) && !found)
    {
        if(search_elf_symbol_section(elf_info, symtab_idx, symtabStr_idx, sym_to_find))
        {
            found = true;
        }
    }
    return found;
}

/**
 * Get the Elf header
 *
 * @param[in] fd The open file descriptor for the ELF file
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
	    INFO_MSG("No ELF magic found so not an ELF file  %s\n", pathname);
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
 * Look in the elf file specificied and find the symbol we are after
 *
 * @param[in] mem_map The Memory map entry we are searching
 * @param[in,out] sym_to_find The symbol to find
 *
 * @return True if success
 */
static bool find_symbol_in_elf(Elf_info_t * elf_info, Symbol_t * sym_to_find)
{
    int fd = -1;
    if(elf_info->fd < 0)
    {
        if( (fd = open(elf_info->mem_map->pathname, O_RDONLY)) > 0) 
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

    bool found = false;
    if(elf_info->fd >= 0)
    {
        found = search_elf_sections(elf_info, sym_to_find, fd >= 0 ? true : false);
    }
    return found;
}

void init_elf_info_struct(Elf_info_t * elf_info)
{
    memset(elf_info, 0, sizeof(Elf_info_t));
    elf_info->fd = -1;
}

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

void init_symbol_struct(Symbol_t * sym, const char * symbol)
{
    memset(sym, 0, sizeof(Symbol_t));
    sym->name = symbol;
}

/**
 * Find the symbol in the process by looking up in the ELF files that
 * make up the process memory map space
 *
 * @param[in] pid The process to inspect
 * @param[in] library Optional library 
 */
void * find_addr_of_symbol(pid_t pid, const char * library, const char * symbol)
{
    Elf_info_t elf_info;
    init_elf_info_struct(&elf_info);

    Symbol_t sym_to_find;
    init_symbol_struct(&sym_to_find, symbol);

    char memory_map[50];
    snprintf(memory_map, sizeof(memory_map), "/proc/%i/maps", pid);
    FILE * mem_fp = fopen(memory_map, "r");
    if(mem_fp)
    {
        char linebuf[256];
        while(fgets(linebuf, sizeof(linebuf), mem_fp) != NULL)
        {
            Map_entry_t * next_map_entry = parse_map_entry(linebuf);

            if(!match_library(library, next_map_entry->pathname))
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

            if(find_symbol_in_elf(&elf_info, &sym_to_find))
            {
                break;
            }
        }
        fclose(mem_fp);
    }

    free_elf_info_struct(&elf_info);

    return sym_to_find.values[0];
}


char * find_closest_symbol(pid_t pid, const unsigned long addr)
{
    char * retVal = NULL;

    char memory_map[50];
    snprintf(memory_map, sizeof(memory_map), "/proc/%i/maps", pid);
    FILE * mem_fp = fopen(memory_map, "r");
    if(mem_fp)
    {
        char linebuf[256];
        while(fgets(linebuf, sizeof(linebuf), mem_fp) != NULL)
        {
            Map_entry_t * map_entry = parse_map_entry(linebuf);

            if((addr >= map_entry->start_address) && (addr < map_entry->end_address))
            {
//                char * retVal = find_closet_symbol(map_entry, addr);
            }
            free(map_entry);
        }
        fclose(mem_fp);
    }

    return retVal;
}
