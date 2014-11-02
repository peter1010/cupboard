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
#include "elf_info.h"

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
}

/**
 * Parse the Elf header
 *
 * @param[in] fd The open file descriptor for the ELF file
 * @param[in] pathname The name of the Elf file
 *
 * @return True if this indeed is an Elf file
 */
static Elf_info * parse_elf_header(int fd)
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
        LOG_ERROR("No ELF Magic seen for '%s'", elf_info->m_mem_map->pathname());
        return retVal;
    }
    switch(buf[EI_CLASS])
    {
        case ELFCLASS32:
            {
                const Elf32_Ehdr * ehdr = (const Elf32_Ehdr *)buf;

                if((sizeof(Elf32_Ehdr) <= ehdr->e_ehsize) && (sizeof(Elf32_Ehdr) <= num))
                {
                    retVal = new Elf32_info;
                    retVal->m_num_of_sections = ehdr->e_shnum;
                    retVal->m_section_entry_size = ehdr->e_shentsize;
                    retVal->m_e_shoff = ehdr->e_shoff;
                    retVal->m_e_shstrndx = ehdr->e_shstrndx;
                }
            }
            break;
        case ELFCLASS64:
            {
                const Elf64_Ehdr * ehdr = (const Elf64_Ehdr *)buf;

                if((sizeof(Elf64_Ehdr) <= ehdr->e_ehsize) && (sizeof(Elf64_Ehdr) <= num))
                {
                    retVal = new Elf64_info:
                    retVal->m_num_of_sections = ehdr->e_shnum;
                    retVal->m_section_entry_size = ehdr->e_shentsize;
                    retVal->m_e_shoff = ehdr->e_shoff;
                    retVal->m_e_shstrndx = ehdr->e_shstrndx;
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
        elf_info = parse_elf_header(fd);
        if(elf_info)
        {
            elf_info->m_fd = fd;
            if(!get_elf_section_header_table(elf_info))
            {
                delete elf_info;
                elf_info = NULL;
            }
        }
    }
    return elf_info;
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
 * Get contents of elf section
 *
 * @param[in] shndx The index in section header of the section to get
 *
 * @return Section contents in a malloced memory block
 */
void * Elf32_info::get_elf_section(int shndx) const
{
    uint8_t * p = &m_shdr[shndx * m_section_entry_size];
    const Elf32_Shdr * shdr = reinterpret_cast<const Elf32_Shdr *>(p);
    const size_t size = shdr->sh_size;
    const unsigned long offset = shdr->sh_offset;

    uint8_t * section = new uint8_t[size];
    if( pread(m_fd, section, size, offset) != (int) size)
    {
        LOG_ERROR("Failed to read section table");
        delete [] section;
        exit(0);
    }
    return section;
}

/**
 * Get contents of elf section
 *
 * @param[in] shndx The index in section header of the section to get
 *
 * @return Section contents in a malloced memory block
 */
void * Elf64_info::get_elf_section(int shndx) const
{
    uint8_t * p = &m_shdr[shndx * m_section_entry_size];
    const Elf64_Shdr * shdr = reinterpret_cast<const Elf64_Shdr *>(p);
    const size_t size = shdr->sh_size;
    const unsigned long offset = shdr->sh_offset;

    uint8_t * section = new uint8_t[size];
    if( pread(m_fd, section, size, offset) != (int) size)
    {
        LOG_ERROR("Failed to read section table");
        delete [] section;
        exit(0);
    }
    return section;
}

/**
 * Get the symbol type value for the symbol specified by the
 * index
 *
 * @param[in] symbols Pointer to section containing the symbols
 * @param[in] idx The index in section header of the section to get
 *
 * @return the type
 */
unsigned Elf32_info::get_symbol_type(const void * symbols, int idx) const
{
    const Elf32_Sym * pSym = &((const Elf32_Sym *)symbols)[idx];
    return ELF32_ST_TYPE(pSym->st_info);
}

/**
 * Get the symbol type value for the symbol specified by the
 * index
 *
 * @param[in] symbols Pointer to section containing the symbols
 * @param[in] idx The index in section header of the section to get
 *
 * @return the type
 */
unsigned Elf64_info::get_symbol_type(const void * symbols, int idx) const
{
    const Elf64_Sym * pSym = &((const Elf64_Sym *)symbols)[idx];
    return ELF64_ST_TYPE(pSym->st_info);
}

/**
 * Get the section address value for the section sprcified by the
 * index
 *
 * @param[in] shndx The index in section header of the section to get
 *
 * @return the address
 */
unsigned Elf32_info::get_section_address(int shndx) const
{
    uint8_t * p = &m_shdr[shndx * m_section_entry_size];
    const Elf32_Shdr * shdr = (const Elf32_Shdr *)p;
    return shdr->sh_addr;
}

/**
 * Get the section address value for the section sprcified by the
 * index
 *
 * @param[in] shndx The index in section header of the section to get
 *
 * @return the address
 */
unsigned Elf64_info::get_section_address(int shndx) const
{
    uint8_t * p = &m_shdr[shndx * m_section_entry_size];
    const Elf64_Shdr * shdr = reinterpret_cast<const Elf64_Shdr *>(p);
    return shdr->sh_addr;
}

/**
 * Get the number of symbols in symbol table
 *
 * @param[in] symtab_idx The index in the Section header table of symbol table in question
 *
 * @return The number of symbols
 */
int Elf32_info::get_number_of_symbols(int symtab_idx) const
{
    uint8_t * p = &m_shdr[symtab_idx * m_section_entry_size];
    const Elf32_Shdr * symtab = reinterpret_cast<const Elf32_Shdr *>(p);
    const unsigned size = symtab->sh_size;
    const unsigned ele_size = symtab->sh_entsize;
    assert(sizeof(Elf32_Sym) <= ele_size);
    const int num_of_symbols = size / ele_size;
    LOG_DEBUG("Number of symbols is %i", num_of_symbols);
    return num_of_symbols;
}

/**
 * Get the number of symbols in symbol table
 *
 * @param[in] symtab_idx The index in the Section header table of symbol table in question
 *
 * @return The number of symbols
 */
int Elf64_info::get_number_of_symbols(int symtab_idx) const
{
    uint8_t * p = &m_shdr[symtab_idx * m_section_entry_size];
    const Elf64_Shdr * symtab = reinterpret_cast<const Elf64_Shdr *>(p);
    const unsigned size = symtab->sh_size;
    const unsigned ele_size = symtab->sh_entsize;
    assert(sizeof(Elf64_Sym) <= ele_size);
    const int num_of_symbols = size / ele_size;
    LOG_DEBUG("Number of symbols is %i", num_of_symbols);
    return num_of_symbols;
}

/**
 * Get the section offset value for the section sprcified by the
 * index
 *
 * @param[in] shndx The index in section header of the section to get
 *
 * @return the offset
 */
unsigned Elf32_info::get_section_offset(int shndx) const
{
    uint8_t * p = &m_shdr[shndx * m_section_entry_size];
    const Elf32_Shdr * shdr = reinterpret_cast<const Elf32_Shdr *>(p);
    return shdr->sh_offset;
}

/**
 * Get the section offset value for the section sprcified by the
 * index
 *
 * @param[in] shndx The index in section header of the section to get
 *
 * @return the offset
 */
unsigned Elf64_info::get_section_offset(int shndx) const
{
    uint8_t * p = &m_shdr[shndx * m_section_entry_size];
    const Elf64_Shdr * shdr = reinterpret_cast<const Elf64_Shdr *>(p);
    return shdr->sh_offset;
}

/**
 * Get the symbol section value for the symbol specified by the
 * index
 *
 * @param[in] symbols Pointer to section containing the symbols
 * @param[in] idx The index in section header of the section to get
 *
 * @return the section index
 */
unsigned Elf32_info::get_symbol_section(const void * symbols, int idx) const
{
    const Elf32_Sym * pSym = &((const Elf32_Sym *)symbols)[idx];
    return pSym->st_shndx;
}

/**
 * Get the symbol section value for the symbol specified by the
 * index
 *
 * @param[in] symbols Pointer to section containing the symbols
 * @param[in] idx The index in section header of the section to get
 *
 * @return the section index
 */
unsigned Elf64_info::get_symbol_section(const void * symbols, int idx) const
{
    const Elf64_Sym * pSym = &((const Elf64_Sym *)symbols)[idx];
    return pSym->st_shndx;
}

/**
 * Get the symbol value for the symbol specified by the
 * index
 *
 * @param[in] symbols Pointer to section containing the symbols
 * @param[in] idx The index in section header of the section to get
 *
 * @return the section index
 */
MemPtr_t Elf32_info::get_raw_symbol_value(const void * symbols, int idx) const
{
    const Elf32_Sym * pSym = &((const Elf32_Sym *)symbols)[idx];
    return (MemPtr_t) (pSym->st_value);
}

/**
 * Get the symbol value for the symbol specified by the
 * index
 *
 * @param[in] symbols Pointer to section containing the symbols
 * @param[in] idx The index in section header of the section to get
 *
 * @return the section index
 */
MemPtr_t Elf64_info::get_raw_symbol_value(const void * symbols, int idx) const
{
    const Elf64_Sym * pSym = &((const Elf64_Sym *)symbols)[idx];
    return (MemPtr_t) (pSym->st_value);
}

/**
 * Get the name of the symbol
 *
 * @param[in] symbols Pointer to section containing the symbols
 * @param[in] idx The index in section header of the section to get
 * @param[in] symstr The string table
 *
 * @return The symbol name
 */
const char * Elf32_info::get_symbol_name(const void * symbols, int idx, const char * symstr) const
{
    const Elf32_Sym * pSym = &((const Elf32_Sym *)symbols)[idx];
    const int name_idx = pSym->st_name;
    return &(symstr[name_idx]);
}

/**
 * Get the name of the symbol
 *
 * @param[in] symbols Pointer to section containing the symbols
 * @param[in] idx The index in section header of the section to get
 * @param[in] symstr The string table
 *
 * @return The symbol name
 */
const char * Elf64_info::get_symbol_name(const void * symbols, int idx, const char * symstr) const
{
    const Elf64_Sym * pSym = &((const Elf64_Sym *)symbols)[idx];
    const int name_idx = pSym->st_name;
    return &(symstr[name_idx]);
}

/**
 * Get the section name value for the section specified by the
 * index
 *
 * @param[in] shndx The index in section header of the section to get
 *
 * @return the section name
 */
char * Elf32_info::get_section_name(int shndx) const
{
    const Elf32_Shdr * shdr = &(reinterpret_cast<const Elf32_Shdr *>(m_shdr))[shndx];
    const int name_idx = shdr->sh_name;
    return &m_shstrtab[name_idx];
}

/**
 * Get the section name value for the section specified by the
 * index
 *
 * @param[in] shndx The index in section header of the section to get
 *
 * @return the section name
 */
char * Elf64_info::get_section_name(int shndx) const
{
    const Elf64_Shdr * shdr = &(reinterpret_cast<const Elf64_Shdr *>(m_shdr))[shndx];
    const int name_idx = shdr->sh_name;
    return &m_shstrtab[name_idx];
}

/**
 * Get the section type value for the section specified by the
 * index
 *
 * @param[in] shndx The index in section header of the section to get
 *
 * @return the section name
 */
unsigned Elf32_info::get_section_type(int shndx) const
{
    const Elf32_Shdr * shdr = &(reinterpret_cast<const Elf32_Shdr *>(m_shdr))[shndx];
    return shdr->sh_type;
}

/**
 * Get the section type value for the section specified by the
 * index
 *
 * @param[in] shndx The index in section header of the section to get
 *
 * @return the section name
 */
unsigned Elf64_info::get_section_type(int shndx) const
{
    const Elf64_Shdr * shdr = &(reinterpret_cast<const Elf64_Shdr *>(m_shdr))[shndx];
    return shdr->sh_type;
}


