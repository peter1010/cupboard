/**
 */

#include <unistd.h>
#include <assert.h>

#include "logging.h"
#include "elf64_info.h"

Elf64_info::Elf64_info(const Elf64_Ehdr * ehdr)
{
    m_num_of_sections = ehdr->e_shnum;
    m_section_entry_size = ehdr->e_shentsize;
    m_e_shoff = ehdr->e_shoff;
    m_e_shstrndx = ehdr->e_shstrndx;
}

Elf64_info::~Elf64_info()
{
}

/**
 * Get contents of elf section
 *
 * @param[in] shndx The index in section header of the section to get
 *
 * @return Section contents in a malloced memory block
 */
void * Elf64_info::load_elf_section(int shndx) const
{
    const Elf64_Shdr * shdr = reinterpret_cast<const Elf64_Shdr *>(get_shdr(shndx));
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
 * @param[in] symbol Pointer to symbol element
 *
 * @return the type
 */
unsigned Elf64_info::get_symbol_type(const void * symbol) const
{
    const Elf64_Sym * pSym = ((const Elf64_Sym *)symbol);
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
unsigned Elf64_info::get_section_address(int shndx) const
{
    const Elf64_Shdr * shdr = reinterpret_cast<const Elf64_Shdr *>(get_shdr(shndx));
    return shdr->sh_addr;
}

/**
 * Get the symbol section value for the symbol specified by the
 * index
 *
 * @param[in] symbol Pointer symbol element
 *
 * @return the section index
 */
unsigned Elf64_info::get_symbol_section(const void * symbol) const
{
    const Elf64_Sym * pSym = ((const Elf64_Sym *)symbol);
    return pSym->st_shndx;
}

/**
 * Get the symbol value for the symbol specified by the
 * index
 *
 * @param[in] symbol Pointer to symbol element
 *
 * @return the section index
 */
MemPtr_t Elf64_info::get_raw_symbol_value(const void * symbol) const
{
    const Elf64_Sym * pSym = ((const Elf64_Sym *)symbol);
    return (MemPtr_t) (pSym->st_value);
}

/**
 * Get the name of the symbol
 *
 * @param[in] symbol Pointer to symbol element
 * @param[in] symstr The string table
 *
 * @return The symbol name
 */
const char * Elf64_info::get_symbol_name(const void * symbol, const char * symstr) const
{
    const Elf64_Sym * pSym = ((const Elf64_Sym *)symbol);
    const int name_idx = pSym->st_name;
    const char * symbol_name = &symstr[name_idx];
    LOG_DEBUG("%08lx => %s (%llu) {%i}", (unsigned long) pSym->st_value, symbol_name, pSym->st_size, pSym->st_shndx);
    return symbol_name;
}

unsigned Elf64_info::get_section_element_size(int idx) const
{
    const Elf64_Shdr * shdr = reinterpret_cast<const Elf64_Shdr *>(get_shdr(idx));
    return shdr->sh_entsize;
}

unsigned Elf64_info::get_section_size(int idx) const
{
    const Elf64_Shdr * shdr = reinterpret_cast<const Elf64_Shdr *>(get_shdr(idx));
    return shdr->sh_size;
}

/**
 * Get the section offset value for the section sprcified by the
 * index
 *
 * @param[in] shndx The index in section header of the section to get
 *
 * @return the offset
 */
unsigned Elf64_info::get_section_offset(int idx) const
{
    const Elf64_Shdr * shdr = reinterpret_cast<const Elf64_Shdr *>(get_shdr(idx));
    return shdr->sh_offset;
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
    const Elf64_Shdr * shdr = reinterpret_cast<const Elf64_Shdr *>(get_shdr(shndx));
    const int name_idx = shdr->sh_name;
    return &m_shstrtab[name_idx];
}

/**
 * Get the section type value for the section specified by the
 * index
 *
 * @param[in] shndx The index in section header of the section to get
 *
 * @return the section type
 */
unsigned Elf64_info::get_section_type(int idx) const
{
    const Elf64_Shdr * shdr = reinterpret_cast<const Elf64_Shdr *>(get_shdr(idx));
    return shdr->sh_type;
}

/**
 * Get the section link value for the section specified by the
 * index
 *
 * @param[in] idx The index in section header of the section to get
 *
 * @return the value of section link field
 */
unsigned Elf64_info::get_section_link(int idx) const
{
    const Elf64_Shdr * shdr = reinterpret_cast<const Elf64_Shdr *>(get_shdr(idx));
    return shdr->sh_link;
}

