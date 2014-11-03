/**
 */

#ifndef _ELF_INFO_H_
#define _ELF_INFO_H_

#include "symbols.h"

class Map_entry;

/**
 * Information collected as the Elf file associated with Map_entry is parsed
 */
class Elf_info
{
public:
    virtual void * get_elf_section(int shndx) const = 0;
    virtual unsigned get_symbol_type(const void * symbols, int idx) const = 0;
    virtual unsigned get_section_address(int shndx) const = 0;
    virtual int get_number_of_symbols(int symtab_idx) const = 0;
    virtual unsigned get_section_offset(int shndx) const = 0;
    virtual unsigned get_symbol_section(const void * symbols, int idx) const = 0;
    virtual MemPtr_t get_raw_symbol_value(const void * symbols, int idx) const = 0;
    virtual const char * get_symbol_name(const void * symbols, int idx, const char * symstr) const = 0;
    virtual char * get_section_name(int shndx) const = 0;
    virtual unsigned get_section_type(int shndx) const = 0;
    virtual unsigned get_section_link(int shndx) const = 0;

    const void * get_shdr(int shndx) const
        {return &m_shdr[shndx * m_section_entry_size];}

    bool get_elf_section_header_table();
    int get_section_idx(unsigned typ_to_find, bool print_shdr_tab=false) const;

    static Elf_info * create(Map_entry * map);
    void switch_map(Map_entry * map);

    Elf_info();
    virtual ~Elf_info();

    Map_entry * m_mem_map;
    int m_fd;

    unsigned int m_num_of_sections;
    unsigned int m_section_entry_size;
    unsigned int m_e_shoff;
    unsigned int m_e_shstrndx;

    uint8_t * m_shdr;     /* Elf section header table */
    char * m_shstrtab;
};

#endif
