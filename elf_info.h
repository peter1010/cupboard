/**
 */

#ifndef _ELF_INFO_H_
#define _ELF_INFO_H_

#include "symbols.h"
#include "mmap_entry.h"

/**
 * Information collected as the Elf file associated with Map_entry is parsed
 */
class Elf_info
{
public:
    virtual void * load_elf_section(int shndx) const = 0;
    virtual unsigned get_symbol_type(const void * symbol) const = 0;
    virtual unsigned get_section_address(int shndx) const = 0;
    virtual unsigned get_symbol_section(const void * symbol) const = 0;
    virtual MemPtr_t get_raw_symbol_value(const void * symbol) const = 0;
    virtual const char * get_symbol_name(const void * symbol, const char * symstr) const = 0;

    virtual unsigned get_section_element_size(int) const = 0;
    virtual unsigned get_section_size(int) const = 0;
    virtual unsigned get_section_offset(int) const = 0;
    virtual char * get_section_name(int) const = 0;
    virtual unsigned get_section_type(int) const = 0;
    virtual unsigned get_section_link(int) const = 0;

    const void * get_shdr(int idx) const
        {return &m_shdr[idx * m_section_entry_size];}

    int get_number_of_symbols(int symtab_idx) const;
    bool load_elf_section_header_table(bool * just_done);
    int get_section_idx(unsigned typ_to_find, bool print_shdr_tab=false) const;
    bool get_symbol_value(const void * symbol, MemPtr_t * pValue) const;

    static Elf_info * create(Map_entry * map);
    void switch_map(Map_entry * map);

    bool same_pathname(const Map_entry * other) const
        {return m_mem_map->same_pathname(other);}

    void debug_print() const
        {return m_mem_map->debug_print();}

    Elf_info();
    virtual ~Elf_info();

protected:
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
