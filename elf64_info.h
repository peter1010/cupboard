/**
 */

#ifndef _ELF64_INFO_H_
#define _ELF64_INFO_H_

#include <elf.h>

#include "elf_info.h"

class Elf64_info : public Elf_info
{
public:
    virtual void * load_elf_section(int shndx) const;
    virtual unsigned get_symbol_type(const void * symbol) const;
    virtual unsigned get_section_address(int shndx) const;
    virtual unsigned get_symbol_section(const void * symbol) const;
    virtual MemPtr_t get_raw_symbol_value(const void * symbol) const;
    virtual const char * get_symbol_name(const void * symbol, const char * symstr) const;

    virtual unsigned get_section_element_size(int) const;
    virtual unsigned get_section_size(int) const;
    virtual unsigned get_section_offset(int) const;
    virtual char * get_section_name(int) const;
    virtual unsigned get_section_type(int) const;
    virtual unsigned get_section_link(int) const;

    Elf64_info(const Elf64_Ehdr * ehdr);
    virtual ~Elf64_info();
};

#endif
