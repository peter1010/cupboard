/**
 */

#ifndef _ELF32_INFO_H_
#define _ELF32_INFO_H_

#include <elf.h>

#include "elf_info.h"

class Elf32_info : public Elf_info
{
public:
    virtual void * get_elf_section(int shndx) const;
    virtual unsigned get_symbol_type(const void * symbols, int idx) const;
    virtual unsigned get_section_address(int shndx) const;
    virtual int get_number_of_symbols(int symtab_idx) const;
    virtual unsigned get_section_offset(int shndx) const;
    virtual unsigned get_symbol_section(const void * symbols, int idx) const;
    virtual MemPtr_t get_raw_symbol_value(const void * symbols, int idx) const;
    virtual const char * get_symbol_name(const void * symbols, int idx, const char * symstr) const;
    virtual char * get_section_name(int shndx) const;
    virtual unsigned get_section_type(int shndx) const;
    virtual unsigned get_section_link(int shndx) const;
    
    Elf32_info(const Elf32_Ehdr * ehdr);
    virtual ~Elf32_info();
};

#endif
