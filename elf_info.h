/**
 */

#ifndef _ELF_INFO_H_
#define _ELF_INFO_H_

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

class Map_entry;

/**
 * Information collected as the Elf file associated with Map_entry is parsed
 */
class Elf_info
{
public:
    virtual bool is_elf_32bit() const = 0;
    virtual bool is_elf_64bit() const = 0;

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

class Elf32_info : Elf_info
{
public:
    virtual bool is_elf_32bit() const {return true;};
    virtual bool is_elf_64bit() const {return false;};
};

class Elf64_info : Elf_info
{
public:
    virtual bool is_elf_32bit() const {return true;};
    virtual bool is_elf_64bit() const {return false;};
};

#endif
