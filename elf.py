#!/usr/bin/env python3

import sys
import struct
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def dbg_padding(data):
    non_nulls = [b for b in data if b != 0]
    if len(non_nulls) > 0:
        logging.debug("PADDING = %s", str(data))


def elf_header_fmt(arch_size, endianess):
    if arch_size == 32:
        ptrs = "LLL"
    else:
        ptrs = "QQQ"
    fmt = "{}HHL{}LHHHHHH".format(endianess, ptrs)
    return fmt, struct.calcsize(fmt)


def prog_header_fmt(arch_size, endianess):
    if arch_size == 32:
        fmt = "{}LLLLLLLL".format(endianess)
    else:
        fmt = "{}LLQQQQQQ".format(endianess)
    return fmt, struct.calcsize(fmt)

def read_data(in_fp, foffset, size):
    in_fp.seek(foffset)
    data = in_fp.read(size)
    assert len(data) >= size
    return data
 

class ElfProgramHeaderTable:
    def __init__(self, elf_container, foffset, num_entries, entry_size):
        self.elf_container = elf_container
        self.foffset = foffset
        self.num_entries = num_entries
        self.entry_size = entry_size

    def load_from_fp(self, in_fp):
        data = read_data(in_fp, self.foffset, self.num_entries * self.entry_size)
        logger.debug("Number of program header entries is %i %i", self.num_entries, self.entry_size)
        fmt, min_len = prog_header_fmt(self.elf_container.arch_size, self.elf_container.endianess)
        for i in range(self.num_entries):
            pos = i * self.entry_size
            if self.elf_container.arch_size == 32:
                (
                    p_type,   p_offset, p_vaddr, p_paddr,
                    p_filesz, p_memsz,  p_flags, p_align
                ) = struct.unpack(fmt, data[pos:pos+min_len])
            else:
                (
                    p_type,  p_flags,  p_offset, p_vaddr,
                    p_paddr, p_filesz, p_memsz, p_align
                ) = struct.unpack(fmt, data[pos:pos+min_len])
            flags = ""
            if p_flags & 0x01:
                flags += "X"
            elif p_flags & 0x02:
                flags += "W"
            elif p_flags & 0x04:
                flags += "R"
            p_flags = flags
#define PT_NULL         0               /* Program header table entry unused */
#define PT_LOAD         1               /* Loadable program segment */
#define PT_DYNAMIC      2               /* Dynamic linking information */
#define PT_INTERP       3               /* Program interpreter */
#define PT_NOTE         4               /* Auxiliary information */
#define PT_SHLIB        5               /* Reserved */
#define PT_PHDR         6               /* Entry for header table itself */
#define PT_TLS          7               /* Thread-local storage segment */
#define PT_NUM          8               /* Number of defined types */
#define PT_LOOS         0x60000000      /* Start of OS-specific */
#define PT_GNU_EH_FRAME 0x6474e550      /* GCC .eh_frame_hdr segment */
#define PT_GNU_STACK    0x6474e551      /* Indicates stack executability */
#define PT_GNU_RELRO    0x6474e552      /* Read-only after relocation */
#define PT_LOSUNW       0x6ffffffa
#define PT_SUNWBSS      0x6ffffffa      /* Sun Specific segment */
#define PT_SUNWSTACK    0x6ffffffb      /* Stack segment */
#define PT_HISUNW       0x6fffffff
                                                                                                                   
            if p_type == 0: # Null entry
                continue
            if p_type == 1: # PT_LOAD
                p_type = "PT_LOAD"
            elif p_type == 2: #
                p_type = "PT_DYNAMIC"
            elif p_type == 3:
                p_type = "PT_INTERP"
            elif p_type == 4:
                p_type = "PT_NOTE"
            elif p_type == 5:
                p_type = "PT_SHLIB"
            elif p_type == 6:
                p_type = "PT_PHDR"
            elif p_type == 7:
                p_type = "PT_TLS"
            elif p_type == 0x6474e550:
                p_type = "PT_GNU_EH_FRAME"
            elif p_type == 0x6474e551:
                p_type = "PT_GNU_STACK"
            elif p_type == 0x6474e552:
                p_type = "PT_GNU_RELRO"
#define PT_LOSUNW       0x6ffffffa
#define PT_SUNWBSS      0x6ffffffa      /* Sun Specific segment */
#define PT_SUNWSTACK    0x6ffffffb      /* Stack segment */
#define PT_HISUNW       0x6fffffff
            print(p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align)

class ElfSectionHeaderTable:
    def __init__(self, elf_container, foffset, num_entries, entry_size, section_str_idx):
        self.elf_container = elf_container
        self.foffset = foffset
        self.num_entries = num_entries
        self.entry_size = entry_size
        self.section_str_idx = section_str_idx

    def load_from_fp(self, in_fp):
        data = read_data(in_fp, self.foffset, self.num_entries * self.entry_size)
        logger.debug("Number of Section header entries is %i %i", self.num_entries, self.entry_size)
        pass
 

class Elf:
    def __init__(self, arch_size, endianess):
        self.arch_size = arch_size
        self.endianess = endianess
        self.program_header_table = None
        self.section_header_table = None

    def load_from_fp(self, in_fp):
        """First Load the ELF header"""
        fmt, datasize = elf_header_fmt(self.arch_size, self.endianess)
        data = read_data(in_fp, 16, datasize)
        (
            e_type,      e_machine, e_version,   e_entry,
            e_phoff,     e_shoff,   e_flags,     e_ehsize,
            e_phentsize, e_phnum,   e_shentsize, e_shnum,
            e_shstrndx) = struct.unpack(fmt, data)
        # TODO, type, machine, flags
        logger.debug("e_type=%i e_machine=%i e_flags=0x%X", e_type, e_machine,
            e_flags
        )
        if e_version != 1:
            logger.error("Not an valid ELF Header version %i", e_version)
            return None
        # TODO, e_entry
        logger.debug("e_entry=0x%X", e_entry)
        if e_ehsize < len(data):
            logger.error("Invalid header length %i !< %i", e_ehsize, len(data))
            return None
        dbg_padding(in_fp.read(e_ehsize-len(data)))
        obj = ElfProgramHeaderTable(self, e_phoff, e_phnum, e_phentsize)
        obj.load_from_fp(in_fp)
        self.program_header_table = obj
        print(e_shentsize, e_shnum, e_shstrndx)
        obj = ElfSectionHeaderTable(self, e_shoff, e_shnum, e_shentsize,
            e_shstrndx
        )
        obj.load_from_fp(in_fp)
        self.section_header_table = obj


def load_elf(in_fp):
    """Start by reading the ELD header

    See /us/include/elf.h for meaning of fields"""
    e_ident = in_fp.read(16)
    magic = e_ident[:4]
    if magic != b'\x7fELF':
        logger.error("Not an ELF file")
        return None
    _class = e_ident[4]
    if _class == 1:
        arch_size = 32
    elif _class == 2:
        arch_size = 64
    else:
        logger.error("Invalid ELF class %i", _class)
        return None
    endianess = e_ident[5]
    if endianess == 1:
        endianess = '<'     # little-endian
    elif endianessendianess == 2:
        endianess = '>'     # Big-endian
    else:
        logger.error("Invalid ELF Endianess %i", endianess)
        return None
    version = e_ident[6]
    if version != 1:
        logger.error("Not an valid ELF version %i", version)
        return None
    logger.info("ELF Class is %i, %s", arch_size, endianess)
    logger.debug("EI_OSABI=%i, EI_ABIVERSION=%i", e_ident[7], e_ident[8])
    dbg_padding(e_ident[9:])
    obj = Elf(arch_size, endianess)
    obj.load_from_fp(in_fp)


def read_elffile(filename):
    with open(filename, "rb") as in_fp:
        load_elf(in_fp)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    read_elffile(sys.argv[1])
