#!/usr/bin/env python3

import sys
import struct
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

from . import errors

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
        fmt = "{}LLLLLLLL"
    else:
        fmt = "{}LLQQQQQQ"
    fmt = fmt.format(endianess)
    return fmt, struct.calcsize(fmt)


def section_header_fmt(arch_size, endianess):
    if arch_size == 32:
        fmt = "{}LLLLLLLLLL"
    else:
        fmt = "{}LLQQQQLLQQ"
    fmt = fmt.format(endianess)
    return fmt, struct.calcsize(fmt)


def symtab_entry_fmt(arch_size, endianess):
    if arch_size == 32:
        fmt = "{}LLLBBW"
    else:
        fmt = "{}LBBWQQ"
    fmt = fmt.format(endianess)
    return fmt, struct.calcsize(fmt)


def read_data(in_fp, foffset, size):
    in_fp.seek(foffset)
    data = in_fp.read(size)
    assert len(data) >= size
    return data


def p_flags2str(flags):
    tokens = []
    if flags & 0x04:
        tokens.append("R")
    if flags & 0x02:
        tokens.append("W")
    if flags & 0x01:
        tokens.append("X")
    return "".join(tokens)


class ElfProgramHeaderTable:
    def __init__(self, elf_container, foffset, num_entries, entry_size):
        self.elf_container = elf_container
        self.foffset = foffset
        self.num_entries = num_entries
        self.entry_size = entry_size

    def load_from_fp(self, in_fp):
        num_entries, entry_size = self.num_entries, self.entry_size
        arch_size = self.elf_container.arch_size
        data = read_data(in_fp, self.foffset, num_entries * entry_size)
        logger.debug("Number of program header entries is %i", num_entries)
        fmt, min_len = prog_header_fmt(arch_size,
            self.elf_container.endianess
        )
        for i in range(num_entries):
            pos = i * entry_size
            buf = data[pos:pos+min_len]
            if arch_size == 32:
                (
                    p_type,   p_offset, p_vaddr, p_paddr,
                    p_filesz, p_memsz,  p_flags, p_align
                ) = struct.unpack(fmt, buf)
            else:
                (
                    p_type,  p_flags,  p_offset, p_vaddr,
                    p_paddr, p_filesz, p_memsz, p_align
                ) = struct.unpack(fmt, buf)
            dbg_padding(data[pos+min_len:pos+entry_size])
            p_flags = p_flags2str(p_flags)
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
            if p_filesz > 0:
                print(p_type, p_flags, p_offset, p_filesz)
#            print(p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align)


class ElfSection:
    def __init__(self, hdr_table, foffset, size):
        self.hdr_table = hdr_table
        self.foffset = foffset
        self.size = size

    def load_from_fp(self, in_fp):
        self.data = read_data(in_fp, self.foffset, self.size)

    @property
    def arch_size(self):
        return self.hdr_table.arch_size

    @property
    def endianess(self):
        return self.hdr_table.endianess

    def dbg_print(self):
        pass


class ElfStrtabSection(ElfSection):
    def get_string(self, offset):
        return self.data[offset:self.data.find(b'\0', offset)]


class Symbol:
    def __init__(self, parent, name, value, size, section):
        self.name = name
        self.value = value
        self.size = size
        self.section = section

    def __str__(self):
        return "{}:{}".format(self.name, self.value)

    @staticmethod
    def parse_elf_symbol(self, container, data):
        arch_size, endianess = container.arch_size, container.endianess
        fmt, min_len = symtab_entry_fmt(arch_size, endianess)
        if archsize == 32:
            (
                st_name, st_value, st_size,
                st_info, st_other, st_shndx
            ) = struct.unpack(fmt, data)
        else:
            (
                st_name,  st_info, st_other,
                st_shndx, st_value, st_size
            ) = struct.unpack(fmt, data)
        dbg_padding(data[min_len:])
        name = self.parent.link.get_string(st_name)
        return Symbol(parent)



class ElfSymtabSection(ElfSection):
    def __init__(self, hdr_table, foffset, size, entry_size, link):
        super(ElfSymtabSection, self).__init__(hdr_table, foffset, size)
        self.entry_size = entry_size
        self.link = link

    def num_of(self):
        return self.size // self.entry_size

    def get_symbol(self, i):
        pos = i * self.entry_size
        fmt, min_len = section_header_fmt(self.arch_size, self.endianess)
        if archsize == 32:
            (
                st_name, st_value, st_size,
                st_info, st_other, st_shndx
            ) = struct.unpack(fmt, data[pos:pos+min_len])
        else:
            (
                st_name,  st_info, st_other,
                st_shndx, st_value, st_size
            ) = struct.unpack(fmt, data[pos:pos+min_len])
        dbg_padding(data[pos+min_len:pos+entry_size])
        st_name = self.link.get_string(st_name)
        return Symbol(st_name, st_value)


def sh_type2class(_typ):
    # Elf Section types
    return {
        0: ('SHT_NULL', ElfSection),
        1: ('SHT_PROGBITS', ElfSection),
        2: ('SHT_SYMTAB', ElfSymtabSection),
        3: ('SHT_STRTAB', ElfStrtabSection),
        4: ('SHT_RELA', ElfSection), 
        5: ('SHT_HASH', ElfSection), 
        6: ('SHT_DYNAMIC', ElfSection),
        7: ('SHT_NOTE', ElfSection),
        8: ('SHT_NOBITS', ElfSection),
        9: ('SHT_REL', ElfSection),
        10: ('SHT_SHLIB', ElfSection),
        11: ('SHT_DYNSYM', ElfSection),
        14: ('SHT_INIT_ARRAY', ElfSection),
        15: ('SHT_FINI_ARRAY', ElfSection),
        16: ('SHT_PREINIT_ARRAY', ElfSection),
        17: ('SHT_GROUP', ElfSection),
        18: ('SHT_SYMTAB_SHNDX', ElfSection),
        0x6ffffff5: ('SHT_GNU_ATTRIBUTES', ElfSection),
        0x6ffffff6: ('SHT_GNU_HASH', ElfSection),
        0x6ffffff7: ('SHT_GNU_LIBLIST', ElfSection),
        0x6ffffff8: ('SHT_CHECKSUM', ElfSection),
        0x6ffffffa: ('SHT_SUNW_move', ElfSection),
        0x6ffffffb: ('SHT_SUNW_COMDAT', ElfSection),
        0x6ffffffc: ('SHT_SUNW_syminfo', ElfSection),
        0x6ffffffd: ('SHT_GNU_verdef', ElfSection),
        0x6ffffffe: ('SHT_GNU_verneed', ElfSection),
        0x6fffffff: ('SHT_GNU_versym', ElfSection),
    }[_typ]


class ElfSectionHeaderTable:
    def __init__(self, elf_container, foffset, num_entries, entry_size, section_str_idx):
        self.elf_container = elf_container
        self.foffset = foffset
        self.num_entries = num_entries
        self.entry_size = entry_size
        self.section_str_idx = section_str_idx

    @property
    def arch_size(self):
        return self.elf_container.arch_size

    @property
    def endianess(self):
        return self.elf_container.endianess

    def load_from_fp(self, in_fp):
        num_entries, entry_size = self.num_entries, self.entry_size
        data = read_data(in_fp, self.foffset, num_entries * entry_size)
        logger.debug("Number of Section header entries is %i", num_entries)
        fmt, min_len = section_header_fmt(self.arch_size,
            self.endianess
        )
        idx = self.section_str_idx
        entries = [idx] + list(range(idx)) + list(range(idx+1, num_entries))
        section_strtab = None
        sections = []
        for i in entries:
            pos = i * entry_size
            (
                sh_name,   sh_type, sh_flags, sh_addr,
                sh_offset, sh_size, sh_link, sh_info,
                sh_addralign, sh_entsize
            ) = struct.unpack(fmt, data[pos:pos+min_len])
            dbg_padding(data[pos+min_len:pos+entry_size])
            sh_type, _class = sh_type2class(sh_type)
            obj = _class(self, sh_offset, sh_size)
            obj.load_from_fp(in_fp)
            if i == self.section_str_idx:
                section_strtab = obj
            sh_name = section_strtab.get_string(sh_name)
            obj.name = sh_name
            print(i, sh_name, sh_type, sh_offset, sh_size)
            sections.append(obj)
        sections = sections[1:idx] + sections[idx:idx+1] + sections[idx+1:]
        for section in sections:
            if hasattr(section, "link"):
                section.link = sections[section.link]
            section.dbg_print()


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
        logger.debug("e_type=%i e_machine=%i e_flags=0x%X",
            e_type, e_machine, e_flags
        )
        if e_version != 1:
            logger.error("Not an valid ELF Header version %i", e_version)
            raise errors.NotElfFileError()
        # TODO, e_entry
        logger.debug("e_entry=0x%X", e_entry)
        if e_ehsize < len(data):
            logger.error("Invalid header length %i !< %i",
                e_ehsize, len(data)
            )
            raise errors.NotElfFileError()
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
        raise errors.NotElfFileError()
    _class = e_ident[4]
    if _class == 1:
        arch_size = 32
    elif _class == 2:
        arch_size = 64
    else:
        logger.error("Invalid ELF class %i", _class)
        raise errors.NotElfFileError()
    endianess = e_ident[5]
    if endianess == 1:
        endianess = '<'     # little-endian
    elif endianessendianess == 2:
        endianess = '>'     # Big-endian
    else:
        logger.error("Invalid ELF Endianess %i", endianess)
        raise errors.NotElfFileError()
    version = e_ident[6]
    if version != 1:
        logger.error("Not an valid ELF version %i", version)
        raise errors.NotElfFileError()
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
