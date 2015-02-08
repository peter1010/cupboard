#!/usr/bin/env python3

"""Code for parsing ELF files.

As parts of the elf file are parsed the
data discovered is passed to the data model database using the consumer proxy
"""

import sys
import struct
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

from . import errors
from . import symbol

def dbg_padding(data):
    non_nulls = [b for b in data if b != 0]
    if len(non_nulls) > 0:
        logging.debug("PADDING = %s", str(data))


def _elf_header_fmt(arch_size, endianess):
    if arch_size == 32:
        ptrs = "LLL"
    else:
        ptrs = "QQQ"
    fmt = "{}HHL{}LHHHHHH".format(endianess, ptrs)
    return fmt, struct.calcsize(fmt)


def _prog_header_fmt(arch_size, endianess):
    if arch_size == 32:
        fmt = "{}LLLLLLLL"
    else:
        fmt = "{}LLQQQQQQ"
    fmt = fmt.format(endianess)
    return fmt, struct.calcsize(fmt)


def _section_header_fmt(arch_size, endianess):
    if arch_size == 32:
        fmt = "{}LLLLLLLLLL"
    else:
        fmt = "{}LLQQQQLLQQ"
    fmt = fmt.format(endianess)
    return fmt, struct.calcsize(fmt)


def _symtab_entry_fmt(arch_size, endianess):
    if arch_size == 32:
        fmt = "{}LLLBBH"
    else:
        fmt = "{}LBBHQQ"
    fmt = fmt.format(endianess)
    return fmt, struct.calcsize(fmt)


def _reloc_entry_fmt(arch_size, endianess):
    if arch_size == 32:
        fmt = "{}LL"
    else:
        fmt = "{}QQ"
    fmt = fmt.format(endianess)
    return fmt, struct.calcsize(fmt)


def _read_data(in_fp, foffset, size):
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
    def __init__(self, parent, foffset, num_entries, entry_size):
        self.parent = parent
        self.foffset = foffset
        self.num_entries = num_entries
        self.entry_size = entry_size

    def load_from_fp(self, in_fp):
        num_entries, entry_size = self.num_entries, self.entry_size
        arch_size = self.parent.arch_size
        data = _read_data(in_fp, self.foffset, num_entries * entry_size)
        logger.debug("Number of program header entries is %i", num_entries)
        fmt, min_len = _prog_header_fmt(arch_size,
            self.parent.endianess
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
#define PT_GNU_EH_FRAME 0x6474e550      /* GCC .eh_frame_hdr segment */
#define PT_GNU_STACK    0x6474e551      /* Indicates stack executability */
#define PT_GNU_RELRO    0x6474e552      /* Read-only after relocation */
#define PT_SUNWBSS      0x6ffffffa      /* Sun Specific segment */
#define PT_SUNWSTACK    0x6ffffffb      /* Stack segment */

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
#define PT_SUNWBSS      0x6ffffffa      /* Sun Specific segment */
#define PT_SUNWSTACK    0x6ffffffb      /* Stack segment */
            if p_filesz > 0:
                print(p_type, p_flags, p_offset, p_filesz)
#            print(p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align)


class ElfSection:
    """Base class for all objects that hold info about ELF Sections"""

    def __init__(self, fp, parent, i_name, foffset, size, entry_size, link):
        self.parent = parent
        self.i_name = i_name       # Index into section strtab
        self.foffset = foffset     # File offset
        self.size = size            
        self.entry_size = entry_size
        self.link = link 
        self.in_fp = fp             
        self.data = None           # Initial no data read (only read when required) 
        self.reset()

    def reset(self):
        pass

    @property
    def name(self):
        """Return section name as a string"""
        return self.parent.get_section_strtab().get_string(self.i_name)

    def load_data(self):
        if not self.data:
            self.data = _read_data(self.in_fp, self.foffset, self.size)
        
    def consume_symbols(self):
        pass

    def consume_rels(self):
        pass

    @property
    def consumer(self):
        return self.parent.consumer

    @property
    def arch_size(self):
        return self.parent.arch_size

    @property
    def endianess(self):
        return self.parent.endianess

    def dbg_print(self):
        pass

    def num_of(self):
        return self.size // self.entry_size


class ElfNullSection(ElfSection):
    TYPE_NAME = "SHT_NULL"


class ElfProgSection(ElfSection):
    TYPE_NAME = "SHT_PROGBITS"


class ElfStrtabSection(ElfSection):
    TYPE_NAME = "SHT_STRTAB"
    def get_string(self, offset):
        self.load_data()
        byteStr = self.data[offset:self.data.find(b'\0', offset)]
        return byteStr.decode("ascii")


class ElfNoteSection(ElfSection):
    TYPE_NAME = "SHT_NOTE"


class ElfHashSection(ElfSection):
    TYPE_NAME = "SHT_GNU_HASH"


class ElfVersymSection(ElfSection):
    TYPE_NAME = "SHT_GNU_versym"


class ElfVerneedSection(ElfSection):
    TYPE_NAME = "SHT_GNU_verneed"



class ElfSymtabSection(ElfSection):
    TYPE_NAME = "SHT_SYMTAB"

    def reset(self):
        self.done = set()

    def get_symbol(self, idx):
        strtab = self.parent.get_section(self.link)
        fmt, min_len = _symtab_entry_fmt(self.arch_size, self.endianess)
        pos = idx * self.entry_size
        if self.arch_size == 32:
            (
                st_name, st_value, st_size,
                st_info, st_other, st_shndx
            ) = struct.unpack(fmt, self.data[pos:pos+min_len])
        else:
            (
                st_name,  st_info, st_other,
                st_shndx, st_value, st_size
            ) = struct.unpack(fmt, self.data[pos:pos+min_len])
        dbg_padding(self.data[pos+min_len:pos+self.entry_size])
        name = strtab.get_string(st_name)
        bind = st_info >> 4
        typ = st_info & 0x0f
        self.done.add(idx)
        return symbol.Symbol(name, st_value, st_size, (bind, typ))

    def consume_symbols(self):
        self.load_data()
        consumer = self.consumer
        strtab = self.parent.get_section(self.link)
        fmt, min_len = _symtab_entry_fmt(self.arch_size, self.endianess)
        for idx in range(self.num_of()):
            if idx in self.done:
                continue
            sym = self.get_symbol(idx)
            consumer.add_symbol(sym)


class ElfDynSymtabSection(ElfSymtabSection):
    TYPE_NAME = "SHT_DYNSYM"


class ElfRelSection(ElfSection):
    TYPE_NAME = "SHT_REL"

    def consume_rels(self):
        sym_section = self.parent.get_section(self.link)
        sym_section.load_data()
        self.load_data()
        arch_size = self.arch_size
        fmt, min_len = _reloc_entry_fmt(arch_size, self.endianess)
        consumer = self.consumer
        for idx in range(self.num_of()):
            pos = idx * self.entry_size
            (r_offset, r_info) = struct.unpack(fmt, self.data[pos:pos+min_len])
            if arch_size == 32:
                r_sym = r_info >> 8
                r_typ = r_info & 0xFF
            else:
                r_sym = r_info >> 32
                r_typ = r_info & 0xFFFFFFFF

            sym = sym_section.get_symbol(r_sym)
            sym.offset = r_offset
            sym.rel_typ = r_typ
            consumer.add_symbol(sym)


def sh_type2class(_typ):
    # Elf Section types
    return {
        0: (None, ElfNullSection),
        1: (None, ElfProgSection),
        2: (None, ElfSymtabSection),
        3: (None, ElfStrtabSection),
        4: ('SHT_RELA', ElfSection), 
        5: ('SHT_HASH', ElfSection), 
        6: ('SHT_DYNAMIC', ElfSection),
        7: ('SHT_NOTE', ElfNoteSection),
        8: ('SHT_NOBITS', ElfSection),
        9: (None, ElfRelSection),
        10: ('SHT_SHLIB', ElfSection),
        11: (None, ElfDynSymtabSection),
        14: ('SHT_INIT_ARRAY', ElfSection),
        15: ('SHT_FINI_ARRAY', ElfSection),
        16: ('SHT_PREINIT_ARRAY', ElfSection),
        17: ('SHT_GROUP', ElfSection),
        18: ('SHT_SYMTAB_SHNDX', ElfSection),
        0x6ffffff5: ('SHT_GNU_ATTRIBUTES', ElfSection),
        0x6ffffff6: ('SHT_GNU_HASH', ElfHashSection),
        0x6ffffff7: ('SHT_GNU_LIBLIST', ElfSection),
        0x6ffffff8: ('SHT_CHECKSUM', ElfSection),
        0x6ffffffa: ('SHT_SUNW_move', ElfSection),
        0x6ffffffb: ('SHT_SUNW_COMDAT', ElfSection),
        0x6ffffffc: ('SHT_SUNW_syminfo', ElfSection),
        0x6ffffffd: ('SHT_GNU_verdef', ElfSection),
        0x6ffffffe: (None, ElfVerneedSection),
        0x6fffffff: (None, ElfVersymSection),
    }[_typ]


class ElfSectionHeaderTable:
    def __init__(self, parent, foffset, num_entries, entry_size, section_str_idx):
        self.parent = parent
        self.foffset = foffset
        self.num_entries = num_entries
        self.entry_size = entry_size
        self.section_str_idx = section_str_idx

    @property
    def consumer(self):
        return self.parent.consumer

    @property
    def arch_size(self):
        return self.parent.arch_size

    @property
    def endianess(self):
        return self.parent.endianess

    def get_section_strtab(self):
        return self.sections[self.section_str_idx]
    
    def get_section(self, idx):
        return self.sections[idx]

#    .get_string(sh_name)
    def load_from_fp(self, in_fp):
        num_entries, entry_size = self.num_entries, self.entry_size
        data = _read_data(in_fp, self.foffset, num_entries * entry_size)
        logger.debug("Number of Section header entries is %i", num_entries)
        fmt, min_len = _section_header_fmt(self.arch_size,
            self.endianess
        )
        sections = []
        for i in range(num_entries):
            pos = i * entry_size
            (
                sh_name,   sh_type, sh_flags, sh_addr,
                sh_offset, sh_size, sh_link, sh_info,
                sh_addralign, sh_entsize
            ) = struct.unpack(fmt, data[pos:pos+min_len])
            dbg_padding(data[pos+min_len:pos+entry_size])
            sh_type, _class = sh_type2class(sh_type)
            obj = _class(in_fp, self, sh_name, sh_offset, sh_size, sh_entsize,
                sh_link
            )
            if not hasattr(obj, "TYPE_NAME"):
                print(sh_type)
                obj.TYPE_NAME = sh_type
            sections.append(obj)
        self.sections = sections

        for i, section in enumerate(sections):
            print(i, section.name, section.TYPE_NAME, section.foffset, section.size)
        for i, section in enumerate(sections):
            section.consume_rels()
        for i, section in enumerate(sections):
            section.consume_symbols()


class Elf:
    def __init__(self, arch_size, endianess, consumer):
        self.arch_size = arch_size
        self.endianess = endianess
        self.consumer = consumer
        self.program_header_table = None
        self.section_header_table = None

    def load_from_fp(self, in_fp):
        """First Load the ELF header"""
        fmt, datasize = _elf_header_fmt(self.arch_size, self.endianess)
        data = _read_data(in_fp, 16, datasize)
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
        # Load the Sections (we are interested in the Symbol table)
        obj = ElfSectionHeaderTable(self, e_shoff, e_shnum, e_shentsize,
            e_shstrndx
        )
        obj.load_from_fp(in_fp)
        self.section_header_table = obj
        # Load the Program Header
        obj = ElfProgramHeaderTable(self, e_phoff, e_phnum, e_phentsize)
        obj.load_from_fp(in_fp)
        self.program_header_table = obj


def load_elf(in_fp, consumer):
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
    obj = Elf(arch_size, endianess, consumer)
    obj.load_from_fp(in_fp)


def read_elffile(filename, consumer):
    """Read A elf file, calling methods on the consumer object
    
    The consumer is a proxy object that stores away information
    discovered whilst reading the Elf file"""
    with open(filename, "rb") as in_fp:
        consumer.set_data_source(filename)
        load_elf(in_fp, consumer)


if __name__ == "__main__":
    from . import consumer
    
    logging.basicConfig(level=logging.DEBUG)
    read_elffile(sys.argv[1], consumer.DefaultConsumer)
