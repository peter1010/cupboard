import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

ES_OVERRIDE=1
CS_OVERRIDE=2
SS_OVERRIDE=3
DS_OVERRIDE=4
FS_OVERRIDE=5
GS_OVERRIDE=6


REGS_8BIT = (
    "%al",  # Lower 8 bits of A(r0)
    "%cl",  # Lower 8 bits of C(r2)
    "%dl",  # Lower 8 bits of D(r3)
    "%bl",  # Lower 8 bits of B(r1)
    "%ah",  # Second 8 bits of A(r0)
    "%ch",  # Second 8 bits of C(r2)
    "%dh",  # Second 8 bits of D(r3)
    "%bh"   # Second 8 bits of B(r1)
)

REGS_16BIT = (
    "%ax",  # Lower 16 bits of A
    "%cx",  # Lower 16 bits of C
    "%dx",  # Lower 16 bite of D
    "%bx",  # Lower 16 bits of B
    "%sp",  # Stack pointer (16 bits)
    "%bp",  # Base Pointer (16 bits)
    "%si",  # Address reg (16 bits)
    "%di"   # Address reg (16 bits)
)

REGS_32BIT = (
    "%eax", # Lower 32 bits of A
    "%ecx", # Lower 32 bits of C
    "%edx", # Lower 32 bits of D
    "%ebx",
    "%esp",
    "%ebp",
    "%esi",
    "%edi"
)


def to_r8_reg(val):
    return REGS_8BIT[val]

INDIRECT_16BIT = (
    "(%bx,%si)",
    "(%bx,%di)",
    "(%bp,%si)",
    "(%bp,%di)",
    "(%si)",
    "(%di)",
    "(%bp)",
    "(%bx)"
)

INDIRECT_32BIT = (
    "(%eax)",
    "(%ecx)",
    "(%edx)",
    "(%ebx)",
    None, # SIB
    "(%ebp)",
    "(%esi)",
    "(%edi)"
)

INDIRECT_64BIT = (
    "(%rax)",
    "(%rcx)",
    "(%rdx)",
    "(%rbx)",
    None, # SIB
    "(%rip) (%rbp)",    # Depends on MOD bits :)
    "(%rsi)",
    "(%rdi)"
)

REX_INDIRECT_64BIT = (
    "(%r8)",
    "(%r9)",
    "(%r10)",
    "(%r11)",
    None, # SIB
    "(%rip) (%r13",     # Depends on MOD bits :)
    "(%r14)",
    "(%r15)"
)


def to_indirect(instr, val, disp):
    if instr.addr_mode == 16:
        regs = INDIRECT_16BIT[val]
    elif instr.addr_mode == 32:
        regs = INDIRECT_32BIT[val]
    else:
        regs = INDIRECT_64BIT[val]
    if disp:
        return "{}{}".format(disp, regs)
    else:
        return regs
    
SIB_BASE_REG = (
    "%eax",
    "%ecx",
    "%edx",
    "%ebx",
    "%esp",
    None,
    "%es1",
    "%edi"
)

_SIZE_OVERRIDE = {
   16: 32,
   32: 16,
   64: 32
}

class Instruction:

    def __init__(self, arch):
        self.mode = arch.mode
        self.addr_mode = arch.mode
        self.data_mode = arch.mode
        self.lock = ""

    def set_addr_override(self):
        self.addr_mode = _SIZE_OVERRIDE[self.mode]

    def set_data_override(self):
        self.data_mode = _SIZE_OVERRIDE[self.mode]
        if self.mode == 64:
            logger.warn("Need to fix for long mode!") 

    def set_seg_override(self, seg_override):
        self.seg_override = seg_override

    def set_rex(self, octet):
        self.rex = octet

    def swap_operands(self):
        self.op1, self.op2 = self.op2, self.op1

    def set_lock_prefix(self):
        self.lock = "lock "

def to_indirect_sib(instr, val, disp):
    scale = 1 << (val >> 6)
    offset = INDIRECT_32BIT((val & 0x38) >> 3)
    base = SIB_BASE_REG(val & 7)
    if disp:
        if scale > 1:
            return "{}({},{},{})".format(disp, base, offset, scale)
        else:
            return "{}({},{})".format(disp, base, offset)
    else:
        if scale > 1:
            return "({},{},{})".format(base, offset, scale)
        else:
            return "({},{})".format(base, offset)

def to_r16_32_reg(instr, val):
    if instr.data_mode == 32:
        return REGS_32BIT[val]
    return REGS_16BIT[val]


def to_r32_reg(val):
    return REGS_32BIT[val]


def to_mm_reg(val):
    return "MM{}".format(val)


def to_xmm_reg(val):
    return "XMM{}".format(val)


def extract_32bit_disp(data, idx):
    disp = data[idx] + (data[idx+1] << 8) + (data[idx+2] << 16) + (data[idx+3] << 24)
    if disp > 0x7fffffff: # Word is signed!
        disp = disp - 0x100000000
    return disp, idx + 4


def extract_16bit_disp(data, idx):
    disp = data[idx] + (data[idx+1] << 8)
    if disp > 0x7fff: # Word is signed!
        disp = disp - 0x10000
    return disp, idx + 2


def extract_8bit_disp(data, idx):
    disp = data[idx]
    if disp > 0x7f:   # Byte is signed!
        disp = disp - 0x100
    return disp, idx + 1


def mod00(instr, op2_code, data, idx):
    # Do the Effective address element from the 16-bit / 32-bit
    # ModR/M Byte given mod val 0
    if instr.addr_mode == 16:
        if op2_code == 6:
            disp, idx = extract_16bit_disp(data, idx)
            op2 = "({})".format(disp)
        else:
            op2 = to_indirect(instr, op2_code, None)
    elif instr.addr_mode == 32:
        if op2_code == 5:
            disp, idx = extract_32bit_disp(data, idx)
            op2 = "({})".format(disp)
        elif op2_code == 4:
            sib = data[idx]
            idx += 1
            op2 = to_indirect_sib(instr, sib, None)
        else:
            op2 = to_indirect(instr, op2_code, None)
    instr.op2 = op2
    return idx


def mod01(instr, op2_code, data, idx):
    # Do the Effective address element from the 16-bit / 32-bit
    # ModR/M Byte given mod val 01
    if (instr.addr_mode == 32) and (op2_code == 5):
        sib = data[idx]
        idx += 1
        op2 = to_indirect_sib(instr, sib, None)
    else:
        # 8 bit displacement
        disp, idx = extract_8bit_disp(data, idx)
        op2 = to_indirect(instr, op2_code, disp)
    instr.op2 = op2
    return idx


def mod10(instr, op2_code, data, idx):
    # Do the Effective address element from the 16-bit / 32-bit
    # ModR/M Byte given mod val 10
    if instr.addr_mode == 16:
        # 16 bit displacement
        disp, idx = extract_16bit_disp(data, idx)
        op2 = to_indirect(instr, op2_code, disp)
    elif instr.addr_mode == 32:
        if op2_code == 4:
            sib = data[idx]
            idx += 1
            op2 = to_indirect_sib(instr, sib, None)
        else:
            disp, idx = extract_32bit_disp(data, idx)
            op2 = to_indirect(instr, op2_code, disp)
    instr.op2 = op2
    return idx
 

def modrm2reg8(instr, data, idx):
    """For Opcodes where the ModR/M defs two 8 bit operands"""
    modrm = data[idx]
    mod = modrm & 0xc0
    op2_code = modrm & 7
    idx += 1
    if mod == 0x00:
        idx = mod00(instr, op2_code, data, idx)
    elif mod == 0x40:
        idx = mod01(instr, op2_code, data, idx)
    elif mod == 0x80:
        idx = mod10(instr, op2_code, data, idx)
    elif mod == 0xc0:
        instr.op2 = to_r8_reg(op2_code)
    instr.op1 = to_r8_reg((modrm & 0x38) >> 3)
    return idx


def rev_modrm2reg8(instr, data, idx):
    idx = modrm2reg8(instr, data, idx)
    instr.swap_operands()
    return idx


def modrm2reg16_32(instr, data, idx):
    modrm = data[idx]
    mod = modrm & 0xc0
    op2_code = modrm & 7
    idx += 1
    if mod == 0x00:
        idx = mod00(instr, op2_code, data, idx)
    elif mod == 0x40:
        idx = mod01(instr, op2_code, data, idx)
    elif mod == 0x80:
        idx = mod10(instr, op2_code, data, idx)
    elif mod == 0xc0:
        instr.op2 = to_r16_32_reg(instr, op2_code)
    instr.op1 = to_r16_32_reg(instr, (modrm & 0x38) >> 3)
    return idx


def rev_modrm2reg16_32(instr, data, idx):
    idx = modrm2reg16_32(instr, data, idx)
    instr.swap_operands()
    return idx


def imm2al(instr, data, idx):
    disp, idx = extract_8bit_disp(data, idx)
    instr.op1 = "${}".format(disp)
    instr.op2 = "%al"
    return idx


def imm2ax(instr, data, idx):
    if instr.data_mode == 32:
        disp, idx = extract_32bit_disp(data, idx)
        instr.op2 = "%eax"
    else:
        disp, idx = extract_16bit_disp(data, idx)
        instr.op2 = "%ax"
    instr.op1 = "${}".format(disp)
    return idx


def reg_es(instr, data, idx):
    return idx, ("%es", None)


def reg_cs(instr, data, idx):
    instr.op1 = "%cs"
    return idx


def reg_ss(instr, data, idx):
    instr.op1 = "%ss"
    return idx


def reg_ds(instr, data, idx):
    instr.op1 = "%ds"
    return idx


def reg_al(instr, data, idx):
    instr.op1 = "%al"
    return idx


def reg_e_ax(instr, data, idx):
    return to_r16_32_reg(instr, 0)

def reg_e_cx(instr, data, idx):
    return to_r16_32_reg(instr, 1)

def reg_e_dx(instr, data, idx):
    return to_r16_32_reg(instr, 2)

def reg_e_bx(instr, data, idx):
    return to_r16_32_reg(instr, 3)

def reg_e_sp(instr, data, idx):
    return to_r16_32_reg(instr, 4)

def reg_e_bp(instr, data, idx):
    return to_r16_32_reg(instr, 5)

def reg_e_si(instr, data, idx):
    return to_r16_32_reg(instr, 6)

def reg_e_di(instr, data, idx):
    return to_r16_32_reg(instr, 7)


ONE_BYTE_OPCODES = (
    # 0x00 - 0x0f
    ("add", modrm2reg8),
    ("add", modrm2reg16_32),
    ("add", rev_modrm2reg8),
    ("add", rev_modrm2reg16_32),
    ("add", imm2al),
    ("add", imm2ax),
    ("push", reg_es),
    ("pop", reg_es),
    ("or", modrm2reg8),
    ("or", modrm2reg16_32),
    ("or", rev_modrm2reg8),
    ("or", rev_modrm2reg16_32),
    ("or", imm2al),
    ("or", imm2ax),
    ("push", reg_cs),
    None, # 0x0f - Two byte prefix
    # 0x10 - 0x1f
    ("adc", modrm2reg8),
    ("adc", modrm2reg16_32),
    ("adc", rev_modrm2reg8),
    ("adc", rev_modrm2reg16_32),
    ("adc", imm2al),
    ("adc", imm2ax),
    ("push", reg_ss),
    ("pop", reg_ss),
    ("sbb", modrm2reg8),
    ("sbb", modrm2reg16_32),
    ("sbb", rev_modrm2reg8),
    ("sbb", rev_modrm2reg16_32),
    ("sbb", imm2al),
    ("sbb", imm2ax),
    ("push", reg_ds),
    ("pop", reg_ds),
    # 0x20 - 0x2f
    ("and", modrm2reg8),
    ("and", modrm2reg16_32),
    ("and", rev_modrm2reg8),
    ("and", rev_modrm2reg16_32),
    ("and", imm2al),
    ("and", imm2ax),
    None, # 0x26 - ES Override
    ("daa", reg_al),
    ("sub", modrm2reg8),
    ("sub", modrm2reg16_32),
    ("sub", rev_modrm2reg8),
    ("sub", rev_modrm2reg16_32),
    ("sub", imm2al),
    ("sub", imm2ax),
    None, # 0x2E - CS Override
    ("das", reg_al),
    # 0x30 - 0x3f
    ("xor", modrm2reg8),
    ("xor", modrm2reg16_32),
    ("xor", rev_modrm2reg8),
    ("xor", rev_modrm2reg16_32),
    ("xor", imm2al),
    ("xor", imm2ax),
    None, # 0x36 - SS Override
    ("aaa", reg_al),
    ("cmp", modrm2reg8),
    ("cmp", modrm2reg16_32),
    ("cmp", rev_modrm2reg8),
    ("cmp", rev_modrm2reg16_32),
    ("cmp", imm2al),
    ("cmp", imm2ax),
    None, # 0x3E - DS Override
    ("aas", reg_al),
    # 0x40 - 0x4f
    ("inc", reg_e_ax),
    ("inc", reg_e_cx),
    ("inc", reg_e_dx),
    ("inc", reg_e_bx),
    ("inc", reg_e_sp),
    ("inc", reg_e_bp),
    ("inc", reg_e_si),
    ("dec", reg_e_ax),
    ("dec", reg_e_cx),
    ("dec", reg_e_dx),
    ("dec", reg_e_bx),
    ("dec", reg_e_sp),
    ("dec", reg_e_bp),
    ("dec", reg_e_si),
    ("dec", reg_e_di),
    ("dec", reg_e_di),
    # 0x50 - 0x5f
    ("push", reg_e_ax),
    ("push", reg_e_cx),
    ("push", reg_e_dx),
    ("push", reg_e_bx),
    ("push", reg_e_sp),
    ("push", reg_e_bp),
    ("push", reg_e_si),
    ("pop", reg_e_ax),
    ("pop", reg_e_cx),
    ("pop", reg_e_dx),
    ("pop", reg_e_bx),
    ("pop", reg_e_sp),
    ("pop", reg_e_bp),
    ("pop", reg_e_si),
    # 0x60 - 0x6f
    ("pusha", None),
    ("popa", None),
    ("bound",),
    ("arpl",),
    None, # 0x64 - FS Override
    None, # 0x65 - GS Overide
    None, # 0x66 - Operand/Precision-size override
    None, # 0x67 - Address-size override
    ("PUSH",),
    ("IMUL",),
    ("PUSH",),
    ("IMUL",),
    ("INS",),
    ("INS",),
    ("OUTS",),
    ("OUTS",),
    # 0x70 - 0x7f
    ("JO",),
    ("JNO",),
    ("JB",),
    ("JNB",),
    ("JZ",),
    ("JNZ",),
    ("JBE",),
    ("JNBE",),
    ("JS",),
    ("JNS",),
    ("JP",),
    ("JNP",),
    ("JL",),
    ("JNL",),
    ("JLE",),
    ("JNLE",),
    # 0x80 - 0x8f
    (("ADD","OR","ADC","SBB","AND","SUB","XOR","CMP"),),
    (("ADD","OR","ADC","SBB","AND","SUB","XOR","CMP"),),
    (("ADD","OR","ADC","SBB","AND","SUB","XOR","CMP"),),
    (("ADD","OR","ADC","SBB","AND","SUB","XOR","CMP"),),
    ("TEST",),
    ("TEST",),
    ("XCHG",),
    ("XCHG",),
    ("MOV",),
    ("MOV",),
    ("MOV",),
    ("MOV",),
    ("MOV",),
    ("LEA",),
    ("MOV",),
    ("POP",),
    # 0x90 - 0x9f
    (("XCHG","NOP", "PAUSE"),),
    None, None, None, None, None, None, None,
    (("CBW","CWDE"),),
    (("CWD","CDQ"),),
    ("CALLF",),
    ("WAIT",), # 0x9b - wait prefix
    ("PUSHF",),
    ("POPF",),
    ("SAHF",),
    ("LAHF",),
    # 0xA0 - 0xAf
    ("MOV",),
    ("MOV",),
    ("MOV",),
    ("MOV",),
    ("MOVS",),
    ("MOVS",),
    ("CMPS",),
    ("CMPS",),
    ("TEST",),
    ("TEST",),
    ("STOS",),
    ("STOS",),
    ("LODS",),
    ("LODS",),
    ("SCAS",),
    ("SCAS",),
    # 0xB0 - 0xBf
    ("MOV",),
    ("MOV",),
    ("MOV",),
    ("MOV",),
    ("MOV",),
    ("MOV",),
    ("MOV",),
    ("MOV",),
    ("MOV",),
    ("MOV",),
    ("MOV",),
    ("MOV",),
    ("MOV",),
    ("MOV",),
    ("MOV",),
    ("MOV",),
    # 0xC0 - 0xCf
    (("ROL","ROR","RCL","RCR","SHL","SHR","SAL","SAR"),),
    (("ROL","ROR","RCL","RCR","SHL","SHR","SAL","SAR"),),
    ("RETN",),
    ("RETN",),
    ("LES",),
    ("LDS",),
    ("MOV",),
    ("MOV",),
    ("ENTER",),
    ("LEAVE",),
    ("RETF",),
    ("RETF",),
    ("INT",),
    ("INT",),
    ("INT0",),
    ("IRET",),
    # 0xD0 - 0xDf
    (("ROL","ROR","RCL","RCR","SHL","SHR","SAL","SAR"),),
    (("ROL","ROR","RCL","RCR","SHL","SHR","SAL","SAR"),),
    (("ROL","ROR","RCL","RCR","SHL","SHR","SAL","SAR"),),
    (("ROL","ROR","RCL","RCR","SHL","SHR","SAL","SAR"),),
    ("AMX",),
    ("ADX",),
    None,
    ("SALC",),
    ("XLAT",),
    (("FADD","FMUL","FCOM","FCOMP","FSUB","FSUBR","FDIV","FDIVR"),),
    None, # 0xD9 Float point prefix
    None, None, None, None, None, # TODO
    # 0xE0 - 0xEf
    ("LOOPNZ",),
    ("LOOPZ",),
    ("LOOP",),
    ("JCXZ",),
    ("IN",),
    ("IN",),
    ("OUT",),
    ("OUT",),
    ("CALL",),
    ("JMP",),
    ("JMPF",),
    ("JMP",),
    ("IN",),
    ("IN",),
    ("OUT",),
    ("OUT",),
    # 0xF0 - 0xFf
    None, # 0xF0 lock
    ("INT1",),
    None, # 0xF2 Repeat Override
    None, # 0xF3 Repeat Override
    ("HLT",),
    ("CMC",),
    (("TEST","TEST","NOT","NEG","MUL","IMUL","DIV","IDIV"),),
    (("TEST","TEST","NOT","NEG","MUL","IMUL","DIV","IDIV"),),
    ("CLC",),
    ("STC",),
    ("CLI",),
    ("STI",),
    ("CLD",),
    ("STD",),
    (("INC","DEC","INC","DEC","CALL","CALLF","JMP","JMPF","PUSH"),),
)

def decode(arch, data):
    instr = Instruction(arch)
    # Do prefixes
    seg_override = 0
    lock_prefix = False
    rep_prefix = 0
    for idx in range(16):
        octet = data[idx]
        if octet == 0x26:
            instr.set_seg_override(ES_OVERRIDE)
        elif octet == 0x2e:
            instr.set_seg_override(CS_OVERRIDE)
        elif octet == 0x36:
            instr.set_seg_override(SS_OVERRIDE)
        elif octet == 0x3e:
            instr.set_seg_override(DS_OVERRIDE)
        elif octet == 0x64:
            instr.set_seg_override(FS_OVERRIDE)
        elif octet == 0x65:
            instr.set_seg_override(GS_OVERRIDE)
        elif octet == 0x66:
            instr.set_data_override()
        elif octet == 0x67:
            instr.set_addr_override()
        elif octet == 0xf0:
            instr.set_lock_prefix()
        elif octet == 0xf2:
            instr.rep_prefix = -1 # REPNZ
        elif octet == 0xf3:
            instr.rep_prefix = +1 # REPZ
        else:
            break
    else:
        logger.error("Too many prefixes")

    if (instr.mode == 64) and ((octet >= 0x40) or (octet <= 0x4f)):
        instr.set_rex(octet)
        idx += 1
        octet = data[idx]

    # octet is the operand, step forward ready for next.
    idx += 1

    if octet == 0x0f:
        # Two byte opcode
        pass
    else:
        mnemonic, operand_fn = ONE_BYTE_OPCODES[octet]
    instr.mnemonic = mnemonic
    try:
        idx = operand_fn(instr, data, idx)
    except TypeError:
        raise ValueError
    return "{}{} {},{}".format(instr.lock, instr.mnemonic, instr.op1, instr.op2), idx
