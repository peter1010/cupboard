import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

ES_OVERRIDE=1
CS_OVERRIDE=2
SS_OVERRIDE=3
DS_OVERRIDE=4


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


def to_indirect(arch, val, disp):
    if arch.addr_size == 16:
        regs = INDIRECT_16BIT[val]
    elif arch.addr_size == 32:
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

def to_indirect_sib(arch, val, disp):
    scale = 1 << (val >> 6)
    offset = INDIRECT_32REG((val & 0x38) >> 3)
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

def to_r16_32_reg(arch, val):
    if arch.data_size == 32:
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


def mod00(arch, op2_code, data, idx):
    # Do the Effective address element from the 16-bit / 32-bit
    # ModR/M Byte given mod val 0
    if arch.addr_size == 16:
        if op2_code == 6:
            disp, idx = extract_16bit_disp(data, idx)
            op2 = "({})".format(disp)
        else:
            op2 = to_indirect(arch, op2_code, None)
    elif arch.addr_size == 32:
        if op2_code == 5:
            disp, idx = extract_32bit_disp(data, idx)
            op2 = "({})".format(disp)
        elif op2_code == 4:
            sib = data[idx]
            idx += 1
            op2 = to_indirect_sib(arch, sib, None)
        else:
            op2 = to_indirect(arch, op2_code, None)
    return idx, op2


def mod01(arch, op2_code, data, idx):
    # Do the Effective address element from the 16-bit / 32-bit
    # ModR/M Byte given mod val 01
    if (arch.addr_size == 32) and (op2_code == 5):
        sib = data[idx]
        idx += 1
        op2 = to_indirect_sib(arch, sib, None)
    else:
        # 8 bit displacement
        disp, idx = extract_8bit_disp(data, idx)
        op2 = to_indirect(arch, op2_code, disp)
    return idx, op2


def mod10(arch, op2_code, data, idx):
    # Do the Effective address element from the 16-bit / 32-bit
    # ModR/M Byte given mod val 10
    if arch.addr_size == 16:
        # 16 bit displacement
        disp, idx = extract_16bit_disp(data, idx)
        op2 = to_indirect(arch, op2_code, disp)
    elif arch.addr_size == 32:
        if op2_code == 4:
            sib = data[idx]
            idx += 1
            op2 = to_indirect_sib(arch, sib, None)
        else:
            disp, idx = extract_32bit_disp(data, idx)
            op2 = to_indirect(arch, op2_code, disp)
    return idx, op2
 

def modrm2reg8(arch, data, idx):
    """For Opcodes where the ModR/M defs two 8 bit operands"""
    modrm = data[idx]
    mod = modrm & 0xc0
    op2_code = modrm & 7
    idx += 1
    if mod == 0x00:
        idx, op2 = mod00(arch, op2_code, data, idx)
    elif mod == 0x40:
        idx, op2 = mod01(arch, op2_code, data, idx)
    elif mod == 0x80:
        idx, op2 = mod10(arch, op2_code, data, idx)
    elif mod == 0xc0:
        op2 = to_r8_reg(op2_code)
    op1 = to_r8_reg((modrm & 0x38) >> 3)
    return idx, (op1, op2)


def rev_modrm2reg8(arch, data, idx):
    idx, ops = modrm2reg8(arch, data, idx)
    return idx, (ops[1], ops[0])


def modrm2reg16_32(arch, data, idx):
    modrm = data[idx]
    mod = modrm & 0xc0
    op2_code = modrm & 7
    idx += 1
    if mod == 0x00:
        idx, op2 = mod00(arch, op2_code, data, idx)
    elif mod == 0x40:
        idx, op2 = mod01(arch, op2_code, data, idx)
    elif mod == 0x80:
        idx, op2 = mod10(arch, op2_code, data, idx)
    elif mod == 0xc0:
        op2 = to_r16_32_reg(arch, op2_code)
    op1 = to_r16_32_reg(arch, (modrm & 0x38) >> 3)
    return idx, (op1, op2)


def rev_modrm2reg16_32(arch, data, idx):
    idx, ops = modrm2reg16_32(arch, data, idx)
    return idx, (ops[1], ops[0])


def imm2al(arch, data, idx):
    disp, idx = extract_8bit_disp(data, idx)
    return idx, ("${}".format(disp), "%al")


def imm2ax(arch, data, idx):
    if arch.data_size == 32:
        disp, idx = extract_32bit_disp(data, idx)
        op2 = "%eax"
    else:
        disp, idx = extract_16bit_disp(data, idx)
        op2 = "%ax"
    return idx, ("${}".format(disp), op2)


def reg_es(arch, data, idx):
    return idx, ("%es", None)


def reg_cs(arch, data, idx):
    return idx, ("%cs", None)


def reg_ss(arch, data, idx):
    return idx, ("%ss", None)


def reg_ds(arch, data, idx):
    return idx, ("%ds", None)


def reg_al(arch, data, idx):
    return idx, ("%al", None)

def reg_e_ax(arch, data, idx):
    if arch.data_size == 32:
        return "%eax"
    return "%ax"

def reg_e_cx(arch, data, idx):
    if arch.data_size == 32:
        return "%ecx"
    return "%cx"

#    "%dx",  # Lower 16 bite of D
#    "%bx",  # Lower 16 bits of B
#    "%sp",  # Stack pointer (16 bits)
#    "%bp",  # Base Pointer (16 bits)
#    "%si",  # Address reg (16 bits)
#    "%di"   # Address reg (16 bits)


def opcode2reg16_32(arch, data, idx):
    """For Opcodes where last 3 bits encode the register"""
    #e.g. POP EAX
    val = data[idx-1] & 0x7
    if cpu_width == 16:
        return to_r8_reg(val)
    return to_r16_32_reg(arch, val), idx


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
    ("inc",),
    ("inc",),
    ("inc",),
    ("inc",),
    ("inc",),
    ("inc",),
    ("dec",),
    ("DEC",),
    ("DEC",),
    ("DEC",),
    ("DEC",),
    ("DEC",),
    ("DEC",),
    ("DEC",),
    # 0x50 - 0x5f
    ("PUSH", opcode2reg16_32),
    ("PUSH", opcode2reg16_32),
    ("PUSH", opcode2reg16_32),
    ("PUSH", opcode2reg16_32),
    ("PUSH", opcode2reg16_32),
    ("PUSH", opcode2reg16_32),
    ("PUSH", opcode2reg16_32),
    ("PUSH", opcode2reg16_32),
    ("POP", opcode2reg16_32),
    ("POP", opcode2reg16_32),
    ("POP", opcode2reg16_32),
    ("POP", opcode2reg16_32),
    ("POP", opcode2reg16_32),
    ("POP", opcode2reg16_32),
    ("POP", opcode2reg16_32),
    ("POP", opcode2reg16_32),
    # 0x60 - 0x6f
    ("PUSHA",),
    ("POPA",),
    ("BOUND",),
    ("ARPL",),
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
    # Do prefixes
    seg_override = 0
    lock_prefix = False
    rep_prefix = 0
    for idx in range(16):
        octet = data[idx]
        if octet == 0x26:
            seg_override = ES_OVERRIDE
        elif octet == 0x2e:
            seg_override = CS_OVERRIDE
        elif octet == 0x36:
            seg_override = SS_OVERRIDE
        elif octet == 0x3e:
            seg_override = DS_OVERRIDE
        elif octet == 0x64:
            seg_override = FS_OVERRIDE
        elif octet == 0x65:
            seg_override = GS_OVERRIDE
        elif octet == 0x66:
            arch.data_size = 16 if arch.data_size == 32 else 32
        elif octet == 0x67:
            arch.addr_size = 16 if arch.addr_size == 32 else 32
        elif octet == 0xf0:
            lock_prefix = True
        elif octet == 0xf2:
            rep_prefix = REPNZ
        elif octet == 0xf3:
            rep_prefix = REPZ
        else:
            break
    else:
        logger.error("Too many prefixes")
    idx += 1

    if octet == 0x0f:
        # Two byte opcode
        pass
    else:
        mnemonic, operand_fn = ONE_BYTE_OPCODES[octet]
        idx, ops = operand_fn(arch, data, idx)
        return "{} {},{}".format(mnemonic, ops[0], ops[1])
        pass
