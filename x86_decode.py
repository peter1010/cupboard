import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

ES_OVERRIDE=1
CS_OVERRIDE=2
SS_OVERRIDE=3
DS_OVERRIDE=4


def to_r8_reg(val):
    return (
        "AL", "CL", "DL", "BL",
        "AH", "CH", "DH", "BH")[val]


def to_indirect(val):
    return ("[BX+SI]","[BX+DI]","[BP+SI]","[BP+DI]",
            "[SI]","[DI]","[BP]","[BX]")[val]


def to_r16_reg(val):
    return (
        "AX", "CX", "DX", "BX",
        "SP", "BP", "SI", "DI")[val]


def to_r32_reg(val):
    return (
        "EAX", "ECX", "EDX", "EBX",
        "ESP", "EBP", "ESI", "EDI")[val]


def to_mm_reg(val):
    return "MM{}".format(val)


def to_xmm_reg(val):
    return "XMM{}".format(val)

def modrm2reg8(data, idx):
    """For Opcodes where the ModR/M defs two 8 bit operands"""
    modrm = data[idx]
    mod = modrm & 0xc0
    op1_code = modrm & 7
    if mod == 0x00:
        if op1_code == 6:
            disp = data[idx+1] + data[idx+2] * 256
            idx += 2
            op1 = "[{}]".format(disp)
        else:
            op1 = to_indirect(op1_code)
    elif mod == 0x40:
        # 8 bit displacement
        disp = data[idx+1]
        if disp > 127:   # Byte is signed!
            disp = disp - 256
        op1 = to_indirect(op1_code) + "+[{}]".format(disp)
        idx += 1
    elif mod == 0x80:
        # 16 bit displacement
        disp = data[idx+1] + data[idx+2] * 256
        if disp > 32767: # Word is signed!
            disp = disp - 65536
        op1 = to_indirect(op1_code) + "+{}".format(disp)
        idx += 2
    elif mod == 0xc0:
        op1 = to_r8_reg(op1_code)
    op2 = to_r8_reg((modrm & 0x38) >> 3)
    return idx+1, (op1, op2)


def modrm2reg16_32(data, idx):
    pass

def opcode2reg16_32(data, idx):
    """For Opcodes where last 3 bits encode the register"""
    #e.g. POP EAX
    val = data[idx-1] & 0x7
    if cpu_width == 16:
        return to_r8_reg(val)
    return to_r16_reg(val), idx


one_byte_opcodes = (
    # 0x00 - 0x0f
    ("ADD", modrm2reg8),
    ("ADD", modrm2reg16_32),
    ("ADD",),
    ("ADD",),
    ("ADD",),
    ("ADD",),
    ("PUSH",),
    ("POP",),
    ("OR",),
    ("OR",),
    ("OR",),
    ("OR",),
    ("OR",),
    ("OR",),
    ("PUSH",),
    None, # 0x0f - Two byte prefix
    # 0x10 - 0x1f
    ("ADC",),
    ("ADC",),
    ("ADC",),
    ("ADC",),
    ("ADC",),
    ("ADC",),
    ("PUSH",),
    ("POP",),
    ("SBB",),
    ("SBB",),
    ("SBB",),
    ("SBB",),
    ("SBB",),
    ("SBB",),
    ("PUSH",),
    ("POP",),
    # 0x20 - 0x2f
    ("AND",),
    ("AND",),
    ("AND",),
    ("AND",),
    ("AND",),
    ("AND",),
    None, # 0x26 - ES Override
    ("DAA",),
    ("SUB",),
    ("SUB",),
    ("SUB",),
    ("SUB",),
    ("SUB",),
    ("SUB",),
    None, # 0x2E - CS Override
    ("DAS",),
    # 0x30 - 0x3f
    ("XOR",),
    ("XOR",),
    ("XOR",),
    ("XOR",),
    ("XOR",),
    ("XOR",),
    None, # 0x36 - SS Override
    ("AAA",),
    ("CMP",),
    ("CMP",),
    ("CMP",),
    ("CMP",),
    ("CMP",),
    ("CMP",),
    None, # 0x3E - DS Override
    ("AAS",),
    # 0x40 - 0x4f
    ("INC",),
    ("INC",),
    ("INC",),
    ("INC",),
    ("INC",),
    ("INC",),
    ("INC",),
    ("INC",),
    ("DEC",),
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

def decode(data):
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
            logger.warn("Fix Op override")
        elif octet == 0x67:
            logger.warn("Fix Addr override")
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

    if octet == 0x0f:
        # Two byte opcode
        pass
    else:
        pass
