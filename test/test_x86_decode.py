#!/usr/bin/env python3

import unittest
import sys
import subprocess
import random
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

sys.path.append("..")

from symbols import __main__ as symbols
from symbols import x86_decode as decode
from symbols import errors

class Arch:
    def __init__(self):
        self.mode = 32

def assemble(arch, lines_of_code, lines_of_mcode=[]):
    machine_code = []
    num_of = len(lines_of_code)
    to_assemble = "\n".join(lines_of_code) + "\n"
    to_assemble = to_assemble.encode("ascii")
    if arch.mode == 32:
        args = ["as", "-al", "--32", "--listing-lhs-width=20", "--"]
    else:
        args = ["as", "-al", "--64", "--listing-lhs-width=20", "--"]
    proc = subprocess.Popen(args,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = proc.communicate(to_assemble)
    if stderr:
        for line in stderr.splitlines():
            tokens = line.split(b":", maxsplit=4)
            if tokens[2].endswith(b"Error"):
                idx = int(tokens[1])
                print(lines_of_code[idx-1], line, lines_of_mcode[idx-1])

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            line_num, rest = line.split(maxsplit=1)
        except ValueError:
            continue
        if line_num == b'GAS':
            continue
        line_num = int(line_num)
        try:
            mcode, assembly = rest.split(b"\t")
        except ValueError:
            assert False
        addr, mcode = mcode.split(b" ", maxsplit=1)
        mcode = b"".join(mcode.split())
        logger.debug("%i: %s %s", line_num, str(mcode), assembly)
        mcode = [mcode[i:i+2] for i in range(0, len(mcode), 2)]
        mcode = bytes([int(i, 16) for i in mcode])
        machine_code.append(mcode)
    assert num_of == len(machine_code)
    return machine_code


class X86DecodeTest(unittest.TestCase):

    def setUp(self):
        pass

    def chk_disassembler(self, arch, lines_of_code, lines_of_mcode):
        if not isinstance(lines_of_code, list):
            lines_of_code = [lines_of_code]
            lines_of_mcode = [lines_of_mcode]
        lines_of_mcode2 = assemble(arch, lines_of_code, lines_of_mcode)
        for idx in range(len(lines_of_mcode)):
            instruction = lines_of_code[idx]
            mcode = lines_of_mcode[idx]
            mcode2 = lines_of_mcode2[idx]
            if mcode != mcode2:      # Some assembly lead to different mcode
                instruction2, idx = decode.decode(arch, mcode2)
                self.assertEqual(instruction2, instruction)
            else:
                self.assertEqual(mcode, mcode2)

    def chk_disassembler2(self, arch, lines_of_code, lines_of_mcode):
        if not isinstance(lines_of_code, list):
            lines_of_code = [lines_of_code]
            lines_of_mcode = [lines_of_mcode]
        lines_of_mcode2 = assemble(arch, lines_of_code, lines_of_mcode)
        for idx in range(len(lines_of_mcode)):
            instruction = lines_of_code[idx]
            mcode = lines_of_mcode[idx]
            mcode2 = lines_of_mcode2[idx]
            self.assertEqual(mcode, mcode2)


    def testAdd00_32bit_fixed_sib(self):
        arch = Arch()
        lines_of_code = []
        lines_of_mcode = []
        for i in range(256):
            mcode = bytes([0, i, 1, 2, 3, 4, 5, 6, 7, 8])
            instruction, idx = decode.decode(arch, mcode)
            lines_of_code.append(instruction)
            lines_of_mcode.append(mcode[:idx])
        self.chk_disassembler(arch, lines_of_code, lines_of_mcode)


    def testAdd00_32bit_var_sib(self):
        arch = Arch()
        lines_of_code = []
        lines_of_mcode = []
        for j in (0x0C, 0x4c, 0x8c):
            for i in range(256):
                mcode = bytes([0, j, i, 1, 2, 3, 4, 5, 6, 7])
                instruction, idx = decode.decode(arch, mcode)
                lines_of_code.append(instruction)
                lines_of_mcode.append(mcode[:idx])
        self.chk_disassembler(arch, lines_of_code, lines_of_mcode)


    def testAdd00_16bit_addr(self):
        arch = Arch()
        lines_of_code = []
        lines_of_mcode = []
        for i in range(256):
            mcode = bytes([0x67, 0, i, 1, 2, 3, 4, 5, 6, 7])
            instruction, idx = decode.decode(arch, mcode)
            lines_of_code.append(instruction)
            lines_of_mcode.append(mcode[:idx])
        self.chk_disassembler(arch, lines_of_code, lines_of_mcode)


    def testAdd01_32bit_fixed_sib(self):
        arch = Arch()
        lines_of_code = []
        lines_of_mcode = []
        for i in range(256):
            mcode = bytes([1, i, 2, 3, 4, 5, 6, 7, 8])
            instruction, idx = decode.decode(arch, mcode)
            lines_of_code.append(instruction)
            lines_of_mcode.append(mcode[:idx])
        self.chk_disassembler(arch, lines_of_code, lines_of_mcode)


    def testAdd01_32bit_var_sib(self):
        arch = Arch()
        lines_of_code = []
        lines_of_mcode = []
        for j in (0x0C, 0x4c, 0x8c):
            for i in range(256):
                mcode = bytes([1, j, i, 1, 2, 3, 4, 5, 6, 7])
                instruction, idx = decode.decode(arch, mcode)
                lines_of_code.append(instruction)
                lines_of_mcode.append(mcode[:idx])
        self.chk_disassembler(arch, lines_of_code, lines_of_mcode)


    def testAdd01_16bit_addr(self):
        arch = Arch()
        lines_of_code = []
        lines_of_mcode = []
        for i in range(256):
            mcode = bytes([0x67, 1, i, 1, 2, 3, 4, 5, 6, 7])
            instruction, idx = decode.decode(arch, mcode)
            lines_of_code.append(instruction)
            lines_of_mcode.append(mcode[:idx])
        self.chk_disassembler(arch, lines_of_code, lines_of_mcode)

    def testAdd01_16bit_op(self):
        arch = Arch()
        lines_of_code = []
        lines_of_mcode = []
        for i in range(256):
            mcode = bytes([0x66, 1, i, 1, 2, 3, 4, 5, 6, 7])
            instruction, idx = decode.decode(arch, mcode)
            lines_of_code.append(instruction)
            lines_of_mcode.append(mcode[:idx])
        self.chk_disassembler(arch, lines_of_code, lines_of_mcode)


    def testAdd01_16bit_addr_and_op(self):
        arch = Arch()
        lines_of_code = []
        lines_of_mcode = []
        for i in range(256):
            mcode = bytes([0x67, 0x66, 1, i, 1, 2, 3, 4, 5, 6, 7])
            instruction, idx = decode.decode(arch, mcode)
            lines_of_code.append(instruction)
            lines_of_mcode.append(mcode[:idx])
        self.chk_disassembler(arch, lines_of_code, lines_of_mcode)


    def testAdd02(self):
        """00 and 02 are same except ops are swapped"""
        arch = Arch()
        data = b"\x02\x05\x0a\x00\x00\x00"
        instruction, idx = decode.decode(arch, data)
        self.chk_disassembler(arch, instruction, data)

    def testAdd03(self):
        """01 and 03 are same except ops are swapped"""
        arch = Arch()
        data = b"\x66\x03\x05\x0a\x00\x00\x00"
        instruction, idx = decode.decode(arch, data)
        self.chk_disassembler(arch, instruction, data)

    def testAdd04(self):
        arch = Arch()
        data = b"\x04\x05"
        instruction, idx = decode.decode(arch, data)
        self.chk_disassembler2(arch, instruction, data)

    def testAdd05(self):
        arch = Arch()
        lines_of_mcode = [
            b"\x05\x01\x02\x03\x04",
            b"\x66\x05\x01\x02"
        ]
        lines_of_code = [decode.decode(arch, data)[0] for data in lines_of_mcode]
        self.chk_disassembler2(arch, lines_of_code, lines_of_mcode)

    def test06toFF(self):
        arch = Arch()
        lines_of_mcode = [
            b"\x06",
            b"\x07",
            b"\x08\xf1",
            b"\x09\xf1",
            b"\x0A\xf1",
            b"\x0B\xf1",
            b"\x0C\xf1",
            b"\x0D\x01\x02\x03\x04",
            b"\x0E",
            b"\x10\xf1",
            b"\x11\xf1",
            b"\x12\xf1",
            b"\x13\xf1",
            b"\x14\xf1",
            b"\x15\x01\x02\x03\x04",
            b"\x16",
            b"\x17",
            b"\x18\xf1",
            b"\x19\xf1",
            b"\x1A\xf1",
            b"\x1B\xf1",
            b"\x1C\xf1",
            b"\x1D\x01\x02\x03\x04",
            b"\x1E",
            b"\x1F",
            b"\x20\xf1",
            b"\x21\xf1",
            b"\x22\xf1",
            b"\x23\xf1",
            b"\x24\xf1",
            b"\x25\x01\x02\x03\x04",
            b"\x27",
            b"\x28\xf1",
            b"\x29\xf1",
            b"\x2A\xf1",
            b"\x2B\xf1",
            b"\x2C\xf1",
            b"\x2D\x01\x02\x03\x04",
            b"\x2F",
            b"\x30\xf1",
            b"\x31\xf1",
            b"\x32\xf1",
            b"\x33\xf1",
            b"\x34\xf1",
            b"\x35\x01\x02\x03\x04",
            b"\x37",
            b"\x38\xf1",
            b"\x39\xf1",
            b"\x3A\xf1",
            b"\x3B\xf1",
            b"\x3C\xf1",
            b"\x3D\x01\x02\x03\x04",
            b"\x3F",
            b"\x40",
            b"\x66\x40",
            b"\x60",
            b"\x66\x60",
            b"\x61",
            b"\x66\x61",
        ]
        lines_of_code = [decode.decode(arch, data)[0] for data in lines_of_mcode]
        self.chk_disassembler(arch, lines_of_code, lines_of_mcode)



    @unittest.skip("")
    def test_fuzzy(self):
        for i in range(1000):
            data = bytes([1] + [random.randint(0, 255) for i in range(16)])
            try:
                instruction, idx = decode.decode(Arch(), data)
            except ValueError:
                continue
            except TypeError:
                continue
            except AttributeError:
                continue
            except IndexError:
                continue
            print(instruction)
            data2 = assemble(instruction)
            if data[:idx] != data2:
                instruction2, idx = decode.decode(Arch(), data2)
                self.assertEqual(instruction2, instruction)
            else:
                self.assertEqual(data[:idx], data2)


def main():
    symbols.config_logging(also_to_console=False)
    unittest.main()

if __name__ == "__main__":
    main()


#   4 0007 6700470A 	add %al, 10(%bx)
#   5 000b 00430A   	add %al, 10(%ebx)
#   6 000e 67660147 	add %ax, 10(%bx)
#   6      0A
#   7 0013 6601430A 	add %ax, 10(%ebx)
#   8 0017 6701470A 	add %eax, 10(%bx)
#   9 001b 01430A   	add %eax, 10(%ebx)
#  10 001e 02050A00 	add (10),%al
#  10      0000
#  11 0024 6603050A 	add (10),%ax
#  11      000000
#  12 002b 03050A00 	add (10),%eax
#  12      0000
