#!/usr/bin/env python3

import unittest
import sys
import subprocess
import random

sys.path.append("..")

from symbols import __main__ as symbols
from symbols import x86_decode as decode
from symbols import errors

class Arch:
    def __init__(self):
        self.mode = 32

def assemble(arch, lines_of_code):
    if isinstance(lines_of_code, list):
        num_of = len(lines_of_code)
        to_assemble = "\n".join(lines_of_code) + '\n'
    else:
        num_of = None
        to_assemble = lines_of_code + '\n'
    machine_code = []
    to_assemble = to_assemble.encode("ascii")
    if arch.mode == 32:
        args = ["as", "-al", "--32", "--listing-lhs-width=20", "--"]
    else:
        args = ["as", "-al", "--64", "--listing-lhs-width=20", "--"]
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate(to_assemble)
    if stderr:
        print(stderr)
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
            print(line)
            assert False
        addr, mcode = mcode.split(b" ", maxsplit=1)
        mcode = b"".join(mcode.split())
        print(mcode, assembly)
        mcode = [mcode[i:i+2] for i in range(0, len(mcode), 2)]
        mcode = bytes([int(i, 16) for i in mcode])
        machine_code.append(mcode)
    if num_of:
        assert num_of == len(machine_code)
        return machine_code
    else:
        assert len(machine_code) == 1
        return machine_code[0]


class X86DecodeTest(unittest.TestCase):

    def setUp(self):
        pass

    def testAdd00_32bit_fixed_sib(self):
        arch = Arch()
        lines_of_code = []
        lines_of_mcode = []
        for i in range(256):
            mcode = bytes([0, i, 1, 1, 1, 1, 1, 1, 1])
            instruction, idx = decode.decode(arch, mcode)
            lines_of_code.append(instruction)
            lines_of_mcode.append(mcode[:idx])
        lines_of_mcode2 = assemble(arch, lines_of_code)
        for i in enumerate(lines_of_mcode):
            instruction = lines_of_code[idx]
            mcode = lines_of_mcode[idx]
            mcode2 = lines_of_mcode2[idx]
            if mcode[0] != mcode2[0]:      # Some assembly lead to different mcode    
                instruction2, idx = decode.decode(arch, mcode2)
                self.assertEqual(instruction2, instruction)
            else:
                self.assertEqual(mcode, mcode2)


    def testAdd00_32bit_var_sib(self):
        arch = Arch()
        lines_of_code = []
        lines_of_mcode = []
        for j in (0x0C, 0x4c, 0x8c):
            for i in range(256):
                mcode = bytes([0, j, i, 1, 1, 1, 1, 1, 1, 1])
                instruction, idx = decode.decode(arch, mcode)
                lines_of_code.append(instruction)
                lines_of_mcode.append(mcode[:idx])
        lines_of_mcode2 = assemble(arch, lines_of_code)
        for i in enumerate(lines_of_mcode):
            instruction = lines_of_code[idx]
            mcode = lines_of_mcode[idx]
            mcode2 = lines_of_mcode2[idx]
            if mcode[0] != mcode2[0]:      # Some assembly lead to different mcode    
                instruction2, idx = decode.decode(arch, mcode2)
                self.assertEqual(instruction2, instruction)
            else:
                self.assertEqual(mcode, mcode2)



    def testAdd00_16bit(self):
        arch = Arch()
        lines_of_code = []
        lines_of_mcode = []
        for i in range(256):
            mcode = bytes([0x67, 0, i, 1, 1, 1, 1, 1, 1, 1])
            instruction, idx = decode.decode(arch, mcode)
            lines_of_code.append(instruction)
            lines_of_mcode.append(mcode[:idx])
        lines_of_mcode2 = assemble(arch, lines_of_code)
        for i in enumerate(lines_of_mcode):
            instruction = lines_of_code[idx]
            mcode = lines_of_mcode[idx]
            mcode2 = lines_of_mcode2[idx]
            if mcode[0] != mcode2[0]:      # Some assembly lead to different mcode    
                instruction2, idx = decode.decode(arch, mcode2)
                self.assertEqual(instruction2, instruction)
            else:
                self.assertEqual(mcode, mcode2)



    def testAdd1a(self):
        arch = Arch()
        data = b"\x66\x01\xC3"
        instruction, idx = decode.decode(arch, data)
        self.assertEqual(str(instruction), "add %ax,%bx")
        self.assertEqual(data, assemble(arch, instruction))

    def testAdd1b(self):
        arch = Arch()
        data = b"\x01\xC3"
        instruction, idx = decode.decode(arch, data)
        self.assertEqual(str(instruction), "add %eax,%ebx")
        self.assertEqual(data, assemble(arch, instruction))

    def testAdd2(self):
        arch = Arch()
        data = b"\x67\x00\x47\x0a"
        instruction, idx = decode.decode(arch, data)
        self.assertEqual(str(instruction), "add %al,10(%bx)")
        self.assertEqual(data, assemble(arch, instruction))

    def testAdd4(self):
        arch = Arch()
        data = b"\x02\x05\x0a\x00\x00\x00"
        instruction, idx = decode.decode(arch, data)
        self.assertEqual(str(instruction), "add (10),%al")
        self.assertEqual(data, assemble(arch, instruction))

    def testAdd5(self):
        arch = Arch()
        data = b"\x66\x03\x05\x0a\x00\x00\x00"
        instruction, idx = decode.decode(arch, data)
        self.assertEqual(str(instruction), "add (10),%ax")
        self.assertEqual(data, assemble(arch, instruction))

    def testAdd6(self):
        arch = Arch()
        data = b"\x03\x05\x0a\x00\x00\x00"
        instruction, idx = decode.decode(arch, data)
        self.assertEqual(str(instruction), "add (10),%eax")
        self.assertEqual(data, assemble(arch, instruction))

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
