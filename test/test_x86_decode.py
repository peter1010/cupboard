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

def assemble(data):
    args = ["as", "-al", "--listing-lhs-width=20", "--"]
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate(data.encode("ascii") + b"\n")
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        line_num, rest = line.split(maxsplit=1)
        if line_num != b'1':
            continue
        code, assembly = rest.split(b"\t")
        addr, code = code.split(b" ", maxsplit=1)
        code = b"".join(code.split())
        data = [code[i:i+2] for i in range(0, len(code), 2)]
        data = bytes([int(i, 16) for i in data])
        return data

class X86DecodeTest(unittest.TestCase):

    def setUp(self):
        pass

    def testAdd1(self):
        data = b"\x00\xE3"
        instruction, idx = decode.decode(Arch(), data)
        self.assertEqual(str(instruction), "add %ah,%bl")
        self.assertEqual(data, assemble(instruction))

    def testAdd1a(self):
        data = b"\x66\x01\xC3"
        instruction, idx = decode.decode(Arch(), data)
        self.assertEqual(str(instruction), "add %ax,%bx")
        self.assertEqual(data, assemble(instruction))

    def testAdd1b(self):
        data = b"\x01\xC3"
        instruction, idx = decode.decode(Arch(), data)
        self.assertEqual(str(instruction), "add %eax,%ebx")
        self.assertEqual(data, assemble(instruction))

    def testAdd2(self):
        data = b"\x67\x00\x47\x0a"
        instruction, idx = decode.decode(Arch(), data)
        self.assertEqual(str(instruction), "add %al,10(%bx)")
        self.assertEqual(data, assemble(instruction))

    def testAdd3(self):
        data = b"\x00\x43\x0a"
        instruction, idx = decode.decode(Arch(), data)
        self.assertEqual(str(instruction), "add %al,10(%ebx)")
        self.assertEqual(data, assemble(instruction))

    def testAdd4(self):
        data = b"\x02\x05\x0a\x00\x00\x00"
        instruction, idx = decode.decode(Arch(), data)
        self.assertEqual(str(instruction), "add (10),%al")
        self.assertEqual(data, assemble(instruction))

    def testAdd5(self):
        data = b"\x66\x03\x05\x0a\x00\x00\x00"
        instruction, idx = decode.decode(Arch(), data)
        self.assertEqual(str(instruction), "add (10),%ax")
        self.assertEqual(data, assemble(instruction))

    def testAdd6(self):
        data = b"\x03\x05\x0a\x00\x00\x00"
        instruction, idx = decode.decode(Arch(), data)
        self.assertEqual(str(instruction), "add (10),%eax")
        self.assertEqual(data, assemble(instruction))

    def test_fuzzy(self):
        for i in range(1000):
            data = bytes([random.randint(0, 255) for i in range(16)])
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
    assemble("add %al, %ah\n")
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
