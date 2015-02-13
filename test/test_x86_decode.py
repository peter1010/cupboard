#!/usr/bin/env python3

import unittest
import sys

sys.path.append("..")

from symbols import __main__ as symbols
from symbols import x86_decode as decode
from symbols import errors

class Arch:
    def __init__(self):
        self.addr_size = 32
        self.data_size = 32


class X86DecodeTest(unittest.TestCase):

    def setUp(self):
        pass

    def testAdd1(self):
        data = b"\x00\xE3"
        instruction = decode.decode(Arch(), data)
        self.assertEqual(str(instruction), "add %ah,%bl")

    def testAdd1a(self):
        data = b"\x66\x01\xC3"
        instruction = decode.decode(Arch(), data)
        self.assertEqual(str(instruction), "add %ax,%bx")

    def testAdd1b(self):
        data = b"\x01\xC3"
        instruction = decode.decode(Arch(), data)
        self.assertEqual(str(instruction), "add %eax,%ebx")

    def testAdd2(self):
        data = b"\x67\x00\x47\x0a"
        instruction = decode.decode(Arch(), data)
        self.assertEqual(str(instruction), "add %al,10(%bx)")

    def testAdd3(self):
        data = b"\x00\x43\x0a"
        instruction = decode.decode(Arch(), data)
        self.assertEqual(str(instruction), "add %al,10(%ebx)")

    def testAdd4(self):
        data = b"\x02\x05\x0a\x00\x00\x00"
        instruction = decode.decode(Arch(), data)
        self.assertEqual(str(instruction), "add (10),%al")

    def testAdd5(self):
        data = b"\x66\x03\x05\x0a\x00\x00\x00"
        instruction = decode.decode(Arch(), data)
        self.assertEqual(str(instruction), "add (10),%ax")

    def testAdd6(self):
        data = b"\x03\x05\x0a\x00\x00\x00"
        instruction = decode.decode(Arch(), data)
        self.assertEqual(str(instruction), "add (10),%eax")



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
