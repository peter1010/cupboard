#!/usr/bin/env python3

import unittest
import sys

sys.path.append("..")

from symbols import __main__ as symbols
from symbols import elf
from symbols import errors


class ElfTest(unittest.TestCase):
    
    def testLoad_badfile(self):
        with self.assertRaises(FileNotFoundError):
            elf.read_elffile("/usr/bin/wibble_wobble")

    def testLoad_notElf(self):
        with self.assertRaises(errors.NotElfFileError):
            elf.read_elffile("/etc/fstab")

    def testLoad(self):
        elf.read_elffile("/usr/bin/echo")

def main():
    symbols.config_logging(also_to_console=False)
    unittest.main()

if __name__ == "__main__":
    main()
