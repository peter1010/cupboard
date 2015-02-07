#!/usr/bin/env python3

import unittest
import sys

sys.path.append("..")

from symbols import __main__ as symbols
from symbols import parse_elf as elf
from symbols import errors

class Consumer:
    def __init__(self):
        pass
    def set_data_source(self, pathname):
        self.pathname = pathname

class ElfTest(unittest.TestCase):
    
    def testLoad_badfile(self):
        obj = Consumer()
        with self.assertRaises(FileNotFoundError):
            elf.read_elffile("/usr/bin/wibble_wobble", obj)

    def testLoad_notElf(self):
        obj = Consumer()
        with self.assertRaises(errors.NotElfFileError):
            elf.read_elffile("/etc/fstab", obj)

    def testLoad(self):
        obj = Consumer()
        elf.read_elffile("/usr/bin/echo", obj)
        self.assertEqual(obj.pathname, "/usr/bin/echo")

def main():
    symbols.config_logging(also_to_console=False)
    unittest.main()

if __name__ == "__main__":
    main()
