symbols
========

A Gui written in python (using tkinter gui tools) for debugging of binary
applications running under Linux. Also contains plugins written in C.

Initial goal (yet to be achieved). Is loading of Symbol table for a running
application (either locally or remotely)

Most have been developed by me as a learning excercise to
understand deeper how it all works.

TODO
====
[ ] Load arbitrary elf files and extract symbols


lookup (wip)
============

Two binaries to get Symbol name or Symbal address from a running processes

Run 'make' to build the code, the build has only been tested on
a Arch linux distro. So I make no guarantees that it
will build on other platforms.

It builds two executables that can be found in \_\_i686\_\_ on
a 32bit machine.

symbol2addr
===========

Pass the PID of a process and the name of a symbol. If the symbol can
be found print the address that symbol is at in the process.

addr2symbol
===========

Pass the PID of a process and the address. Return the name of the symbol
which is close to that address.

