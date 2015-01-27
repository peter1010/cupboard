
include ../../build_tools/rules.mk

S2A_OBJS= symbols.o logging.o symbol2addr.o mmap_entry.o elf_info.o elf32_info.o elf64_info.o addr2sym.o sym2addr.o
A2S_OBJS= symbols.o logging.o addr2symbol.o mmap_entry.o elf_info.o elf32_info.o elf64_info.o sym2addr.o addr2sym.o

.PHONY: all
all: symbol2addr addr2symbol

symbol2addr: $(S2A_OBJS)
	$(LINK) $(S2A_OBJS) -o $@ -lstdc++

addr2symbol: $(A2S_OBJS)
	$(LINK) $(A2S_OBJS) -o $@ -lstdc++

-include $(S2A_OBJS:.o=.d)
-include $(A2S_OBJS:.o=.d)
