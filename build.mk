CFLAGS=-Wall -O3

MAKEDEPEND=gcc -M $(CPPFLAGS) -o $*.d $<
COMPILE=gcc -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
LINK=gcc $(LDFLAGS) -o $@

OBJS= symbols.o logging.o symbol2addr.o

.PHONY: all
all: symbol2addr

symbol2addr: $(OBJS)
	$(LINK) $(OBJS)

%.o : %.c
	$(COMPILE) -MMD
	@cp $*.d $*.P;
	@sed -e 's/#.*//' -e 's/^[^:]*: *//' -e 's/ *\\$$//' -e '/^$$/ d' -e 's/$$/ :/' < $*.d >> $*.P
	@rm -f $*.d
	@mv $*.P $*.d


-include $(OBJS:.o=.d)
