PREFIX=/usr
BINDIR=$(PREFIX)/bin

CC=gcc
INSTALL=ginstall

all:	SimpleTunProgram
distclean:	clean

clean:
	rm SimpleTunProgram


install: all
	$(INSTALL) -D SimpleTunProgram $(DESTDIR)$(BINDIR)/SimpleTunProgram

macmask:
	$(CC) SimpleTunProgram.c -o SimpleTunProgram
