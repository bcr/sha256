CFLAGS=-Wall -DUNIT_TEST
PDFTEX=pdftex

%.pdf: %.tex
	$(PDFTEX) $<

all: sha256 sha256.pdf
