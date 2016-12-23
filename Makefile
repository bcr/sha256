CFLAGS=-Wall -DUNIT_TEST
PDFTEX=pdftex

%.pdf: %.tex
	$(PDFTEX) $<

all: sha256 sha256.pdf

test: sha256
	! ./sha256 | grep -q FAIL
