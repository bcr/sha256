CFLAGS=-Wall -DUNIT_TEST
PDFTEX=pdftex

%.pdf: %.tex
	$(PDFTEX) $<

all: sha256 sha256.pdf

clean:
	rm -f sha256 sha256.log sha256.toc sha256.pdf sha256.idx sha256.scn
