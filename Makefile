PREFIX=/usr/local
INSTALL=install

torskbot:

install: torskbot
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	$(INSTALL) torskbot $(DESTDIR)$(PREFIX)/bin

clean:
	rm -f torskbot

.SUFFIXES: .py
.py:
	cp $< $@
	chmod a+x $@
