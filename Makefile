PREFIX=/usr/local
INSTALL=install

torskbot:

TAGS tags: torskbot.py
	etags -l python $<
	ctags -l python $<

lint: torskbot.py
	pyflakes $<

install: torskbot
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	$(INSTALL) torskbot $(DESTDIR)$(PREFIX)/bin

clean:
	rm -f torskbot TAGS tags

.SUFFIXES: .py
.py:
	cp $< $@
	chmod a+x $@
