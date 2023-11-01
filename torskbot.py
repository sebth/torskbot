#!/usr/bin/python3

# torskbot  Copyright (C) 2014  Sebastian Thorarensen <sebth@naju.se>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import codecs
import encodings.idna
import getopt
import re
import socket
import sys
import urllib.parse
import urllib.request
from fnmatch import fnmatch
from gzip import GzipFile
from html.parser import HTMLParser
from html.entities import name2codepoint
from select import select
from time import sleep


codecs.register_error(
    'ircfallback',
    lambda e: (e.object[e.start:e.end].decode('latin-1', 'replace'), e.end))


class IRCReconnectError(Exception):
    pass


class IRCConnection:

    def __init__(self, address, nick, realname):
        self.address = address
        self.nick = nick
        self.realname = realname

    def __enter__(self):
        self._s = None
        while not self._s:
            try:
                self._s = socket.create_connection(self.address, 60)
            except socket.error as e:
                printerror('connect: ' +
                           (e.strerror if e.strerror else str(e)))
                printerror('waiting one minute before attempting to reconnect')
                sleep(60)
        self._s.settimeout(None)
        self._buf = ''
        self.send('NICK', self.nick)
        self.send('USER', self.nick, 'localhost', 'localhost', self.realname)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self._s:
            if exc_value:
                self.send('QUIT', repr(exc_value))
            self._s.close()

    def __iter__(self):
        while True:
            m = self.recv()
            if m[0] == 'PING':
                self.send('PONG', m[1])
            elif m[0] == '433':
                self.nick += '_'
                self.send('NICK', self.nick)
            else:
                yield m
                if self.nick.endswith('_'):
                    self.nick = self.nick.rstrip('_')
                    self.send('NICK', self.nick)

    def _reconnect(self):
        self._s.close()
        self.__enter__()
        raise IRCReconnectError()

    def _sendall(self, b):
        try:
            self._s.sendall(b)
        except socket.error as e:
            printerror('send: ' + (e.strerror if e.strerror else str(e)))
            self._reconnect()

    def _recv(self, size):
        try:
            buf = self._s.recv(size)
        except socket.error as e:
            printerror('recv: ' + (e.strerror if e.strerror else str(e)))
            self._reconnect()
        if not buf:
            self._reconnect()
        return buf

    def send(self, *m):
        if ' ' in m[-1] or ':' in m[-1]:
            m = m[:-1] + (':' + m[-1],)
        self._sendall(' '.join(m).encode()[:510] + b'\r\n')

    def _testconn(self):
        if not select([self._s], [], [], 60)[0]:
            self.send('PING', 'server')
            if not select([self._s], [], [], 60)[0]:
                self.send('QUIT', 'Tidsfristen för ping löpte ut')
                self._reconnect()

    def recv(self):
        while '\r\n' not in self._buf:
            self._testconn()
            self._buf += self._recv(512).decode(errors='ircfallback')

        l = ol = self._buf[:self._buf.index('\r\n')]
        if l[0] == ':':
            l = l[l.index(' ')+1:]
        m = l.split(':', 1)
        self._buf = self._buf[len(ol)+2:]
        return m[0].split() + ([m[1]] if len(m) > 1 else [])


def urldls(url):
    return urllib.parse.urlsplit(url)[1].split('.')


def idneq(domain1, domain2):
    domain1 = (encodings.idna.ToUnicode(domain1)
               .encode('ascii', 'replace').decode('ascii'))
    domain2 = (encodings.idna.ToUnicode(domain2)
               .encode('ascii', 'replace').decode('ascii'))
    return fnmatch(domain1, domain2) or fnmatch(domain2, domain1)


def urlchange(oldurl, newurl):
    olddl = urldls(oldurl)
    newdl = urldls(newurl)
    domainhack = olddl[-2] + olddl[-1]
    return (not idneq(olddl[-2], newdl[-2]) and
            domainhack != newdl[-2] and
            domainhack != newdl[-2][:-1])


class FinalURLHTTPRedirectHandler(urllib.request.HTTPRedirectHandler):

    def __init__(self, *args, **kwargs):
        self.final_url = None
        super().__init__(*args, **kwargs)

    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        self.final_url = newurl
        return super().redirect_request(req, fp, code, msg, hdrs, newurl)


class EncodingHTMLParser(HTMLParser):

    def __init__(self):
        self.result = None
        self.done = False
        self.should_be_done = False
        super().__init__()

    def handle_starttag(self, tag, attrs):
        if not self.done and tag == 'meta':
            attrs = dict(attrs)
            if 'charset' in attrs:
                self.result = attrs['charset']
                self.done = True
            elif (attrs.get('http-equiv', '').lower() == 'content-type' and
                    'content' in attrs):
                match = re.match('text/html;\s*charset=(.+)',
                                 attrs['content'])
                if match:
                    self.result = match.group(1)
                    self.done = True

    def handle_endtag(self, tag):
        if tag in ('head', 'html'):
            self.done = True


class TitleHTMLParser(HTMLParser):

    def __init__(self):
        self._intitle = False
        self._title = ''
        self.title = None
        self.og_title = None
        self.done = False
        self.should_be_done = False
        super().__init__()

    def handle_starttag(self, tag, attrs):
        if not self.done:
            attrs = dict(attrs)
            if self.title is None and tag == 'title':
                self._intitle = True
            elif (tag == 'meta' and
                    attrs.get('property', '').lower() == 'og:title'):
                self.og_title = re.sub('[\r\n]', ' ', attrs.get('content', ''))

    def handle_endtag(self, tag):
        if tag == 'title':
            space = '\x20\x09\x0a\x0c\x0d'
            self.title = re.sub('[{}]+'.format(space), ' ',
                                self._title).strip(space)
            self._intitle = False
        elif tag == 'head':
            if self.result:
                self.done = True
            else:
                # Some non-conforming pages have the title at the
                # beginning of the body instead of in the head.  Signal
                # to the caller that we _should_ be done if the page is
                # conforming, but that it can continue feeding if it
                # wants to be stubborn.
                self.should_be_done = True
        elif tag == 'html':
            self.done = True

    def handle_data(self, data):
        if self._intitle:
            self._title += data

    def handle_entityref(self, name):
        if self._intitle:
            self._title += chr(name2codepoint[name])

    def handle_charref(self, name):
        if self._intitle:
            self._title += chr(int(name[1:], 16) if name.startswith('x')
                               else int(name))

    @property
    def result(self):
        return self.og_title or self.title


class DescHTMLParser(HTMLParser):

    def __init__(self):
        self.desc = None
        self.og_desc = None
        self.done = False
        self.should_be_done = False
        super().__init__()

    def handle_starttag(self, tag, attrs):
        if not self.done and tag == 'meta':
            attrs = dict(attrs)
            if (self.desc is None and
                    attrs.get('name', '').lower() == 'description'):
                self.desc = re.sub('[\r\n]', ' ', attrs.get('content', ''))
            elif attrs.get('property', '').lower() == 'og:description':
                self.og_desc = re.sub('[\r\n]', ' ', attrs.get('content', ''))
                self.done = True

    def handle_endtag(self, tag):
        if tag in ('head', 'html'):
            self.done = True

    @property
    def result(self):
        return self.og_desc or self.desc


class RedirectHTMLParser(HTMLParser):

    def __init__(self):
        self.result = None
        self.done = False
        self.should_be_done = False
        super().__init__()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if (not self.done and tag == 'meta' and
                attrs.get('http-equiv', '').lower() == 'refresh' and
                'content' in attrs):
            match = re.match('\d+;\s*url=(.+)', attrs['content'],
                             re.IGNORECASE)
            if match:
                self.result = match.group(1)
                self.done = True

    def handle_endtag(self, tag):
        if tag in ('head', 'html'):
            self.done = True


class ChunkedParserFeeder:

    def __init__(self, f):
        self._f = f
        self._content = b''

    def feeduntil(self, parser, encoding, maxbytes=1024**2):
        d = codecs.getincrementaldecoder(encoding)(errors='replace')
        parser.feed(d.decode(self._content))

        non_conforming_tries = 0
        while not parser.done and non_conforming_tries < 2 and len(self._content) < maxbytes:
            if parser.should_be_done:
                non_conforming_tries += 1
            chunk = self._f.read(1024)
            if not chunk:
                break
            parser.feed(d.decode(chunk))
            self._content += chunk

        return parser.result

    def peek(self, n):
        while len(self._content) < n:
            chunk = self._f.read(1024)
            if not chunk:
                break
            self._content += chunk
        return self._content[:n]


def quote_nonascii(s):
    return re.sub(
        b'[\x80-\xff]',
        lambda match: '%{:x}'.format(ord(match.group())).encode('ascii'),
        s.encode()).decode('ascii')


def urlquote(url):
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit(
        (parts[0], parts[1].encode('idna').decode('ascii'))
        + tuple(map(quote_nonascii, parts[2:])))


def bom2charset(bom):
    if bom.startswith(codecs.BOM_UTF8):
        return 'utf-8-sig'
    if bom == codecs.BOM_UTF32_BE:
        return 'utf-32-be'
    if bom == codecs.BOM_UTF32_LE:
        return 'utf-32-le'
    if bom.startswith(codecs.BOM_UTF16_BE):
        return 'utf-16-be'
    if bom.startswith(codecs.BOM_UTF16_LE):
        return 'utf-16-le'


def normalize(s, skip=0):
    return ' '.join(' '.join(re.split('\W+', s.lower())[skip:]).split())


def fuzzymatch(url, needle):
    return normalize(needle) in normalize(url, 1)


def gettitlemsgs(url, from_=None, redirects=0):
    rh = FinalURLHTTPRedirectHandler()
    opener = urllib.request.build_opener(rh)
    opener.addheaders = [('User-Agent', 'torskbot bot'),
                         ('Accept-Encoding', 'gzip')]
    try:
        f = opener.open(urlquote(url), timeout=5)
    except urllib.error.HTTPError as e:
        f = e
    if rh.final_url:
        if not from_:
            from_ = url
        url = rh.final_url

    info = f.info()
    t = info.get_content_type()
    xml = t in ('application/xhtml+xml', 'application/xml', 'text/xml')
    if t == 'text/html' or xml:
        feeder = ChunkedParserFeeder(GzipFile(fileobj=f)
                                     if info['Content-Encoding'] == 'gzip'
                                     else f)

        cs = bom2charset(feeder.peek(4))
        if not cs:
            cs = info.get_content_charset()
            if not cs:
                if xml:
                    match = re.match(b'\<\?xml\s+version=".*?"\s+'
                                     b'encoding="(.+?)"', feeder.peek(1024))
                    cs = match.group(1).decode('ascii') if match else 'utf-8'
                else:
                    # The standard says that the encoding must be
                    # declared within the first 1024 bytes but some
                    # pages violate that.  Allow up to 2048 to give
                    # some margin.
                    cs = feeder.feeduntil(EncodingHTMLParser(), 'latin-1',
                                          2048)
                    if not cs:
                        cs = 'latin-1'

        title = feeder.feeduntil(TitleHTMLParser(), cs)
        if title is None and redirects < rh.max_redirections:
            newurl = feeder.feeduntil(RedirectHTMLParser(), cs)
            if newurl:
                yield from gettitlemsgs(newurl, from_ if from_ else url,
                                        redirects + 1)
                return

    if from_ and urlchange(urlquote(from_), urlquote(url)):
        yield 'Omdirigering: ' + url

    if t == 'text/html' or xml:
        if title and not fuzzymatch(url, title):
            yield 'Titel: ' + title
        else:
            desc = feeder.feeduntil(DescHTMLParser(), cs)
            if desc and not fuzzymatch(url, desc):
                yield 'Beskrivning: ' + desc


def sendtitle(c, m):
    if m[2].startswith('\x01ACTION ') and m[2].endswith('\x01'):
        # This is a "/me" message
        msg = m[2].strip('\x01').split(' ', 1)[1]
    else:
        msg = m[2]
    for match in re.finditer('https?://[^\s[\]{}<>«»`"‘’“”]+', msg):
        for titlemsg in gettitlemsgs(match.group()):
            c.send('PRIVMSG', m[1], titlemsg)


def printerror(s):
    print(': '.join((sys.argv[0], s)), file=sys.stderr)


def printusage():
    print('usage: {} [-n nick] [-p port] hostname channel'.format(sys.argv[0]),
          file=sys.stderr)


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'n:p:')
    except getopt.GetoptError as e:
        printerror(e)
        printusage()
        return 2
    if len(args) != 2:
        printerror('wrong number of arguments')
        printusage()
        return 2

    ignore_re = re.compile(r'(^|\s)!ig(norera)?\b')

    with IRCConnection((args[0], dict(opts).get('-p', 6667)),
                       dict(opts).get('-n', 'torskbot'),
                       'https://github.com/sebth/torskbot') as c:
        while True:
            try:
                for m in c:
                    if m[0] == '251':
                        c.send('JOIN', args[1])
                    elif m[0] == 'PRIVMSG' and m[1].lower() == args[1].lower():
                        try:
                            if not ignore_re.search(m[2]):
                                sendtitle(c, m)
                        except IRCReconnectError:
                            raise
                        except Exception as e:
                            c.send('PRIVMSG', m[1], 'Fel: ' + repr(e))
                    elif (m[0] == 'KICK' and
                            m[1].lower() == args[1].lower() and
                            m[2] == c.nick):
                        c.send('QUIT', 'Utsparkad')
                        return
            except IRCReconnectError:
                pass


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
