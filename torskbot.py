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
    return not idneq(olddl[-2], newdl[-2]) and olddl[-2]+olddl[-1] != newdl[-2]


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
            super().__init__(False)

        def handle_starttag(self, tag, attrs):
            if tag == 'meta':
                attrs = dict(attrs)
                if 'charset' in attrs:
                    self.result = attrs['charset']
                elif (attrs.get('http-equiv', '').lower() == 'content-type' and
                        'content' in attrs):
                    match = re.match('text/html;\s*charset=(.+)',
                                     attrs['content'])
                    if match:
                        self.result = match.group(1)


class TitleHTMLParser(HTMLParser):

    def __init__(self):
        self._intitle = False
        self._title = ''
        self.result = None
        super().__init__(False)

    def handle_starttag(self, tag, attrs):
        if tag == 'title' and not self.result:
            self._intitle = True

    def handle_endtag(self, tag):
        if tag == 'title':
            if self._title:
                space = '\x20\x09\x0a\x0c\x0d'
                self.result = re.sub('[{}]+'.format(space), ' ',
                                     self._title).strip(space)
            self._intitle = False

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


class RedirectHTMLParser(HTMLParser):

        def __init__(self):
            self.result = None
            super().__init__(False)

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if (tag == 'meta' and
                    attrs.get('http-equiv', '').lower() == 'refresh' and
                    'content' in attrs):
                match = re.match('\d+;\s*url=(.+)', attrs['content'],
                                 re.IGNORECASE)
                if match:
                    self.result = match.group(1)


class ChunkedParserFeeder:

    def __init__(self, f):
        self._f = f
        self._content = b''

    def feeduntil(self, parser, encoding, maxbytes=1024**2):
        parser.feed(self._content.decode(encoding, 'replace'))

        while not parser.result and len(self._content) < maxbytes:
            chunk = self._f.read(1024)
            if not chunk:
                break
            parser.feed(chunk.decode(encoding, 'replace'))
            self._content += chunk

        return parser.result

    def peek(self, n):
        while len(self._content) < n:
            chunk = self._f.read(1024)
            if not chunk:
                break
            self._content += chunk
        return self._content[:n]


def quote_nonascii_path(path):
    return re.sub(
        b'[\x80-\xff]',
        lambda match: '%{:x}'.format(ord(match.group())).encode('ascii'),
        path.encode()).decode('ascii')


def urlquote(url):
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit(
        (parts[0], parts[1].encode('idna').decode('ascii'),
         quote_nonascii_path(parts[2])) + parts[3:])


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


def gettitlemsgs(url, from_=None, redirects=0):
    rh = FinalURLHTTPRedirectHandler()
    opener = urllib.request.build_opener(rh)
    opener.addheaders = [('User-Agent', 'torskbot'),
                         ('Accept-Encoding', 'gzip')]
    try:
        f = opener.open(urlquote(url), timeout=5)
    except urllib.error.HTTPError as e:
        f = e.fp
    if rh.final_url:
        if not from_:
            from_ = url
        url = rh.final_url

    title = None
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
        if not title and redirects < 20:
            newurl = feeder.feeduntil(RedirectHTMLParser(), cs)
            if newurl:
                # TODO: Use `yield from' when upgrading from Python 3.2.
                for titlemsg in gettitlemsgs(newurl, from_ if from_ else url,
                                             redirects + 1):
                    yield titlemsg
                return

    if from_ and urlchange(urlquote(from_), urlquote(url)):
        yield 'Vidarebefordring till: ' + url
    if title:
        yield 'Titel: ' + title


def sendtitle(c, m):
    for match in re.finditer('https?://[^\s[\]{}<>«»`"‘’“”]+', m[2]):
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
                            if not m[2].startswith('!ignorera '):
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
