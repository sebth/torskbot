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

import getopt
import re
import select
import socket
import sys
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from html.entities import name2codepoint
from time import sleep


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
        self._p = select.poll()
        self._p.register(self._s, select.POLLIN)
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

    def _send(self, b):
        sent = self._s.send(b)
        if not sent:
            self._reconnect()
        return sent

    def _recv(self, size):
        buf = self._s.recv(size)
        if not buf:
            self._reconnect()
        return buf

    def send(self, *m):
        if ' ' in m[-1] or ':' in m[-1]:
            m = m[:-1] + (':' + m[-1],)
        b = (' '.join(m) + '\r\n').encode()
        while b:
            b = b[self._send(b):]

    def _testconn(self):
        if not self._p.poll(60e3):
            self.send('PING', 'server')
            if not self._p.poll(60e3):
                self.send('QUIT', 'Tidsfristen för ping löpte ut')
                self._reconnect()

    def recv(self):
        while '\r\n' not in self._buf:
            self._testconn()
            self._buf += self._recv(512).decode(errors='replace')

        l = ol = self._buf[:self._buf.index('\r\n')]
        if l[0] == ':':
            l = l[l.index(' ')+1:]
        m = l.split(':', 1)
        self._buf = self._buf[len(ol)+2:]
        return m[0].split() + ([m[1]] if len(m) > 1 else [])


def urldls(url):
    return urllib.parse.urlsplit(url)[1].split('.')


class FinalURLHTTPRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, *args, **kwargs):
        self._netloc_changed = False
        self.final_url = None
        super().__init__(*args, **kwargs)
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        olddl = urldls(req.full_url)
        newdl = urldls(newurl)
        if olddl[-2] != newdl[-2] and olddl[-2]+olddl[-1] != newdl[-2]:
            self._netloc_changed = True
        if self._netloc_changed:
            self.final_url = newurl
        return super().redirect_request(req, fp, code, msg, hdrs, newurl)


class EncodingHTMLParser(HTMLParser):

        def __init__(self):
            self.encoding = None
            super().__init__(False)

        def handle_starttag(self, tag, attrs):
            if tag == 'meta' and 'charset' in dict(attrs):
                self.encoding = dict(attrs)['charset']


class TitleHTMLParser(HTMLParser):

    def __init__(self):
        self._intitle = False
        self._title = ''
        self.title = None
        super().__init__(False)

    def handle_starttag(self, tag, attrs):
        if tag == 'title' and not self.title:
            self._intitle = True

    def handle_endtag(self, tag):
        if tag == 'title':
            if self._title:
                self.title = re.sub('\s+', ' ', self._title.strip())
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


class ChunkedParserFeeder:

    def __init__(self, f):
        self._f = f
        self._content = b''

    def feeduntil(self, parser, getdata, encoding):
        parser.feed(self._content.decode(encoding, errors='replace'))
        data = getdata()

        while not data and len(self._content) <= 1024**2:
            chunk = self._f.read(1024)
            if not chunk:
                return None
            parser.feed(chunk.decode(encoding, errors='replace'))
            data = getdata()
            self._content += chunk

        return data


def sendtitle(c, m):
    for match in re.finditer('https?://\S+', m[2]):
        rh = FinalURLHTTPRedirectHandler()
        opener = urllib.request.build_opener(rh)
        opener.addheaders = [('User-Agent', 'torskbot')]
        try:
            f = opener.open(match.group(), timeout=5)
        except urllib.error.HTTPError as e:
            f = e.fp
        if rh.final_url:
            c.send('PRIVMSG', m[1], 'Vidarebefordring till: ' + rh.final_url)

        info = f.info()
        t = info.get_content_type()
        if t == 'text/html' or t == 'application/xhtml+xml':
            feeder = ChunkedParserFeeder(f)

            cs = info.get_content_charset()
            if not cs:
                ep = EncodingHTMLParser()
                cs = feeder.feeduntil(ep, lambda: ep.encoding, 'latin-1')

            tp = TitleHTMLParser()
            if feeder.feeduntil(tp, lambda: tp.title, cs if cs else 'latin-1'):
                c.send('PRIVMSG', m[1], 'Titel: ' + tp.title)


def printerror(s):
    print(': '.join((sys.argv[0], s)), file=sys.stderr)


def printusage():
    print('usage: {} [-p port] hostname channel'.format(sys.argv[0]),
          file=sys.stderr)


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'p:')
    except getopt.GetoptError as e:
        printerror(e)
        printusage()
        return 2
    if len(args) != 2:
        printerror('wrong number of arguments')
        printusage()
        return 2

    with IRCConnection((args[0], dict(opts).get('-p', 6667)), 'torskbot',
                       'Torsk') as c:
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
