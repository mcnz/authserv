#! /usr/bin/env python
# encoding: utf-8

import logging
import socket
from sys import exc_info
from select import select
from argparse import ArgumentParser
from traceback import format_exception

from logger import setupLogging
from keymanager import KeyManager

C_BIND_IP   = ''
C_BIND_PORT = 25565

S_BLOCK_TIME    = 1.0
S_RECV_SIZE     = 1024

def loadConfiguration():
    parser = ArgumentParser()
    parser.add_argument(
        '-ip',
        type=str,
        help='address to bind to',
        default=C_BIND_IP
    )
    parser.add_argument(
        '-port',
        type=int,
        help='port to bind to',
        default=C_BIND_PORT
    )
    parser.add_argument(
        '-key',
        type=str,
        help='keypair to use during authentication'
    )
    parser.add_argument(
        '--verbose',
        help='print more information',
        action='store_true'
    )
    return parser.parse_args()

class EndOfStreamException(Exception):
    """
    The remote host closed the socket.
    """
    pass

class ClientContext():

    def __init__(self, k, s, d):
        self.key = k
        self.sock = s
        self.details = d

        self.logger = logging.getLogger(d[0])
        self.buff = bytearray()

        self.logger.info('Client connected')

    def onData(self):
        data = self.sock.recv(S_RECV_SIZE)
        if data:
            self.buff.extend(data)
            self.parseBuffer()
        else:
            raise EndOfStreamException('No more data')

    def dispose(self):
        self.disconnect()

    def parseBuffer(self):
        print 'reading a bit'

    def disconnect(self):
        try:
            self.sock.shutdown(socket.SHUT_RD)
            self.sock.close()
        except socket.error:
            pass
        self.logger.info('Disconnected')

class AuthServer():

    def __init__(self, c, k):
        self.conf = c
        self.key = k
        self.logger = logging.getLogger('authserver')

    def idle(self):
        pass

    def selectReadable(self):
        keys = self.sockets.keys
        empt = []
        idle = self.idle
        while self.alive:
            a = select(keys(), empt, empt, S_BLOCK_TIME)[0]
            if a:
                for s in a:
                    yield s
            else:
                idle()
    
    def run(self):
        binding = (self.conf.ip, int(self.conf.port))
        # create TCP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(binding)
        self.sock.listen(5)

        self.sockets = { self.sock: None }

        # shortcuts
        listensock = self.sock
        socketdict = self.sockets
        nextsocket = self.selectReadable()
        ignore_exc = (None, socket.error, EndOfStreamException)

        self.alive = True

        for sock in nextsocket:

            # got a connect()
            if sock is listensock:
                # intialise
                context = ClientContext(self.key, *sock.accept())
                # store
                socketdict[context.sock] = context

            else:
                try:
                    socketdict[sock].onData()
                except:
                    exception = exc_info()
                    if exception[0] not in ignore_exc:
                        self.logger.warning('An exception occurred while processing a client!')
                        self.logger.warning(''.join(format_exception(*exception)))
                    self.removeClient(sock)


    def checkTimeouts(self):
        t = time()
        for sock in self.sockets.keys():
            context = self.sockets[sock]
            if context and context.isTimedOut(t):
                self.removeClient(sock)

    def removeClient(self, sock):
        context = self.sockets[sock]
        del self.sockets[sock]
        context.dispose()

    def disconnect(self):
        for sock in self.sockets.keys():
            if sock is self.sock:
                try:
                    sock.shutdown(socket.SHUT_RD)
                    sock.close()
                except socket.error:
                    pass
            else:
                self.sockets[sock].dispose()

    def dispose(self):
        self.alive = False
        self.disconnect()


if __name__ == '__main__':

    conf = loadConfiguration()
    setupLogging(logging.DEBUG if conf.verbose else logging.INFO)

    logging.info('Loaded configuration')

    key = KeyManager(conf.key)

    logging.info('Loaded RSA key')

    s = AuthServer(conf, key)
    try:
        logging.info('Starting server...')
        s.run()
    except KeyboardInterrupt:
        logging.debug('Caught ^C')
        s.dispose()