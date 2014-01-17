#! /usr/bin/env python
# encoding: utf-8

import logging
from argparse import ArgumentParser

from logger import setupLogging
from keymanager import KeyManager

C_BIND_IP   = ''
C_BIND_PORT = 25565

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

if __name__ == '__main__':

    conf = loadConfiguration()
    setupLogging(logging.DEBUG if conf.verbose else logging.INFO)

    logging.info('Loaded configuration')

    key = KeyManager(conf.key)