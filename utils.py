# encoding: utf-8
'''
Modified from https://gist.github.com/barneygale/1209061
'''

from random import choice
from struct import pack, unpack
from string import letters, digits

from Crypto.Hash import SHA

def pack_short(h):
    return pack('>H', h)

def unpack_short(h):
    return unpack('>H', h)[0]

def unpack_varint(s):
    d = 0
    for i in range(5):
        b = s[i]
        d |= (b & 0x7F) << 7*i
        if not b & 0x80:
            break
    return d, i+1

def unpack_varint_fromstring(s):
    d = 0
    for i in range(5):
        b = ord(s[i])
        d |= (b & 0x7F) << 7*i
        if not b & 0x80:
            break
    return d, i+1

def pack_varint(d):
    o = ""
    while True:
        b = d & 0x7F
        d >>= 7
        o += chr(b | (0x80 if d > 0 else 0))
        if d == 0:
            break
    return o

def pack_data(d):
    return pack_varint(len(d)) + d

def pseudorandom_string(l):
    s = ''
    selection = letters + '_' + digits
    while l:
        s += choice(selection)
        l -= 1
    return s

def login_hash(server_id, shared_secret, public_key):
    """
    Returns the server id which is then used for joining a server.
    https://github.com/sadimusi/mc4p/blob/master/mc4p/authentication.py
    """
    sha = SHA.new()
    sha.update(server_id)
    sha.update(shared_secret)
    sha.update(public_key)
    d = long(sha.hexdigest(), 16)
    if d >> 39 * 4 & 0x8:
        return "-%x" % ((-d) & (2 ** (40 * 4) - 1))
    return "%x" % d
