# encoding: utf-8
'''
Modified from https://gist.github.com/barneygale/1209061
'''

from struct import unpack

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