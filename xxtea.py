#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import numpy as np


def b2i(b):
    length = (len(b) + 3) // 4
    b = b.ljust(length * 4, b'\x00')
    return struct.unpack('<' + str(length) + 'I', b)


def i2b(i):
    return struct.pack('<' + str(len(i)) + 'I', *i)


def encode(b, k):
    v = list(b2i(b))
    v.append(len(b))
    v = np.array(v, dtype=np.uint32)
    length = len(v)
    k = b2i(k)
    k = np.array(k, dtype=np.uint32)
    rounds = 6 + 52 // length

    magic = np.uint32(0x9e3779b9)
    for r in range(rounds):
        r_sum = magic * np.uint32(r + 1)
        r_key = r_sum >> 2 & 3
        for i in range(length):
            prv = v[(i - 1) % length]
            nex = v[(i + 1) % length]
            v[i] += ((prv >> 5 ^ nex << 2)
                     + (prv << 4 ^ nex ^ nex >> 3 ^ r_sum)
                     + (k[i % 4 ^ r_key] ^ prv))

    return i2b(v)


def decode(b, k):
    v = b2i(b)
    v = np.array(v, dtype=np.uint32)
    length = len(v)
    k = b2i(k)
    k = np.array(k, dtype=np.uint32)
    rounds = 6 + 52 // length

    magic = np.uint32(0x9e3779b9)
    for r in range(rounds - 1, -1, -1):
        r_sum = magic * np.uint32(r + 1)
        r_key = r_sum >> 2 & 3
        for i in range(length - 1, -1, -1):
            prv = v[(i - 1) % length]
            nex = v[(i + 1) % length]
            v[i] -= ((prv >> 5 ^ nex << 2)
                     + (prv << 4 ^ nex ^ nex >> 3 ^ r_sum)
                     + (k[i % 4 ^ r_key] ^ prv))

    b = i2b(v[:-1])
    assert not any(b[v[-1]:])
    return b[:v[-1]]
