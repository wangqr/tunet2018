#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import base64

b64std = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
# b64mod is retrieved from https://auth.tsinghua.edu.cn/js/hashes.min.js
b64mod = b'LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA'


def encode(b):
    return base64.standard_b64encode(b).translate(
        bytes.maketrans(b64std, b64mod))


def decode(s):
    return base64.standard_b64decode(
        s.translate(bytes.maketrans(b64mod, b64std)))
