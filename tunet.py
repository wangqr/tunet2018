#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import collections
import hashlib
import hmac
import json
import requests
import sys
import time
import urllib

import b64mod
import xxtea

session = requests.Session()
BASE_URL = 'https://auth.tsinghua.edu.cn'


def get_challenge(username, ip='', double_stack=1, off_campus=True,
                  tm=time.time()):
    params = collections.OrderedDict([
        ('callback', '_'),
        ('username', username if off_campus else (username + '@tsinghua')),
        ('ip', ip),
        ('double_stack', double_stack),
        ('_', int(tm * 1000))
    ])
    r = session.get(BASE_URL + '/cgi-bin/get_challenge', params=params).text
    r = json.loads(r[2:-1])
    try:
        assert r['error'] == 'ok'
    except AssertionError:
        print(r)
        raise
    return r


def login(username, password, challenge, ip='', double_stack=1, ac_id=1,
          off_campus=True, tm=time.time()):
    challenge = challenge.encode()

    info = collections.OrderedDict([
        ('username', username if off_campus else (username + '@tsinghua')),
        ('password', password),
        ('ip', ip),
        ('acid', str(ac_id)),
        ("enc_ver", "srun_bx1")
    ])
    info_hash = b64mod.encode(xxtea.encode(
        json.dumps(info, separators=(',', ':')).encode(), challenge))

    checksum = hashlib.sha1(
        challenge +
        username.encode() + challenge +
        hmac.new(challenge).hexdigest().encode() + challenge +
        str(ac_id).encode() + challenge +
        ip.encode() + challenge +
        b'200' + challenge + b'1' + challenge +
        b'{SRBX1}' + info_hash
    ).hexdigest()

    params = collections.OrderedDict([
        ('callback', '_'),
        ('action', 'login'),
        ('username', username if off_campus else (username + '@tsinghua')),
        ('org_password', password),
        ('password', '{MD5}' + hmac.new(challenge).hexdigest()),
        ('ac_id', 1),
        ('ip', ip),
        ('double_stack', double_stack),
        ('info', b'{SRBX1}' + info_hash),
        ('chksum', checksum),
        ('n', 200),
        ('type', 1),
        ('_', int(tm * 1000))
    ])

    r = session.get(BASE_URL + '/cgi-bin/srun_portal',
                    params=params).text
    r = json.loads(r[2:-1])
    try:
        assert r['error'] == 'ok'
    except AssertionError:
        print(r)
        raise
    return r


def logout(username, challenge, ip='', double_stack=1, ac_id=1,
           off_campus=True, tm=time.time()):
    challenge = challenge.encode()

    info = collections.OrderedDict([
        ('username', username if off_campus else (username + '@tsinghua')),
        # ('password', password),
        ('ip', ip),
        ('acid', str(ac_id)),
        ("enc_ver", "srun_bx1")
    ])
    info_hash = b64mod.encode(xxtea.encode(
        json.dumps(info, separators=(',', ':')).encode(), challenge))

    checksum = hashlib.sha1(
        challenge +
        username.encode() + challenge +
        # hmac.new(challenge).hexdigest().encode() + challenge +
        str(ac_id).encode() + challenge +
        ip.encode() + challenge +
        b'200' + challenge + b'1' + challenge +
        b'{SRBX1}' + info_hash
    ).hexdigest()

    params = collections.OrderedDict([
        ('callback', '_'),
        ('action', 'logout'),
        ('username', username if off_campus else (username + '@tsinghua')),
        # ('org_password', password),
        # ('password', '{MD5}' + hmac.new(challenge).hexdigest()),
        ('ac_id', 1),
        ('ip', ip),
        ('double_stack', double_stack),
        ('info', b'{SRBX1}' + info_hash),
        ('chksum', checksum),
        ('n', 200),
        ('type', 1),
        ('_', int(tm * 1000))
    ])

    r = session.get(BASE_URL + '/cgi-bin/srun_portal',
                    params=params).text
    r = json.loads(r[2:-1])
    try:
        assert r['error'] == 'ok'
    except AssertionError:
        print(r)
        raise
    return r


def status():
    r = session.head(BASE_URL + '/srun_portal_pc.php')
    if r.next is None:
        return None
    else:
        return urllib.parse.parse_qsl(urllib.parse.urlparse(r.next.url).query)


def usage():
    print('SRUN Client [Protocol: TUNet 2018 web]\n'
          'Author: wangqr <i@wangqr.tk>'
          '\n'
          'usage:\n'
          '  tunet login <username> <password>\n'
          '  tunet logout [<username>]\n'
          '  tunet status\n'
          '\n'
          'options:\n'
          '  -4, -6  Force IPv4/IPv6')
    exit()


def main():
    global BASE_URL
    if '-4' in sys.argv:
        BASE_URL = 'https://auth4.tsinghua.edu.cn'
        sys.argv.remove('-4')
    elif '-6' in sys.argv:
        BASE_URL = 'https://auth6.tsinghua.edu.cn'
        sys.argv.remove('-6')
    if len(sys.argv) < 2:
        usage()
    elif sys.argv[1] == 'login' and len(sys.argv) >= 4:
        usr = sys.argv[2]
        pwd = sys.argv[3]
        r = get_challenge(usr)
        r = login(usr, pwd, r['challenge'])
        print(r)
    elif sys.argv[1] == 'logout':
        r = status()
        if r is None:
            print('Not online')
            return
        print(r)
        for x, y in r:
            if x == 'username':
                usr = y
                break
        r = get_challenge(usr)
        r = logout(usr, r['challenge'])
        print(r)
        pass
    elif sys.argv[1] == 'status':
        r = status()
        if r is None:
            print('Not online')
        else:
            print(r)
        pass
    else:
        usage()


if __name__ == '__main__':
    main()
