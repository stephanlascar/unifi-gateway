# -*- coding: utf-8 -*-
import json
import urllib2
import sys
import uuid

from struct import pack, unpack

import zlib

import os

import time

import binascii

import psutil
from Crypto import Random
from Crypto.Cipher import AES
from binascii import a2b_hex

from random import randint

from uptime import uptime


def packet_encode(key, json):
    iv = Random.new().read(16)

    # zlib compression
    payload = zlib.compress(json)
    # padding - http://stackoverflow.com/a/14205319
    pad_len = AES.block_size - (len(payload) % AES.block_size)
    payload += chr(pad_len) * pad_len
    # encryption
    payload = AES.new(key, AES.MODE_CBC, iv).encrypt(payload)

    # encode packet
    data = 'TNBU'                     # magic
    data += pack('>I', 1)             # packet version
    data += pack('BBBBBB', *(0x00, 0x0d, 0xb9, 0x47, 0x65, 0xf9))   # mac address
    data += pack('>H', 3)             # flags
    data += iv                        # encryption iv
    data += pack('>I', 1)             # payload version
    data += pack('>I', len(payload))  # payload length
    data += payload

    return data


def inform(url, key, json):
    headers = {
        'Content-Type': 'application/x-binary',
        'User-Agent': 'AirControl Agent v1.0'
    }
    data = packet_encode(key, json)
    req = urllib2.Request(url, data, headers)
    print('send %s' % json)
    try:
        res = urllib2.urlopen(req)
        return packet_decode(key, res.read())
    except Exception as a:
        print a


def mac2a(mac):
    return ':'.join(map(lambda i: '%02x' %i, mac))


def mac2serial(mac):
    return ''.join(map(lambda i: '%02x'%i, mac))


def ip2a(ip):
    return '.'.join(map(str, ip))


def packet_decode(key, data, iv=None):
    magic = data[0:4]
    if magic != 'TNBU':
        raise Exception("Missing magic in response: '%s' instead of 'TNBU'" %(magic))
    mac = unpack('BBBBBB', data[8:14])
    # if mac != (0x00, 0x0d, 0xb9, 0x47, 0x65, 0xf9):
    #     raise Exception('Mac address changed in response: %s -> %s'%(mac2a((0x00, 0x0d, 0xb9, 0x47, 0x65, 0xf9)), mac2a(mac)))

    flags = unpack('>H', data[14:16])[0]
    iv = data[16:32] if not iv else iv
    version = unpack('>I', data[32:36])[0]
    payload_len = unpack('>I', data[36:40])[0]
    payload = data[40:(40+payload_len)]

    print(binascii.hexlify(iv))

    # decrypt if required
    if flags & 0x01:
        payload = AES.new(key, AES.MODE_CBC, iv).decrypt(payload)
        # unpad - https://gist.github.com/marcoslin/8026990#file-server-py-L43
        pad_size = ord(payload[-1])
        if pad_size > AES.block_size:
            raise Exception('Response not padded or padding is corrupt')
        payload = payload[:(len(payload) - pad_size)]
    # uncompress if required
    if flags & 0x02:
        payload = zlib.decompress(payload)

    return payload


def cfg_replace(fn, contents):
    '''replace configuration file'''
    fp = os.path.join('/tmp/cfg', fn)
    try:
        os.mkdir('/tmp/cfg')
    except OSError:
        pass
    with open(fp, 'w') as f:
        f.write(contents)


def cfg(fn, key):
    '''read key from configuration file'''
    fp = os.path.join('/tmp/cfg', fn)
    try:
        with open(fp) as f:
            for line in f:
                if line.startswith(key + '='):
                    return line.split('=', 1)[1].rstrip()
    except IOError:
        pass

def create_complete_inform():
    load_average = open('/proc/loadavg').readline().split(' ')
    gateway_wan_ip = ip2a((82, 238, 9, 250))
    gateway_wan_mac = mac2a((0x80, 0x2a, 0xa8, 0xcd, 0xa9, 0x52))
    gateway_lan_ip = ip2a((10, 0, 8, 2))
    gateway_lan_mac = mac2a((0x00, 0x0d, 0xb9, 0x47, 0x65, 0xf9))

    return json.dumps({
        "bootrom_version": "unknown",
        "cfgversion": cfg('_cfg', 'cfgversion'),
        "config_network_wan": {
            "type": "dhcp",
        },
        "config_port_table": [
            {
                "ifname": "eth0",
                "name": "wan"
            },
            {
                "ifname": "eth1",
                "name": "lan"
            },
            {
                "ifname": "eth2",
                "name": "lan"
            }
        ],
        "connect_request_ip": gateway_lan_ip,
        "connect_request_port": "36424",
        "default": False,
        "discovery_response": False,
        "fw_caps": 3,
        "guest_token": "4C1D46707239C6EB5A2366F505A44A91",
        "has_default_route_distance": True,
        "has_dnsmasq_hostfile_update": False,
        "has_dpi": True,
        "dpi-clients": [
            "80:2a:a8:f0:ef:78"
        ],
        "dpi-stats": [
            {
                "initialized": "94107792805",
                "mac": "80:2a:a8:f0:ef:78",
                "stats": [
                    {
                        "app": 5,
                        "cat": 3,
                        "rx_bytes": 82297468,
                        "rx_packets": 57565,
                        "tx_bytes": 1710174,
                        "tx_packets": 25324
                    },
                    {
                        "app": 94,
                        "cat": 19,
                        "rx_bytes": 1593846895,
                        "rx_packets": 1738901,
                        "tx_bytes": 348738675,
                        "tx_packets": 2004045
                    },
                    {
                        "app": 133,
                        "cat": 3,
                        "rx_bytes": 531190,
                        "rx_packets": 2465,
                        "tx_bytes": 676859,
                        "tx_packets": 2760
                    },
                    {
                        "app": 222,
                        "cat": 13,
                        "rx_bytes": 3441437,
                        "rx_packets": 3033,
                        "tx_bytes": 203173,
                        "tx_packets": 1468
                    },
                    {
                        "app": 23,
                        "cat": 0,
                        "rx_bytes": 0,
                        "rx_packets": 0,
                        "tx_bytes": 145,
                        "tx_packets": 2
                    },
                    {
                        "app": 7,
                        "cat": 0,
                        "rx_bytes": 0,
                        "rx_packets": 0,
                        "tx_bytes": 145,
                        "tx_packets": 2
                    },
                    {
                        "app": 7,
                        "cat": 13,
                        "rx_bytes": 24417806554,
                        "rx_packets": 18415873,
                        "tx_bytes": 2817966897,
                        "tx_packets": 9910192
                    },
                    {
                        "app": 185,
                        "cat": 20,
                        "rx_bytes": 28812050,
                        "rx_packets": 208945,
                        "tx_bytes": 160819147,
                        "tx_packets": 1228992
                    },
                    {
                        "app": 65535,
                        "cat": 255,
                        "rx_bytes": 182029551,
                        "rx_packets": 1796815,
                        "tx_bytes": 435732626,
                        "tx_packets": 1933469
                    },
                    {
                        "app": 4,
                        "cat": 10,
                        "rx_bytes": 1522,
                        "rx_packets": 20,
                        "tx_bytes": 882,
                        "tx_packets": 12
                    },
                    {
                        "app": 106,
                        "cat": 18,
                        "rx_bytes": 982710,
                        "rx_packets": 10919,
                        "tx_bytes": 1010970,
                        "tx_packets": 11233
                    },
                    {
                        "app": 30,
                        "cat": 18,
                        "rx_bytes": 7819852,
                        "rx_packets": 20378,
                        "tx_bytes": 1293104,
                        "tx_packets": 18686
                    },
                    {
                        "app": 1,
                        "cat": 0,
                        "rx_bytes": 0,
                        "rx_packets": 0,
                        "tx_bytes": 145,
                        "tx_packets": 2
                    },
                    {
                        "app": 63,
                        "cat": 18,
                        "rx_bytes": 780358,
                        "rx_packets": 3520,
                        "tx_bytes": 545757,
                        "tx_packets": 6545
                    },
                    {
                        "app": 8,
                        "cat": 13,
                        "rx_bytes": 180691586,
                        "rx_packets": 132204,
                        "tx_bytes": 5970383,
                        "tx_packets": 74482
                    },
                    {
                        "app": 21,
                        "cat": 10,
                        "rx_bytes": 5521547718,
                        "rx_packets": 73080390,
                        "tx_bytes": 179999309100,
                        "tx_packets": 130627577
                    }
                ]
            }
        ],
        "dpi-stats-table": [
            {
                "_id": "5875d9f9e4b02fd3851c55e4",
                "_subid": "5875d9f5e4b02fd3851c55d8",
                "by_app": [
                    {
                        "app": 5,
                        "cat": 3,
                        "rx_bytes": 2652,
                        "rx_packets": 4,
                        "tx_bytes": 1797,
                        "tx_packets": 7
                    },
                    {
                        "app": 94,
                        "cat": 19,
                        "rx_bytes": 9010458,
                        "rx_packets": 6977,
                        "tx_bytes": 518163,
                        "tx_packets": 3533
                    },
                    {
                        "app": 209,
                        "cat": 13,
                        "rx_bytes": 39303,
                        "rx_packets": 90,
                        "tx_bytes": 17744,
                        "tx_packets": 78
                    },
                    {
                        "app": 10,
                        "cat": 4,
                        "rx_bytes": 15273,
                        "rx_packets": 15,
                        "tx_bytes": 2728,
                        "tx_packets": 23
                    },
                    {
                        "app": 7,
                        "cat": 13,
                        "rx_bytes": 369394,
                        "rx_packets": 293,
                        "tx_bytes": 24904,
                        "tx_packets": 244
                    },
                    {
                        "app": 185,
                        "cat": 20,
                        "rx_bytes": 62070,
                        "rx_packets": 130,
                        "tx_bytes": 27219,
                        "tx_packets": 169
                    },
                    {
                        "app": 65535,
                        "cat": 255,
                        "rx_bytes": 976848,
                        "rx_packets": 1027,
                        "tx_bytes": 77317,
                        "tx_packets": 695
                    },
                    {
                        "app": 12,
                        "cat": 13,
                        "rx_bytes": 92924774,
                        "rx_packets": 70496,
                        "tx_bytes": 17360339,
                        "tx_packets": 69509
                    },
                    {
                        "app": 150,
                        "cat": 3,
                        "rx_bytes": 54609,
                        "rx_packets": 71,
                        "tx_bytes": 19749,
                        "tx_packets": 85
                    },
                    {
                        "app": 95,
                        "cat": 5,
                        "rx_bytes": 9835,
                        "rx_packets": 41,
                        "tx_bytes": 3956,
                        "tx_packets": 41
                    },
                    {
                        "app": 168,
                        "cat": 20,
                        "rx_bytes": 100049,
                        "rx_packets": 198,
                        "tx_bytes": 60396,
                        "tx_packets": 275
                    },
                    {
                        "app": 3,
                        "cat": 10,
                        "rx_bytes": 12538,
                        "rx_packets": 36,
                        "tx_bytes": 10607,
                        "tx_packets": 75
                    },
                    {
                        "app": 84,
                        "cat": 3,
                        "rx_bytes": 45115,
                        "rx_packets": 135,
                        "tx_bytes": 91866,
                        "tx_packets": 158
                    },
                    {
                        "app": 84,
                        "cat": 13,
                        "rx_bytes": 42563,
                        "rx_packets": 102,
                        "tx_bytes": 32676,
                        "tx_packets": 113
                    },
                    {
                        "app": 186,
                        "cat": 20,
                        "rx_bytes": 44618,
                        "rx_packets": 68,
                        "tx_bytes": 8826,
                        "tx_packets": 86
                    }
                ],
                "by_cat": [
                    {
                        "apps": [
                            5,
                            150,
                            84
                        ],
                        "cat": 3,
                        "rx_bytes": 102376,
                        "rx_packets": 210,
                        "tx_bytes": 113412,
                        "tx_packets": 250
                    },
                    {
                        "apps": [
                            10
                        ],
                        "cat": 4,
                        "rx_bytes": 15273,
                        "rx_packets": 15,
                        "tx_bytes": 2728,
                        "tx_packets": 23
                    },
                    {
                        "apps": [
                            95
                        ],
                        "cat": 5,
                        "rx_bytes": 9835,
                        "rx_packets": 41,
                        "tx_bytes": 3956,
                        "tx_packets": 41
                    },
                    {
                        "apps": [
                            3
                        ],
                        "cat": 10,
                        "rx_bytes": 12538,
                        "rx_packets": 36,
                        "tx_bytes": 10607,
                        "tx_packets": 75
                    },
                    {
                        "apps": [
                            209,
                            7,
                            12,
                            84
                        ],
                        "cat": 13,
                        "rx_bytes": 93376034,
                        "rx_packets": 70981,
                        "tx_bytes": 17435663,
                        "tx_packets": 69944
                    },
                    {
                        "apps": [
                            94
                        ],
                        "cat": 19,
                        "rx_bytes": 9010458,
                        "rx_packets": 6977,
                        "tx_bytes": 518163,
                        "tx_packets": 3533
                    },
                    {
                        "apps": [
                            185,
                            168,
                            186
                        ],
                        "cat": 20,
                        "rx_bytes": 206737,
                        "rx_packets": 396,
                        "tx_bytes": 96441,
                        "tx_packets": 530
                    },
                    {
                        "apps": [
                            65535
                        ],
                        "cat": 255,
                        "rx_bytes": 976848,
                        "rx_packets": 1027,
                        "tx_bytes": 77317,
                        "tx_packets": 695
                    }
                ],
                "initialized": "88122111307"
            },
            {
                "_id": "5875d9f9e4b02fd3851c55e4",
                "_subid": "5875e1f8e4b0ba28be0f8335",
                "by_app": [
                    {
                        "app": 5,
                        "cat": 3,
                        "clients": [
                            {
                                "mac": "80:2a:a8:f0:ef:78",
                                "rx_bytes": 82297468,
                                "rx_packets": 57565,
                                "tx_bytes": 1710174,
                                "tx_packets": 25324
                            }
                        ],
                        "known_clients": 1,
                        "rx_bytes": 82300120,
                        "rx_packets": 57569,
                        "tx_bytes": 1711971,
                        "tx_packets": 25331
                    },
                    {
                        "app": 94,
                        "cat": 19,
                        "clients": [
                            {
                                "mac": "80:2a:a8:f0:ef:78",
                                "rx_bytes": 1593846895,
                                "rx_packets": 1738901,
                                "tx_bytes": 348738675,
                                "tx_packets": 2004045
                            }
                        ],
                        "known_clients": 1,
                        "rx_bytes": 1622602418,
                        "rx_packets": 1760201,
                        "tx_bytes": 349693010,
                        "tx_packets": 2012708
                    },
                    {
                        "app": 209,
                        "cat": 13,
                        "rx_bytes": 43670,
                        "rx_packets": 100,
                        "tx_bytes": 20728,
                        "tx_packets": 91
                    },
                    {
                        "app": 10,
                        "cat": 4,
                        "rx_bytes": 15273,
                        "rx_packets": 15,
                        "tx_bytes": 2728,
                        "tx_packets": 23
                    },
                    {
                        "app": 133,
                        "cat": 3,
                        "clients": [
                            {
                                "mac": "80:2a:a8:f0:ef:78",
                                "rx_bytes": 531190,
                                "rx_packets": 2465,
                                "tx_bytes": 676859,
                                "tx_packets": 2760
                            }
                        ],
                        "known_clients": 1,
                        "rx_bytes": 531190,
                        "rx_packets": 2465,
                        "tx_bytes": 676859,
                        "tx_packets": 2760
                    },
                    {
                        "app": 222,
                        "cat": 13,
                        "clients": [
                            {
                                "mac": "80:2a:a8:f0:ef:78",
                                "rx_bytes": 3441437,
                                "rx_packets": 3033,
                                "tx_bytes": 203173,
                                "tx_packets": 1468
                            }
                        ],
                        "known_clients": 1,
                        "rx_bytes": 3441437,
                        "rx_packets": 3033,
                        "tx_bytes": 203173,
                        "tx_packets": 1468
                    },
                    {
                        "app": 23,
                        "cat": 0,
                        "clients": [
                            {
                                "mac": "80:2a:a8:f0:ef:78",
                                "rx_bytes": 0,
                                "rx_packets": 0,
                                "tx_bytes": 145,
                                "tx_packets": 2
                            }
                        ],
                        "known_clients": 1,
                        "rx_bytes": 0,
                        "rx_packets": 0,
                        "tx_bytes": 145,
                        "tx_packets": 2
                    },
                    {
                        "app": 7,
                        "cat": 0,
                        "clients": [
                            {
                                "mac": "80:2a:a8:f0:ef:78",
                                "rx_bytes": 0,
                                "rx_packets": 0,
                                "tx_bytes": 145,
                                "tx_packets": 2
                            }
                        ],
                        "known_clients": 1,
                        "rx_bytes": 0,
                        "rx_packets": 0,
                        "tx_bytes": 145,
                        "tx_packets": 2
                    },
                    {
                        "app": 7,
                        "cat": 13,
                        "clients": [
                            {
                                "mac": "80:2a:a8:f0:ef:78",
                                "rx_bytes": 24417806554,
                                "rx_packets": 18415873,
                                "tx_bytes": 2817966897,
                                "tx_packets": 9910192
                            }
                        ],
                        "known_clients": 1,
                        "rx_bytes": 24418175948,
                        "rx_packets": 18416166,
                        "tx_bytes": 2817991801,
                        "tx_packets": 9910436
                    },
                    {
                        "app": 185,
                        "cat": 20,
                        "clients": [
                            {
                                "mac": "80:2a:a8:f0:ef:78",
                                "rx_bytes": 28812050,
                                "rx_packets": 208945,
                                "tx_bytes": 160819147,
                                "tx_packets": 1228992
                            }
                        ],
                        "known_clients": 1,
                        "rx_bytes": 28874120,
                        "rx_packets": 209075,
                        "tx_bytes": 160846366,
                        "tx_packets": 1229161
                    },
                    {
                        "app": 65535,
                        "cat": 255,
                        "clients": [
                            {
                                "mac": "80:2a:a8:f0:ef:78",
                                "rx_bytes": 182029551,
                                "rx_packets": 1796815,
                                "tx_bytes": 435732626,
                                "tx_packets": 1933469
                            }
                        ],
                        "known_clients": 1,
                        "rx_bytes": 183022079,
                        "rx_packets": 1798016,
                        "tx_bytes": 435832672,
                        "tx_packets": 1934359
                    },
                    {
                        "app": 12,
                        "cat": 13,
                        "rx_bytes": 92925290,
                        "rx_packets": 70498,
                        "tx_bytes": 17360839,
                        "tx_packets": 69512
                    },
                    {
                        "app": 4,
                        "cat": 10,
                        "clients": [
                            {
                                "mac": "80:2a:a8:f0:ef:78",
                                "rx_bytes": 1522,
                                "rx_packets": 20,
                                "tx_bytes": 882,
                                "tx_packets": 12
                            }
                        ],
                        "known_clients": 1,
                        "rx_bytes": 1522,
                        "rx_packets": 20,
                        "tx_bytes": 882,
                        "tx_packets": 12
                    },
                    {
                        "app": 106,
                        "cat": 18,
                        "clients": [
                            {
                                "mac": "80:2a:a8:f0:ef:78",
                                "rx_bytes": 982710,
                                "rx_packets": 10919,
                                "tx_bytes": 1010970,
                                "tx_packets": 11233
                            }
                        ],
                        "known_clients": 1,
                        "rx_bytes": 982710,
                        "rx_packets": 10919,
                        "tx_bytes": 1010970,
                        "tx_packets": 11233
                    },
                    {
                        "app": 30,
                        "cat": 18,
                        "clients": [
                            {
                                "mac": "80:2a:a8:f0:ef:78",
                                "rx_bytes": 7819852,
                                "rx_packets": 20378,
                                "tx_bytes": 1293104,
                                "tx_packets": 18686
                            }
                        ],
                        "known_clients": 1,
                        "rx_bytes": 7819852,
                        "rx_packets": 20378,
                        "tx_bytes": 1293104,
                        "tx_packets": 18686
                    },
                    {
                        "app": 1,
                        "cat": 0,
                        "clients": [
                            {
                                "mac": "80:2a:a8:f0:ef:78",
                                "rx_bytes": 0,
                                "rx_packets": 0,
                                "tx_bytes": 145,
                                "tx_packets": 2
                            }
                        ],
                        "known_clients": 1,
                        "rx_bytes": 0,
                        "rx_packets": 0,
                        "tx_bytes": 145,
                        "tx_packets": 2
                    },
                    {
                        "app": 150,
                        "cat": 3,
                        "rx_bytes": 54609,
                        "rx_packets": 71,
                        "tx_bytes": 19749,
                        "tx_packets": 85
                    },
                    {
                        "app": 95,
                        "cat": 5,
                        "rx_bytes": 9835,
                        "rx_packets": 41,
                        "tx_bytes": 3956,
                        "tx_packets": 41
                    },
                    {
                        "app": 168,
                        "cat": 20,
                        "rx_bytes": 100583,
                        "rx_packets": 204,
                        "tx_bytes": 62503,
                        "tx_packets": 296
                    },
                    {
                        "app": 3,
                        "cat": 10,
                        "rx_bytes": 12916,
                        "rx_packets": 41,
                        "tx_bytes": 11501,
                        "tx_packets": 86
                    },
                    {
                        "app": 84,
                        "cat": 13,
                        "rx_bytes": 42563,
                        "rx_packets": 102,
                        "tx_bytes": 32676,
                        "tx_packets": 113
                    },
                    {
                        "app": 84,
                        "cat": 3,
                        "rx_bytes": 62456,
                        "rx_packets": 166,
                        "tx_bytes": 101105,
                        "tx_packets": 183
                    },
                    {
                        "app": 63,
                        "cat": 18,
                        "clients": [
                            {
                                "mac": "80:2a:a8:f0:ef:78",
                                "rx_bytes": 780358,
                                "rx_packets": 3520,
                                "tx_bytes": 545757,
                                "tx_packets": 6545
                            }
                        ],
                        "known_clients": 1,
                        "rx_bytes": 780358,
                        "rx_packets": 3520,
                        "tx_bytes": 545757,
                        "tx_packets": 6545
                    },
                    {
                        "app": 8,
                        "cat": 13,
                        "clients": [
                            {
                                "mac": "80:2a:a8:f0:ef:78",
                                "rx_bytes": 180691586,
                                "rx_packets": 132204,
                                "tx_bytes": 5970383,
                                "tx_packets": 74482
                            }
                        ],
                        "known_clients": 1,
                        "rx_bytes": 180691586,
                        "rx_packets": 132204,
                        "tx_bytes": 5970383,
                        "tx_packets": 74482
                    },
                    {
                        "app": 186,
                        "cat": 20,
                        "rx_bytes": 44618,
                        "rx_packets": 68,
                        "tx_bytes": 8826,
                        "tx_packets": 86
                    },
                    {
                        "app": 21,
                        "cat": 10,
                        "clients": [
                            {
                                "mac": "80:2a:a8:f0:ef:78",
                                "rx_bytes": 5521547718,
                                "rx_packets": 73080390,
                                "tx_bytes": 179999309100,
                                "tx_packets": 130627577
                            }
                        ],
                        "known_clients": 1,
                        "rx_bytes": 5521547718,
                        "rx_packets": 73080390,
                        "tx_bytes": 179999309100,
                        "tx_packets": 130627577
                    }
                ],
                "by_cat": [
                    {
                        "apps": [
                            23,
                            7,
                            1
                        ],
                        "cat": 0,
                        "rx_bytes": 0,
                        "rx_packets": 0,
                        "tx_bytes": 435,
                        "tx_packets": 6
                    },
                    {
                        "apps": [
                            5,
                            133,
                            150,
                            84
                        ],
                        "cat": 3,
                        "rx_bytes": 82948375,
                        "rx_packets": 60271,
                        "tx_bytes": 2509684,
                        "tx_packets": 28359
                    },
                    {
                        "apps": [
                            10
                        ],
                        "cat": 4,
                        "rx_bytes": 15273,
                        "rx_packets": 15,
                        "tx_bytes": 2728,
                        "tx_packets": 23
                    },
                    {
                        "apps": [
                            95
                        ],
                        "cat": 5,
                        "rx_bytes": 9835,
                        "rx_packets": 41,
                        "tx_bytes": 3956,
                        "tx_packets": 41
                    },
                    {
                        "apps": [
                            4,
                            3,
                            21
                        ],
                        "cat": 10,
                        "rx_bytes": 5521562156,
                        "rx_packets": 73080451,
                        "tx_bytes": 179999321483,
                        "tx_packets": 130627675
                    },
                    {
                        "apps": [
                            209,
                            222,
                            7,
                            12,
                            84,
                            8
                        ],
                        "cat": 13,
                        "rx_bytes": 24695320494,
                        "rx_packets": 18622103,
                        "tx_bytes": 2841579600,
                        "tx_packets": 10056102
                    },
                    {
                        "apps": [
                            106,
                            30,
                            63
                        ],
                        "cat": 18,
                        "rx_bytes": 9582920,
                        "rx_packets": 34817,
                        "tx_bytes": 2849831,
                        "tx_packets": 36464
                    },
                    {
                        "apps": [
                            94
                        ],
                        "cat": 19,
                        "rx_bytes": 1622602418,
                        "rx_packets": 1760201,
                        "tx_bytes": 349693010,
                        "tx_packets": 2012708
                    },
                    {
                        "apps": [
                            185,
                            168,
                            186
                        ],
                        "cat": 20,
                        "rx_bytes": 29019321,
                        "rx_packets": 209347,
                        "tx_bytes": 160917695,
                        "tx_packets": 1229543
                    },
                    {
                        "apps": [
                            65535
                        ],
                        "cat": 255,
                        "rx_bytes": 183022079,
                        "rx_packets": 1798016,
                        "tx_bytes": 435832672,
                        "tx_packets": 1934359
                    }
                ],
                "initialized": "88121276686",
                "is_ugw": True
            }
        ],
        "has_eth1": True,
        "has_porta": True,
        "has_ssh_disable": True,
        "has_vti": True,
        "hostname": "pfSense",
        "inform_url": "http://192.168.0.7:8080/inform",
        "ip": "82.238.9.250",
        "isolated": False,
        "locating": False,
        'mac': gateway_lan_mac,
        "model": "UGW3",
        "model_display": "UniFi-Gateway-3",
        "netmask": "255.255.248.0",
        "required_version": "4.0.0",
        "selfrun_beacon": True,
        'serial': gateway_lan_mac.replace(":", ""),
        "pfor-stats": [
            {
                "id": "596add99e4b0a76e35003e00",
                "rx_bytes": 41444574,
                "rx_packets": 305634,
                "tx_bytes": 88048319,
                "tx_packets": 364768
            }
        ],
        "speedtest-status": {
            "latency": 9,
            "rundate": int(time.time()),
            "runtime": 6,
            "status_download": 2,
            "status_ping": 2,
            "status_summary": 2,
            "status_upload": 2,
            "xput_download": 385.30819702148,
            "xput_upload": 68.445808410645
        },
        "state": 2,
        "system-stats": {
            "cpu": '%s' % psutil.cpu_percent(),
            "mem": '%s' % (100 - psutil.virtual_memory()[2]),
            "uptime":  '%s' % uptime()
        },
        "time": int(time.time()),
        "uplink": "eth0",
        "uptime": uptime(),
        "routes": [
            {
                "nh": [
                    {
                        "intf": "eth0",
                        "metric": "1/0",
                        "t": "S>*",
                        "via": "20.1.1.1"
                    }
                ],
                "pfx": "0.0.0.0/0"
            },
            {
                "nh": [
                    {
                        "intf": "eth2",
                        "metric": "220/0",
                        "t": "S  ",
                        "via": "10.1.1.1"
                    }
                ],
                "pfx": "0.0.0.0/0"
            },
            {
                "nh": [
                    {
                        "intf": "eth2",
                        "metric": "1/0",
                        "t": "S  "
                    }
                ],
                "pfx": "10.1.1.0/24"
            },
            {
                "nh": [
                    {
                        "intf": "eth2",
                        "t": "C>*"
                    }
                ],
                "pfx": "10.1.1.0/24"
            },
            {
                "nh": [
                    {
                        "intf": "lo",
                        "t": "C>*"
                    }
                ],
                "pfx": "127.0.0.0/8"
            },
            {
                "nh": [
                    {
                        "intf": "eth1",
                        "t": "C>*"
                    }
                ],
                "pfx": "192.168.1.0/24"
            },
            {
                "nh": [
                    {
                        "intf": "eth0",
                        "t": "C>*"
                    }
                ],
                "pfx": "20.1.1.0/21"
            }
        ],
        "network_table": [
            {
                "address": "192.168.1.1/24",
                "addresses": [
                    "%s/24" % gateway_lan_ip
                ],
                "autoneg": "true",
                "duplex": "full",
                "host_table": [
                    {
                        "age": 0,
                        "authorized": True,
                        "bc_bytes": 4814073447,
                        "bc_packets": 104642338,
                        "dev_cat": 1,
                        "dev_family": 4,
                        "dev_id": 239,
                        "dev_vendor": 47,
                        "ip": "192.168.1.8",
                        "mac": "80:2a:a8:f0:ef:78",
                        "mc_bytes": 4814073447,
                        "mc_packets": 104642338,
                        "os_class": 15,
                        "os_name": 19,
                        "rx_bytes": 802239963372,
                        "rx_packets": 805925675,
                        "tx_bytes": 35371476651,
                        "tx_packets": 104136843,
                        "uptime": 5822032
                    },
                    {
                        "age": 41,
                        "authorized": True,
                        "bc_bytes": 9202676,
                        "bc_packets": 200043,
                        "hostname": "switch",
                        "ip": "192.168.1.10",
                        "mac": "f0:9f:c2:09:2b:f2",
                        "mc_bytes": 21366640,
                        "mc_packets": 406211,
                        "rx_bytes": 30862046,
                        "rx_packets": 610310,
                        "tx_bytes": 13628015,
                        "tx_packets": 204110,
                        "uptime": 5821979
                    },
                    {
                        "age": 8,
                        "authorized": True,
                        "bc_bytes": 2000,
                        "bc_packets": 3000,
                        "mac": "f0:9f:c2:09:2b:f3",
                        "mc_bytes": 21232297,
                        "mc_packets": 206139,
                        "rx_bytes": 21232297,
                        "rx_packets": 206139,
                        "tx_bytes": 4000,
                        "tx_packets": 5000,
                        "uptime": 5822017
                    }
                ],
                "l1up": "true",
                "mac": "80:2a:a8:cd:a9:53",
                "mtu": "1500",
                "name": "eth1",
                "speed": "1000",
                "stats": {
                    "multicast": "412294",
                    "rx_bps": "342",
                    "rx_bytes": 52947224765,
                    "rx_dropped": 2800,
                    "rx_errors": 0,
                    "rx_multicast": 412314,
                    "rx_packets": 341232922,
                    "tx_bps": "250",
                    "tx_bytes": 792205417381,
                    "tx_dropped": 0,
                    "tx_errors": 0,
                    "tx_packets": 590930778
                },
                "up": "true"
            },
            {
                "address": "20.1.2.10/21",
                "addresses": [
                    "20.1.2.10/21"
                ],
                "autoneg": "true",
                "duplex": "full",
                "gateways": [
                    "20.1.1.1"
                ],
                "l1up": "true",
                "mac": gateway_wan_mac,
                "mtu": "1500",
                "name": "eth0",
                "nameservers": [
                    gateway_lan_ip,
                    "212.27.40.240",
                    "212.27.40.241"
                ],
                "speed": "1000",
                "stats": {
                    "multicast": "65627",
                    "rx_bps": "262",
                    "rx_bytes": 353519562926,
                    "rx_dropped": 19137,
                    "rx_errors": 0,
                    "rx_multicast": 65629,
                    "rx_packets": 645343103,
                    "tx_bps": "328",
                    "tx_bytes": 953646055362,
                    "tx_dropped": 0,
                    "tx_errors": 0,
                    "tx_packets": 863173990
                },
                "up": "true"
            }
        ],
        "if_table": [
            {
                "drops": 333,
                "enable": True,
                "full_duplex": True,
                "gateways": [
                    gateway_lan_ip
                ],
                "ip": gateway_wan_ip,
                "latency": randint(0, 200),
                "mac": gateway_wan_mac,
                "name": "eth0",
                "nameservers": [
                    gateway_lan_ip,
                    "212.27.40.240",
                    "212.27.40.241"
                ],
                "netmask": "255.255.255.0",
                "num_port": 1,
                "rx_bytes": 353519562926 + randint(0, 200000),
                "rx_dropped": 19137 + randint(0, 2000),
                "rx_errors": 0,
                "rx_multicast": 65629 + randint(0, 2000),
                "rx_packets": 645343103 + randint(0, 200000),
                "speed": 1000,
                "speedtest_lastrun": int(time.time()),
                "speedtest_ping": randint(0, 2000),
                "speedtest_status": "Idle",
                "tx_bytes": 953646055362 + randint(0, 200000),
                "tx_dropped": 0,
                "tx_errors": 0,
                "tx_packets": 863173990 + randint(0, 200000),
                "up": True,
                "uptime": uptime(),
                "xput_down": randint(0, 100),
                "xput_up": randint(0, 30)
            },
            {
                "enable": True,
                "full_duplex": True,
                "ip": gateway_lan_ip,
                "mac": "80:2a:a8:cd:a9:53",
                "name": "eth1",
                "netmask": "255.255.255.0",
                "num_port": 1,
                "rx_bytes": 807912794876,
                "rx_dropped": 2800,
                "rx_errors": 0,
                "rx_multicast": 412314,
                "rx_packets": 700376545,
                "speed": 1000,
                "tx_bytes": 58901673253,
                "tx_dropped": 0,
                "tx_errors": 0,
                "tx_packets": 347161831,
                "up": True
            },
            {
                "enable": False,
                "full_duplex": True,
                "up": False
            }
        ],
        'version': '4.3.49.5001150',
    })


def send_inform(url, key, partial=False):
    if not partial:
        # value = json.dumps({'mac': mac2a((0x00, 0x0d, 0xb9, 0x47, 0x65, 0xf9)), 'ip': ip2a((10, 0, 8, 2)), 'model': 'UGW3',
        #                     'model-display': 'UniFi-Gateway-3', 'inform_as_notif': 'true', 'default': 'false',
        #                     'hotsname': 'pfsense', 'isolated': 'false', 'locating': 'false', 'netmask': '255.255.255.0',
        #                     'version': '4.3.49.5001150', 'serial': mac2serial((0x00, 0x0d, 0xb9, 0x47, 0x65, 0xf9)),
        #                     'uptime': uptime(), 'time': int(time.time()), "has_fan": False, "has_speaker": False,
        #                     "discovery_response": False, "fw_caps": 3589, "general_temperature": 26,
        #                     "guest_token": "FDE5188F48A10D22E4BE82A6A128C50G", "default": False, "board_rev": 3,
        #                     'cfgversion': cfg('_cfg', 'cfgversion'), 'config_network_wan': {'type': 'dhcp'},
        #                     'required_version': '4.0.0', 'notif_reson': 'stun', 'notif_payload': '',
        #                     'inform_ip': '192.168.0.7', 'inform_url': 'http://192.168.0.7:8080/inform',
        #                     'license_state': 'registered', 'selfrun_beacon': True, 'overheating': False, 'state': 2,
        #                     'adopted': True, 'stp_priority': 32768, 'stream_token': '',
        #                     'ssh_session_table': [{'state': 'establish', 'uuid': '%s' % uuid.uuid1()}],
        #                     'sys_stats': {'loadavg_1': '%s' % load_average[0], 'loadavg_15': '%s' % load_average[1],
        #                                   'loadavg_5': '%s' % load_average[2], 'mem_buffer': 0,
        #                                   'mem_total': psutil.virtual_memory()[0], 'mem_used': psutil.virtual_memory()[1]},
        #                     'system-stats': {'cpu': '%s' % psutil.cpu_percent(),
        #                                      'mem': '%s' % (100 - psutil.virtual_memory()[2]), 'uptime': '%s' % uptime()},
        #                     'port_table': [{'port_idx': 1, 'media': 'GE', 'port_poe': False, 'poe_caps': 0},
        #                                    {'port_idx': 2, 'media': 'GE', 'port_poe': False, 'poe_caps': 0},
        #                                    {'port_idx': 3, 'media': 'GE', 'port_poe': False, 'poe_caps': 0}],
        #                     'firewall': open('/tmp/cfg/system').readline()})
        value = create_complete_inform()
    else:
        value = json.dumps({
            'mac': mac2a((0x00, 0x0d, 0xb9, 0x47, 0x65, 0xf9)),
            'ip': ip2a((10, 0, 8, 2)),
            'model': 'UGW3',
            'model-display': 'UniFi-Gateway-3',
            'version': '4.3.49.5001150'
        })

    response = inform(url, a2b_hex(key), value)

    if response:
        response = json.loads(response)
        print('receive %s' % response)
        if response['_type'] == 'setparam':
            othercfg = ''
            for key, val in response.items():
                if key.endswith('_cfg'):
                    cfg_replace(key[0:(len(key)-4)], val)
                elif key != '_type' and key != 'server_time_in_utc' and key != 'mgmt_cfg':
                    othercfg += key + '=' + val + '\n'
            cfg_replace('_cfg', othercfg)

        return int(response['interval']) if 'interval' in response else 5

    return 5
