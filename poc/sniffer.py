import socket

import time

import struct

from uptime import uptime

mac = [0x00, 0x0d, 0xb9, 0x47, 0x65, 0xf9]
ip = [192, 168, 0, 225]
firmware = '4.3.49.5001150'
device = 'UGW3'


class TLV(object):

    def __init__(self):
        self.results = bytearray()

    def add(self, type, value):
        data = bytearray([type, ((len(value) >> 8) & 0xFF), (len(value) & 0xFF)])
        data.extend(value)
        self.results.extend(data)

    def get(self, version, command):
        value = bytearray([version, command, 0, len(self.results)])
        value.extend(self.results)

        return value


def construct_inform_tlv(index):
    tlv = TLV()
    tlv.add(1, bytearray(mac))
    tlv.add(2, bytearray(mac + ip))
    tlv.add(3, bytearray('UGW4.v{}'.format(firmware)))
    tlv.add(10, bytearray([ord(c) for c in struct.pack("!I", uptime())]))
    tlv.add(11, bytearray('PFSENSE'))
    tlv.add(12, bytearray(device))
    tlv.add(19, bytearray(mac))
    tlv.add(18, bytearray([ord(c) for c in struct.pack("!I", index)]))
    tlv.add(21, bytearray(device))
    tlv.add(27, bytearray(firmware))
    tlv.add(22, bytearray(firmware))
    return tlv


index = 1
while True:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 20)
    s.sendto(construct_inform_tlv(index).get(version=2, command=6), ('233.89.188.1', 10001))
    time.sleep(10)
    index += 1
