# -*- coding: utf-8 -*-
import struct
from uptime import uptime

from tlv import UnifiTLV
from tools import mac_string_2_array, ip_string_2_array


def create_broadcast_message(config, index, version=2, command=6):
    lan_mac = config.get('gateway', 'lan_mac')
    lan_ip = config.get('gateway', 'lan_ip')
    firmware = config.get('gateway', 'firmware')
    device = config.get('gateway', 'device')

    tlv = UnifiTLV()
    tlv.add(1, bytearray(mac_string_2_array(lan_mac)))
    tlv.add(2, bytearray(mac_string_2_array(lan_mac) + ip_string_2_array(lan_ip)))
    tlv.add(3, bytearray('{}.v{}'.format(device, firmware)))
    tlv.add(10, bytearray([ord(c) for c in struct.pack('!I', uptime())]))
    tlv.add(11, bytearray('PFSENSE'))
    tlv.add(12, bytearray(device))
    tlv.add(19, bytearray(mac_string_2_array(lan_mac)))
    tlv.add(18, bytearray([ord(c) for c in struct.pack('!I', index)]))
    tlv.add(21, bytearray(device))
    tlv.add(27, bytearray(firmware))
    tlv.add(22, bytearray(firmware))
    return tlv.get(version=version, command=command)
