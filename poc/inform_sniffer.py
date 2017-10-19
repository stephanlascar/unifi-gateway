import base64
import json
import struct

import zlib
from Crypto.Cipher import AES
from binascii import a2b_hex
from flask import Flask, request

from inform import packet_decode

app = Flask(__name__)


@app.route("/inform", methods=['POST'])
def inform():
    data = request.get_data()

    payload = json.loads(packet_decode(a2b_hex("a09e428c482eb53c7731c224295cd9d3"), data))
    print(payload)


    return ''



#mca-ctrl -t connect -s "http://10.0.8.2:8080/inform" -k "A09E428C482EB53C7731C224295CD9D3"



def print_bytearray(value):
    print([b for b in value])

app.run(debug=True, port=8080, host='10.0.8.2')
