# -*- coding: utf-8 -*-
import sys

from inform import send_inform

with open('/tmp/cfg/log', 'w') as f:
    f.write('url=%s\nkey=%s\n' % (sys.argv[1], sys.argv[2]))

send_inform(sys.argv[1], sys.argv[2])
