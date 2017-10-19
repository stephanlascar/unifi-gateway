# -*- coding: utf-8 -*-
import time

from inform import cfg, send_inform


url = cfg('log', 'url')
key = cfg('log', 'key')

print(url)
print(key)

while(True):
    interval = send_inform(url, key)
    print('new interval %s' % interval)
    time.sleep(interval)
