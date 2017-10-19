import MockSSH
import sys

from inform import send_inform

users = {'ubnt': 'ubnt'}




def execCommandImplemented(self, protocol, cmd):
    (_, _, url, key) = cmd.split(' ')
    print(cmd)

    with open('/tmp/cfg/log', 'w') as f:
        f.write('url=%s\nkey=%s\n' % (url, key))

    send_inform(url, key, partial=True)
    send_inform(url, key)


MockSSH.SSHAvatar.execCommand = execCommandImplemented


commands = [
]

MockSSH.runServer(
    commands, prompt="ubnt#", interface='10.0.8.2', port=10022, **users)
