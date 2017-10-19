# WORK IN PROGRESS, NOT WORKING !!

# pfSense Unifi gateway plugin

I don't know about you guys, but I'm very upset each time I log in the unifi controller. It looks like a conspiracy by Ubiquiti to not show all green circles because you don't buy all the ubuiquiti stuff.

The goal of this plugin is to simulate a UGW router to the Unifi controller.

Things to do:
- [x] reverse engineering the unifi protocol
- [ ] create a nice python code
- [ ] create a plugin for pfSense
- [ ] add dpi compatibility ?

## Reverse engineering / Proof of concept

You will find in "poc" directory all the necessary to simulate a UGW gateway. It's a **poc**, so please wait the final version if you don't know what you do.  

## Things to install manualy on pfSense router for now on:

- pkg add http://pkg.freebsd.org/freebsd:11:x86:64/latest/All/py27-setuptools-36.5.0.txz
- pkg add http://pkg.freebsd.org/freebsd:11:x86:64/latest/All/py27-uptime-3.0.1.txz

## How it works now

Without the definitive pfSense plugin, we have to manualy launch the daemon:

```bash
python unifi_gateway.py start
```

## Documentation
- https://github.com/jk-5/unifi-inform-protocol
- https://github.com/fxkr/unifi-protocol-reverse-engineering
