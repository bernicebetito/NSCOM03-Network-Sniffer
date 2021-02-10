#! /usr/bin/env python3

from collections import Counter
from scapy.all import *
from signal import signal, SIGINT
from sys import exit


addresses = Counter()


def handler(signal_received, frame):
    print(' {}   |   {}'.format('   MAC ADDRESS   ', '  IP ADDRESS'))
    print('-----------------------------------------')
    for current in addresses.items():
        print(' {}   |   {}'.format(current[0][0], current[0][1]))
        print('-----------------------------------------')

    exit(0)


try:
    signal(SIGINT, handler)
    print("Enter ctrl + c to stop\n")
    target_ip = "192.168.1.0/24"

    arp = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp

    while True:
        ans, unans = srp(packet, timeout=1, verbose=0)

        for sent, received in ans:
            if received[ARP].hwsrc != "00:00:00:00:00:00" and received[ARP].hwsrc != "ff:ff:ff:ff:ff:ff":
                if received[ARP].psrc != "0.0.0.0":
                    source = tuple([received[ARP].hwsrc, received[ARP].psrc])
                    addresses.update([source])

            if received[ARP].hwdst != "00:00:00:00:00:00" and received[ARP].hwdst != "ff:ff:ff:ff:ff:ff":
                if received[ARP].pdst != "0.0.0.0":
                    dest = tuple([received[ARP].hwdst, received[ARP].pdst])
                    addresses.update([dest])
except KeyboardInterrupt:
    pass