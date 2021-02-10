#! /usr/bin/env python3

from collections import Counter
from scapy.all import *
from signal import signal, SIGINT
from sys import exit


addresses = Counter()


def get_packets(packet):
    if packet[ARP].hwsrc != "00:00:00:00:00:00" and packet[ARP].hwsrc != "ff:ff:ff:ff:ff:ff":
        if packet[ARP].psrc != "0.0.0.0":
            source = tuple([packet[ARP].hwsrc, packet[ARP].psrc])
            addresses.update([source])

    if packet[ARP].hwdst != "00:00:00:00:00:00" and packet[ARP].hwdst != "ff:ff:ff:ff:ff:ff":
        if packet[ARP].pdst != "0.0.0.0":
            dest = tuple([packet[ARP].hwdst, packet[ARP].pdst])
            addresses.update([dest])


def address_mapping():
    # """
    print("\n")
    count = 0
    invalid = 0
    printed = []
    for current in addresses.items():
        if len(printed) > 1:
            for check in printed:
                if current[0][0] == check:
                    invalid = 1
                    break

        if invalid == 0:
            print("------------------------------")
            print('MAC ADDRESS:\n\t{}'.format(current[0][0]))
            printed.append(current[0][0])

            curr = 0
            print('\nIP ADDRESSES:')
            for address in addresses.items():
                if curr >= count:
                    if current[0][0] == address[0][0]:
                        print('\t{}'.format(address[0][1]))
                curr += 1
            count += 1
    # """


def handler(signal_received, frame):
    address_mapping()
    print("------------------------------\n")
    # print("\n".join(f"{f'{key[0]} <--> {key[1]}'}: {count}" for key, count in addresses.items()))
    exit(0)


try:
    signal(SIGINT, handler)
    print("Enter ctrl + c to stop\n")
    sniff(filter="arp", prn=get_packets)
except KeyboardInterrupt:
    pass
