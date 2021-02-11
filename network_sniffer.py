#! /usr/bin/env python3

from collections import Counter
from scapy.all import *
from signal import signal, SIGINT
from sys import exit


arp_addresses = Counter()
ip_addresses = Counter()
mac_convo = Counter()
ip_convo = Counter()


def get_packets(packet):
    if packet.haslayer(IP):
        source = tuple([packet[IP].src, packet[Ether].src])
        ip_addresses.update([source])
        dest = tuple([packet[IP].dst, packet[Ether].dst])
        ip_addresses.update([dest])

        convo = tuple([packet[Ether].src, packet[Ether].dst])
        mac_convo.update([convo])
        convo = tuple([packet[IP].src, packet[IP].dst])
        ip_convo.update([convo])
        print('(IP Packet)\tsource:\t{}\t\tdestination:\t{}'.format(packet[IP].src, packet[IP].dst))

    if packet.haslayer(ARP):
        source = tuple([packet[ARP].hwsrc, packet[ARP].psrc])
        arp_addresses.update([source])
        dest = tuple([packet[ARP].hwdst, packet[ARP].pdst])
        arp_addresses.update([dest])

        convo = tuple([packet[ARP].hwsrc, packet[ARP].hwdst])
        mac_convo.update([convo])
        convo = tuple([packet[ARP].psrc, packet[ARP].pdst])
        ip_convo.update([convo])
        print('(ARP Packet)\tsource:\t{}\t\tdestination:\t{}'.format(packet[ARP].psrc, packet[ARP].pdst))


def address_mapping():
    print("\n\nFinding MAC Address of:")
    for address in ip_addresses.items():
        print('\t{}'.format(address[0][0]))
        packet = ARP(pdst=address[0][0])
        get_arp = sr1(packet, timeout=1, retry=0, verbose=False)
        if get_arp:
            if get_arp.haslayer(ARP):
                response = tuple([get_arp[ARP].hwsrc, get_arp[ARP].psrc])
                arp_addresses.update([response])
        elif address[0][1]:
            response = tuple([address[0][1], address[0][0]])
            arp_addresses.update([response])

    print("\n\n")
    print('=' * 42)
    print(' {:<40}'.format('         IP ADDRESS MAPPING'))
    print('=' * 42)
    print(' {:<17}   |   {:<15}'.format('   MAC ADDRESS   ', '  IP ADDRESS'))
    print('-'*42)
    # """
    count = 0
    printed = []
    for current in arp_addresses.items():
        invalid = 0
        if len(printed) > 1:
            for check in printed:
                if current[0][0] == check:
                    invalid = 1
                    break

        if invalid == 0:
            print(' {:<17}   '.format(current[0][0]), end="|")
            printed.append(current[0][0])
            curr = 0
            first = 0
            last = 0
            for address in arp_addresses.items():
                if curr >= count:
                    if current[0][0] == address[0][0] and last != address[0][1]:
                        last = address[0][1]
                        if first == 0:
                            print('   {:<15}'.format(address[0][1]))
                            first += 1
                        else:
                            print(' {:<17}   |   {:<15}'.format("                 ", address[0][1]))
                curr += 1
            count += 1
            print('-'*42)
    # """


def top_convo():
    # """
    print("\n\n")
    print('=' * 60)
    print('{:<60}'.format('              TOP 5 CONVERSATIONS - MAC ADDRESS'))
    print('=' * 60)
    print('{:<21}|{:<21}  |'.format('       SOURCE', '      DESTINATION'))
    print('-' * 60)
    print(' {:<17}   |     {:<17} |    {:<5}  '.format('    MAC ADDRESS  ', ' MAC ADDRESS', 'COUNT'))
    print('-' * 60)
    for current, count in mac_convo.most_common(5):
        print(' {:<17}   |   {:<17}   |     {:<5}  '.format(current[0], current[1], count))
        print('-'*60)

    print("\n\n")
    print('=' * 60)
    print('{:<60}'.format('              TOP 5 CONVERSATIONS - IP ADDRESS'))
    print('=' * 60)
    print('{:<21}|{:<21}|'.format('       SOURCE', '     DESTINATION'))
    print('-' * 60)
    print('  {:<15}    |    {:<15}  |      {:<5}  '.format('  IP ADDRESS', '  IP ADDRESS', 'COUNT'))
    print('-' * 60)
    for current, count in ip_convo.most_common(5):
        print('  {:<15}    |   {:<15}   |       {:<5}'.format(current[0], current[1], count))
        print('-' * 60)
    # """


def handler(signal_received, frame):
    address_mapping()
    top_convo()
    exit(0)


try:
    signal(SIGINT, handler)
    print("Enter ctrl + c to stop sniffing for packets\n")
    sniff(filter="ip or arp", prn=get_packets)
except KeyboardInterrupt:
    pass
