#! /usr/bin/env python3

from collections import Counter
from scapy.all import *
from signal import signal, SIGINT
from sys import exit
import time

"""
    GROUP 3
        BETITO, BERNICE MARIE M.
        VALERA, LUIS ANGELO
    
    NSCOM03 - S12
    Network Sniffer Project
"""


"""
arp_addresses
    - A collection of IP Addresses with their actual MAC Address
    - Taken from ARP Packets

ip_addresses = Counter()
    - A collection of IP Addresses with their MAC Address
    - Taken from IP Packets

mac_convo = Counter()
    - A collection of MAC Addresses conversing
    - Taken from both ARP Packets and IP Packets

ip_convo = Counter()
    - A collection of IP Addresses conversing
    - Taken from both ARP Packets and IP Packets

protocols = Counter()
    - A collection of protocols utilized by the packets sniffed
"""
arp_addresses = Counter()
ip_addresses = Counter()
mac_convo = Counter()
ip_convo = Counter()
protocols = Counter()


"""
protocol_list
    - A list of possible protocols used by the packets
"""
protocol_list = {
    1: "ICMP",
    2: "IGMP",
    3: "Gateway-Gateway Protocol (GGP)",
    4: "IP in IP Encapsulation",
    6: "TCP",
    8: "EGP",
    12: "PARC Universal Packet Protocol (PUP)",
    17: "UDP",
    20: "Host Monitoring Protocol (HMP)",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    27: "Reliable Datagram Protocol (RDP)",
    47: "General Routing Encapsulation (PPTP data over GRE)",
    50: "(ESP) IPSec",
    51: "(AH) IPSec",
    53: "DNS",
    66: "MIT Remote Virtual Disk (RVD)",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    88: "IGMP",
    89: "OSPF Open Shortest Path First",
    89: "Reservation Protocol (RSVP) QoS",
    110: "POP3",
    115: "Simple File Transfer Protocol",
    118: "SQL Services",
    123: "NTP",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP",
    152: "Background File Transfer Protocol (BFTP)",
    156: "SQL Services",
    161: "SNMP",
    179: "BGP",
    194: "IRC",
    199: "SNMP Multiplexing (SMUX)",
    220: "IMAPv3",
    280: "http-mgmt",
    389: "LDAP",
    443: "HTTPS",
    464: "Kerb password change/set",
    500: "ISAKMP/IKE",
    513: "rlogon",
    514: "rshell",
    530: "RPC",
    543: "klogin, Kerberos login",
    544: "kshell, Kerb Remote shell",
    636: "LDAPS",
    989: "FTP",
    990: "FTP",
    3306: "MySQL",
    5432: "PostgreSQL"
    }


"""
get_packets(packet)
    - Retrieves the IP Addresses and MAC Addresses
    - Determines the protocol used by the packet sniffed
    - Updates all the collections
        - arp_addresses
        - ip_addresses
        - mac_convo
        - ip_convo
        - protocols
    - Prints some information regarding the packet sniffed
        - Type of Packet (IP or ARP)
        - Source IP Address
        - Destination IP Address
    - packet => The packet sniffed
"""
def get_packets(packet):
    global protocol
    
    if packet.haslayer(IP):
        source = tuple([packet[IP].src, packet[Ether].src])
        ip_addresses.update([source])
        dest = tuple([packet[IP].dst, packet[Ether].dst])
        ip_addresses.update([dest])
        convo = tuple([packet[Ether].src, packet[Ether].dst])
        mac_convo.update([convo])
        convo = tuple([packet[IP].src, packet[IP].dst])
        ip_convo.update([convo])
        print('#{:<5}\t[ IP Packet]\t\tsource:\t{:<15}\t\tdestination:\t{:<15}'.format(sum(mac_convo.values()), packet[IP].src, packet[IP].dst))

    if packet.haslayer(ARP):
        source = tuple([packet[ARP].hwsrc, packet[ARP].psrc])
        arp_addresses.update([source])
        dest = tuple([packet[ARP].hwdst, packet[ARP].pdst])
        arp_addresses.update([dest])
        convo = tuple([packet[ARP].hwsrc, packet[ARP].hwdst])
        mac_convo.update([convo])
        convo = tuple([packet[ARP].psrc, packet[ARP].pdst])
        ip_convo.update([convo])
        print('#{:<5}\t[ARP Packet]\t\tsource:\t{:<15}\t\tdestination:\t{:<15}'.format(sum(mac_convo.values()), packet[ARP].psrc, packet[ARP].pdst))
        protocols.update(["ARP"])

    try:
        protocol = protocol_list[packet.proto]
        protocols.update([protocol])
    except:
        pass

#    try:
#        if packet.sport in protocol_list.keys():
#            service1 = protocol_list[packet.sport]
#        else:
#            service1 = str(packet.sport)
#    except:
#        service1 = "UNKNOWN"

    try:
        if packet.dport in protocol_list.keys():
            service2 = protocol_list[packet.dport]
        else:
            service2 = str(packet.dport)
    except:
        service2 = "UNKNOWN"

#    protocols.update([service1])
    protocols.update([service2])


"""
address_mapping(f)
    - Determines the actual MAC Address of the IP Addresses in the ip_addresses collection
    - Prints the IP Addresses and their MAC Address (in console and file)
    - f => The dump file to write to
"""
def address_mapping(f):
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
    print('=' * 42, file=f)

    print(' {:<40}'.format('         IP ADDRESS MAPPING'))
    print(' {:<40}'.format('         IP ADDRESS MAPPING'), file=f)

    print('=' * 42)
    print('=' * 42, file=f)

    print(' {:<17}   |   {:<15}'.format('   MAC ADDRESS   ', '  IP ADDRESS'))
    print(' {:<17}   |   {:<15}'.format('   MAC ADDRESS   ', '  IP ADDRESS'), file=f)

    print('-' * 42)
    print('-' * 42, file=f)

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
            print(' {:<17}   '.format(current[0][0]), end="|", file=f)

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
                            print('   {:<15}'.format(address[0][1]), file=f)
                            first += 1
                        else:
                            print(' {:<17}   |   {:<15}'.format("                 ", address[0][1]))
                            print(' {:<17}   |   {:<15}'.format("                 ", address[0][1]), file=f)
                curr += 1
            count += 1
            print('-' * 42)
            print('-' * 42, file=f)


"""
count_protocol(f)
    - Prints the 30 Most Common protocols utilized and the amount of packets that used them 
    - f => The dump file to write to
"""
def count_protocol(f):
    print("\n\n")
    f.write("\n\n")

    print('=' * 51)
    print('=' * 51, file=f)

    print("       {:<40}".format("        PROTOCOL STATISTICS"))
    print("       {:<40}".format("        PROTOCOL STATISTICS"), file=f)

    print('=' * 51)
    print('=' * 51, file=f)

    print("  {:<10}   |         {:<10}".format("PROTOCOL/PORT NUMBER", "COUNT"))
    print("  {:<10}   |         {:<10}".format("PROTOCOL/PORT NUMBER", "COUNT"), file=f)

    print('-' * 51)
    print('-' * 51, file=f)

    for current, count in protocols.most_common(30):
        print("         {:<10}      |          {:<8}".format(current, count))
        print("         {:<10}      |          {:<8}".format(current, count), file=f)

    print('-' * 51)
    print('-' * 51, file=f)
    

"""
top_convo(f)
    - Prints the Top 5 MAC Address Conversations
        - Source MAC Address
        - Destination MAC Address
        - Count of packets
    - Prints the Top 5 IP Address Conversations
        - Source IP Address
        - Destination IP Address
        - Count of packets 
    - f => The dump file to write to
"""
def top_convo(f):
    print("\n\n")
    f.write("\n\n")

    print('=' * 60)
    print('=' * 60, file=f)

    print('{:<60}'.format('              TOP 5 CONVERSATIONS - MAC ADDRESS'))
    print('{:<60}'.format('              TOP 5 CONVERSATIONS - MAC ADDRESS'), file=f)

    print('=' * 60)
    print('=' * 60, file=f)

    print('{:<21}|{:<21}  |'.format('       SOURCE', '      DESTINATION'))
    print('{:<21}|{:<21}  |'.format('       SOURCE', '      DESTINATION'), file=f)

    print('-' * 60)
    print('-' * 60, file=f)

    print(' {:<17}   |     {:<17} |    {:<5}  '.format('    MAC ADDRESS  ', ' MAC ADDRESS', 'COUNT'))
    print(' {:<17}   |     {:<17} |    {:<5}  '.format('    MAC ADDRESS  ', ' MAC ADDRESS', 'COUNT'), file=f)

    print('-' * 60)
    print('-' * 60, file=f)

    for current, count in mac_convo.most_common(5):
        print(' {:<17}   |   {:<17}   |     {:<5}  '.format(current[0], current[1], count))
        print(' {:<17}   |   {:<17}   |     {:<5}  '.format(current[0], current[1], count), file=f)

        print('-'*60)
        print('-' * 60, file=f)

    print("\n\n")
    f.write("\n\n")

    print('=' * 60)
    print('=' * 60, file=f)

    print('{:<60}'.format('              TOP 5 CONVERSATIONS - IP ADDRESS'))
    print('{:<60}'.format('              TOP 5 CONVERSATIONS - IP ADDRESS'), file=f)

    print('=' * 60)
    print('=' * 60, file=f)

    print('{:<21}|{:<21}|'.format('       SOURCE', '     DESTINATION'))
    print('{:<21}|{:<21}|'.format('       SOURCE', '     DESTINATION'), file=f)

    print('-' * 60)
    print('-' * 60, file=f)

    print('  {:<15}    |    {:<15}  |      {:<5}  '.format('  IP ADDRESS', '  IP ADDRESS', 'COUNT'))
    print('  {:<15}    |    {:<15}  |      {:<5}  '.format('  IP ADDRESS', '  IP ADDRESS', 'COUNT'), file=f)

    print('-' * 60)
    print('-' * 60, file=f)

    for current, count in ip_convo.most_common(5):
        print('  {:<15}    |   {:<15}   |       {:<5}'.format(current[0], current[1], count))
        print('  {:<15}    |   {:<15}   |       {:<5}'.format(current[0], current[1], count), file=f)

        print('-' * 60)
        print('-' * 60, file=f)


"""
handler(signal_received, frame)
    - Allows the program to stop sniffing, to print the needed details, and to exit gracefully
    - signal_received => SIGINT (Signals an interrupt from the keyboard (CTRL and C))
"""
def handler(signal_received, frame):
    file = open("dump.txt", "w")

    print("\n\nTotal # of Packets Sniffed:\t{}".format(sum(mac_convo.values())))
    print("Total # of Packets Sniffed:\t{}".format(sum(mac_convo.values())), file=file)

    end_time = time.asctime(time.localtime(time.time()))
    print("\nTime Started:\t" + start_time + "\n" + "Time Ended:\t" + end_time)
    file.write("\nTime Started:\t" + start_time + "\n" + "Time Ended:\t" + end_time + "\n\n")

    address_mapping(file)
    count_protocol(file)
    top_convo(file)

    exit(0)



"""
    Start of the program / where sniffing is enabled and started
    try-except
        Catches the Keyboard Interruption
"""
try:
    signal(SIGINT, handler)
    print("Enter ctrl + c to stop sniffing for packets\n")

    global start_time
    start_time = time.asctime(time.localtime(time.time()))

    sniff(filter="ip or arp", prn=get_packets)
except KeyboardInterrupt:
    pass
