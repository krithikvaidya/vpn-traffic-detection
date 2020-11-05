# -*- coding: utf-8 -*-

from pprint import pprint
from scapy.arch.windows import get_windows_if_list
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
import sys
import csv


# disable verbose mode
conf.verb = 0

outputFile = open('vpntraffictest.csv', 'w', newline='')
writer = csv.writer(outputFile)

# Write out the top row
writer.writerow(['Version', 'Protocol', 'TTL', 'SrcAddr', 'DestAddr',
'SrcPort', 'DestPort', 'SeqNum', 'AckNum', 'Flag', 'dataSize',
'Service', 'Label'])

suspicious_hosts = ['tcdn.me.\'',  # Browsec
    'nodes.gen4.ninja.\'',  # Zenmate
    'cohen-feelings.org.\''  # Hoxx
]
hotspot_shield = []
suspicious_ips = []

total_packets = 0
suspicious_packets = 0

def parse_packet(packet):
    """
    network_sniffer callback function.
    
    """
    global total_packets
    global suspicious_packets
    if packet and packet.haslayer('UDP') and packet.haslayer ('DNS'):

        if packet.haslayer ('DNSRR'):

            # Check if the hostname is suspicious

            for i in range (packet['DNS'].ancount):

                for sus in suspicious_hosts:

                    if (str(packet[DNS].an[i].rrname).endswith(sus)):

                        print ("Suspicious rrname found: " + str(packet[DNS].an[i].rrname))
                        print ("Corresponding resource record address: " + str(packet[DNS].an[i].rdata), end="\n\n")
                        suspicious_ips.append (str(packet[DNS].an[i].rdata))


    if packet and packet.haslayer('TCP'):

        response_sequence_number = tcp.seq
        response_acknowledgement_number = tcp.ack
        response_timestamp = tcp.time
        response_payload_len += len(tcp.payload)

        if IP in pkt:
            ip_src=str(pkt[IP].src)
            ip_dst=str(pkt[IP].dst)

            for sus in suspicious_ips:

                if ip_src == sus:
                    print ("Suspicious incoming traffic encountered from IP " + ip_src)
                elif ip_dst == sus:
                    print ("Suspicious outgoing traffic encountered to IP " + ip_dst)
                


        else:
            pass
        
        tcp = packet.getlayer('TCP')
        # pprint (tcp)


def network_sniffer():
    """
    Listen for packets...
    """

    interfaces = get_windows_if_list()
    pprint(interfaces)

    print('\n[*] Start Sniffer\n')

    sniff(
        # filter="",
        iface=r'Intel(R) Wireless-AC 9560 160MHz', prn=parse_packet
    )


if __name__ == '__main__':
    network_sniffer()


        # pprint (packet)

        # if packet.qdcount > 0 and isinstance(packet.qd, DNSQR):
        #     name = packet.qd.qname
        #     # print (name)
            
        # elif packet.arcount > 0 and isinstance(packet.ar, DNSRR):
        #     name = packet.ar
        #     pprint (name)
        #     # print (packet.an.rrname)
        #     # print (packet.an.type)
        #     # print (packet.an.rclass)
        #     # print (packet.an.ttl)
        #     # print (packet.an.rdlen)
            
        # else:
        #     return