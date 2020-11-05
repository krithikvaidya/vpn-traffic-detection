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

suspicious_hosts_suffix = [
    'tcdn.me.\'',  # Browsec suffix
    'nodes.gen4.ninja.\'',  # Zenmate suffix
]

suspicious_hosts_prefix = [
    'azbe-9b1c5b'  # Hoxx prefix
]

hotspot_shield = [
    '196.5'
]
suspicious_ips = []

possible_tor_ips = []

total_packets = 0
suspicious_packets = 0

def parse_packet(packet):
    """
    network_sniffer callback function.
    
    """
    global total_packets
    global suspicious_packets
    global hotspot_shield
    global suspicious_ips
    global possible_tor_ips

    if packet:
        total_packets += 1

    if packet and packet.haslayer('UDP') and packet.haslayer ('DNS'):

        if packet.haslayer ('DNSRR'):

            # Check if the hostname is suspicious

            for i in range (packet['DNS'].ancount):

                # print (str(packet[DNS].an[i].rrname))

                for sus in suspicious_hosts_suffix:

                    if (str(packet[DNS].an[i].rrname).endswith(sus)):

                        print ("Suspicious rrname found: " + str(packet[DNS].an[i].rrname))
                        print ("Corresponding resource record address: " + str(packet[DNS].an[i].rdata), end="\n\n")
                        suspicious_ips.append (str(packet[DNS].an[i].rdata))
                        suspicious_packets += 1

                for sus in suspicious_hosts_prefix:

                    if (packet[DNS].an[i].rrname.decode('ascii').startswith(sus)):

                        print ("Suspicious rrname found: " + str(packet[DNS].an[i].rrname))
                        print ("Corresponding resource record address: " + str(packet[DNS].an[i].rdata), end="\n\n")
                        suspicious_ips.append (str(packet[DNS].an[i].rdata))
                        suspicious_packets += 1


    if packet and packet.haslayer('TCP'):

        tcp = packet.getlayer('TCP')
        # pprint (tcp)

        sequence_number = tcp.seq
        acknowledgement_number = tcp.ack
        timestamp = tcp.time
        # payload_len = len(tcp.payload)
        tcp_sport=tcp.sport
        tcp_dport=tcp.dport

        ip_src = None
        ip_dst = None

        if IP in packet:

            ip_src=packet[IP].src
            ip_dst=packet[IP].dst

            for hs_ip in hotspot_shield:

                if ip_src.startswith(hs_ip):
                    print ("Suspicious incoming traffic encountered from IP " + str(ip_src))
                    suspicious_packets += 1
                elif ip_dst.startswith(hs_ip):
                    print ("Suspicious outgoing traffic encountered to IP " + str(ip_dst))
                    suspicious_packets += 1

            for sus in suspicious_ips:

                if str(ip_src) == str(sus):
                    print ("Suspicious incoming traffic encountered from IP " + str(ip_src))
                    suspicious_packets += 1
                elif str(ip_dst) == str(sus):
                    print ("Suspicious outgoing traffic encountered to IP " + str(ip_dst))
                    suspicious_packets += 1

        if 'TLS' in packet:
            
            try:

                x = packet['TLS'].msg[0].msgtype

                if x == 1:  # client hello

                    if str(ip_dst) in possible_tor_ips:

                        # Check if there is a www host name in the packet

                        server_name = packet['TLS'].msg[0].ext[1].servernames[0].servername
                        server_name = server_name.decode('ascii')

                        if (server_name.startswith ('www')):
                            print ("Suspicious Client Hello encountered to IP " + str(ip_dst) + "with server name: " + server_name)
                            possible_tor_ips.append(str(ip_dst))

                            


            except Exception:
                pass

            if 'msgtype' in packet['TLS'].msg[0]:
                print ("YES")

                
        else:
            pass


def network_sniffer():
    """
    Listen for packets...
    """

    interfaces = get_windows_if_list()
    pprint(interfaces)

    print('\n** Start Sniffer **\n')

    load_layer("tls")
    sniff(
        iface=r'Intel(R) Wireless-AC 9560 160MHz', prn=parse_packet
    )


if __name__ == '__main__':
    network_sniffer()