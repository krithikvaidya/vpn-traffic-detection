# -*- coding: utf-8 -*-

from pprint import pprint
from scapy.arch.windows import get_windows_if_list
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
import sys
import csv
from signal import signal, SIGINT


# disable verbose mode
conf.verb = 0

outputFile = open('vpntraffictest.csv', 'w', newline='')
writer = csv.writer(outputFile)

# Write out the top row
writer.writerow(['Suspicious', 'Timestamp', 'Transport_Protocol', 'Network_Protocol', 'TTL', 'SrcAddr', 'DestAddr',
                 'SrcPort', 'DestPort', 'SeqNum', 'AckNum'])
                #  , 'Flag', 'dataSize',
                #  'Service', 'Label'])

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

likely_tor_ips = []

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
    global likely_tor_ips

    suspicious = "NO"
    timestamp = "-"
    protocol1 = "-"
    protocol2 = "-"
    ttl = "-"
    ip_src = "-"
    ip_dst = "-"
    src_port = "-"
    dst_port = "-"
    seq_number = "-"
    ack_number = "-"

    if packet:
        total_packets += 1

    if packet and packet.haslayer('UDP'):

        udp = packet.getlayer('UDP')

        protocol1 = "UDP"
        src_port = udp.sport
        dst_port = udp.dport
        timestamp = udp.time

    if packet and packet.haslayer('UDP') and packet.haslayer('DNS'):

        protocol2 = "DNS"

        if packet.haslayer('DNSRR'):

            # Check if the hostname is suspicious

            for i in range(packet['DNS'].ancount):

                # print (str(packet[DNS].an[i].rrname))

                for sus in suspicious_hosts_suffix:

                    if (str(packet[DNS].an[i].rrname).endswith(sus)):

                        print("Suspicious rrname found: " +
                              str(packet[DNS].an[i].rrname))
                        print("Corresponding resource record address: " +
                              str(packet[DNS].an[i].rdata), end="\n\n")
                        suspicious_ips.append(str(packet[DNS].an[i].rdata))
                        suspicious_packets += 1
                        suspicious = "YES"

                for sus in suspicious_hosts_prefix:

                    if (packet[DNS].an[i].rrname.decode('ascii').startswith(sus)):

                        print("Suspicious rrname found: " +
                              str(packet[DNS].an[i].rrname))
                        print("Corresponding resource record address: " +
                              str(packet[DNS].an[i].rdata), end="\n\n")
                        suspicious_ips.append(str(packet[DNS].an[i].rdata))
                        suspicious_packets += 1
                        suspicious = "YES"

    if packet and packet.haslayer('TCP'):

        protocol1 = "TCP"
        tcp = packet.getlayer('TCP')
        # pprint (tcp)

        seq_number = tcp.seq
        ack_number = tcp.ack
        timestamp = tcp.time
        # payload_len = len(tcp.payload)
        ttl = packet.ttl
        src_port = tcp.sport
        dst_port = tcp.dport

        if IP in packet:

            protocol2 = "IP"
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst


            for hs_ip in hotspot_shield:

                if ip_src.startswith(hs_ip):
                    print(
                        "Suspicious incoming traffic encountered from IP " + str(ip_src))
                    suspicious_packets += 1
                    suspicious = "YES"
                elif ip_dst.startswith(hs_ip):
                    print(
                        "Suspicious outgoing traffic encountered to IP " + str(ip_dst))
                    suspicious_packets += 1
                    suspicious = "YES"

            for sus in suspicious_ips:

                if str(ip_src) == str(sus):
                    print(
                        "Suspicious incoming traffic encountered from IP " + str(ip_src))
                    suspicious_packets += 1
                    suspicious = "YES"
                elif str(ip_dst) == str(sus):
                    print(
                        "Suspicious outgoing traffic encountered to IP " + str(ip_dst))
                    suspicious_packets += 1
                    suspicious = "YES"

            for sus in likely_tor_ips:

                if str(ip_src) == str(sus):
                    print(
                        "Suspicious (TOR) incoming traffic encountered from IP " + str(ip_src))
                    suspicious_packets += 1
                    suspicious = "YES"
                elif str(ip_dst) == str(sus):
                    print(
                        "Suspicious (TOR) outgoing traffic encountered to IP " + str(ip_dst))
                    suspicious_packets += 1
                    suspicious = "YES"

        if 'TLS' in packet:

            try:

                # packet['TLS'].show()
                x = packet['TLS'].msg[0].msgtype

                if x == 1:  # client hello

                    # Check if there is a www host name in the packet

                    try:
                        server_name = packet['TLS'].msg[0].ext[0].servernames[0].servername
                        server_name = server_name.decode('ascii')
                    except:
                        server_name = packet['TLS'].msg[0].ext[1].servernames[0].servername
                        server_name = server_name.decode('ascii')

                    if (server_name.startswith('www') and (dst_port >= 9000 and dst_port <= 9020)):

                        print(
                            "Suspicious (TOR) outgoing traffic encountered to IP " + str(ip_dst))

                        likely_tor_ips.append(str(ip_dst))

                        suspicious_packets += 1
                        suspicious = "YES"

            except Exception as e:
                if str(e) != 'msgtype' and str(e) != 'ext':
                    print('\n\nError: ')
                    print(e)
                    print('\n\n')
                    packet['TLS'].show()
                    print('\n\n')

    
    writer.writerow([suspicious, timestamp, protocol1, protocol2, ttl, ip_src, ip_dst,
                 src_port, dst_port, seq_number, ack_number])


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


def handler(signal_received, frame):
    
    print ("\n\n========================================\n")
    print('\nSIGINT detected')
    print('\n\nTotal Packets Captured: ' + str(total_packets))
    print ('Number of Suspicious Packets: ' + str(suspicious_packets))
    print ("\n\n========================================\n")
    exit(0)


def populate_tor_ips ():

    with open("tor_exit_nodes.txt", "r") as f:

        for line in f:

            likely_tor_ips.append(line.strip())



if __name__ == '__main__':

    # for writing suspicious and total packet counts at termination

    signal(SIGINT, handler)

    populate_tor_ips()

    network_sniffer()
