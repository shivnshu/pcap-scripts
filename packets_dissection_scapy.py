#!/usr/bin/python
from scapy.all import *

f = "capture.pcap"

packets = rdpcap(f)

counter = 1
for pkt in packets:
    print("Packet #" + str(counter))
    counter += 1
    # Ether layer dissection
    if Ether in pkt:
        print("Source MAC addr:", pkt[Ether].src)
        print("Destination MAC addr:", pkt[Ether].dst)
        print("Packet type:", pkt[Ether].type)
        print("")

    # ARP packet
    if ARP in pkt:
        print("ARP packet")
        if pkt[ARP].op == 1:
            print("Who has ", pkt[ARP].pdst, "? Tell ", pkt[ARP].psrc)
        elif pkt[ARP].op == 2:
            print("IP: ", pkt[ARP].pdst, " --> MAC: ", pkt[ARP].hwdst)
        print()

    # IP layer dissection
    if IP in pkt:
        print("IP packet")
        print("Packet IP src:", pkt[IP].src)
        print("Packet IP dst:", pkt[IP].dst)
        print("Packet IP version", pkt[IP].version)
        print("Packet protocol:", pkt[IP].proto)
        print("Packet checksum:", pkt[IP].chksum)
        print()

    # Check if TCP or UDP
    if TCP in pkt:
        print("TCP packet")
        print("Packet source port:", pkt[TCP].sport)
        print("Packet destination port:", pkt[TCP].dport)
        print("Packet checksum:", pkt[TCP].chksum)
        if pkt[TCP].sport == 80 or pkt[TCP].dport == 80:
            print("HTTP packet")
        if pkt[TCP].sport == 443 or pkt[TCP].dport == 443:
            print("HTTPS packet")
        print()
    # UDP
    elif UDP in pkt:
        print("UDP packet")
        print("Packet source port:", pkt[UDP].sport)
        print("Packet destination port:", pkt[UDP].dport)
        print("Packet checksum:", pkt[UDP].chksum)
        
        if DNS in pkt and pkt[DNS].qr == 1:
            print("DNS packet")
            try:
                print("Packet DNS mapping:", pkt[DNS].an.rrname, " --> ", pkt[DNS].an.rdata)
            except:
                pass
        print()

    # ICMP
    elif ICMP in pkt:
        print("ICMP packet")
        print()

    # Raw layer
    if Raw in pkt:
        print("Raw layer with data")
        # print(pkt[Raw].load)
        # print()

    # break
    print("\n**************************************\n")
