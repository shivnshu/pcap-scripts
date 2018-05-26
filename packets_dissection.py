#!/usr/bin/python
from ctypes import *
import ipaddress
import scapy.all
import struct

def MAC_from_array_of_bytes(array):
    assert(len(array) == 6)
    mac_addr = str(hex(array[0])[2:]) + ":" + \
                str(hex(array[1])[2:]) + ":" + \
                str(hex(array[2])[2:]) + ":" + \
                str(hex(array[3])[2:]) + ":" + \
                str(hex(array[4])[2:]) + ":" + \
                str(hex(array[5])[2:])
    return mac_addr


class Ether(Structure):
    _fields_ = [
            ("dst", c_ubyte*6),
            ("src", c_ubyte*6),
            ("type", c_ushort)
            ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.type_map = {2048: 'IPv4', 2054: 'ARP'}

        self.src_addr = MAC_from_array_of_bytes(self.src)
        self.dst_addr = MAC_from_array_of_bytes(self.dst)
     
        self.type_bytes = struct.pack("<H", self.type)
        self.type_num = struct.unpack(">H", self.type_bytes)[0]
        try:
            self.type_str = self.type_map[self.type_num]
        except:
            self.type_str = str(self.type_num)

class IP(Structure):
    _fields_ = [
            ("ihl", c_ubyte, 4),
            ("version", c_ubyte, 4),
            ("tos", c_ubyte),
            ("len", c_ushort),
            ("id", c_ushort),
            ("offset", c_ushort),
            ("ttl", c_ubyte),
            ("protocol_num", c_ubyte),
            ("sum", c_ushort),
            ("src", c_uint32),
            ("dst", c_uint32)
            ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # proto num to name
        self.protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}

        # Readable IP addr
        self.src_addr = str(ipaddress.ip_address(struct.pack("<L", self.src)))
        self.dst_addr = str(ipaddress.ip_address(struct.pack("<L", self.dst)))

        # Readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

class ARP(Structure):
    _fields_ = [
            ("hwtype", c_ushort),
            ("ptype", c_ushort),
            ("hwlen", c_ubyte),
            ("plen", c_ubyte),
            ("op", c_ushort),
            ("sender_mac", c_ubyte*6),
            ("sender_ip", c_ubyte*4),
            ("target_mac", c_ubyte*6),
            ("target_ip", c_ubyte*4)
            ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.ip_src = str(self.sender_ip[0]) + "." + \
                        str(self.sender_ip[1]) + "." + \
                        str(self.sender_ip[2]) + "." + \
                        str(self.sender_ip[3])
        self.ip_target = str(self.target_ip[0]) + "." + \
                        str(self.target_ip[1]) + "." + \
                        str(self.target_ip[2]) + "." + \
                        str(self.target_ip[3])

        self.mac_src = MAC_from_array_of_bytes(self.sender_mac)
        self.mac_target = MAC_from_array_of_bytes(self.target_mac)


class TCP(Structure):
    _fields_ = [
            ("sport", c_ushort),
            ("dport", c_ushort),
            ("seq", c_uint32),
            ("ack", c_uint32),
            ("other", c_uint32),
            ("chksum", c_ushort),
            ("options", c_ubyte*14)
            ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.sport_bytes = struct.pack("<H", self.sport)
        self.sport_num = struct.unpack(">H", self.sport_bytes)[0]

        self.dport_bytes = struct.pack("<H", self.dport)
        self.dport_num = struct.unpack(">H", self.dport_bytes)[0]

        self.chksum_bytes = struct.pack("<H", self.chksum)
        self.chksum_num = hex(struct.unpack(">H", self.chksum_bytes)[0])


class UDP(Structure):
    _fields_ = [
            ("sport", c_ushort),
            ("dport", c_ushort),
            ("len", c_ushort),
            ("chksum", c_ushort)
            ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.sport_bytes = struct.pack("<H", self.sport)
        self.sport_num = struct.unpack(">H", self.sport_bytes)[0]

        self.dport_bytes = struct.pack("<H", self.dport)
        self.dport_num = struct.unpack(">H", self.dport_bytes)[0]

        self.chksum_bytes = struct.pack("<H", self.chksum)
        self.chksum_num = hex(struct.unpack(">H", self.chksum_bytes)[0])


f = "capture.pcap"
packets = scapy.all.rdpcap(f)

counter = 1
for pkt in packets:
    print("Packet #" + str(counter))
    counter += 1
    # pkt = packets[6]
    pkt = bytes(pkt)
    # print(pkt[14:34].hex())

    ether_header = Ether(pkt[0:14])
    print("Ether src addr: ", ether_header.src_addr)
    print("Ether dst addr: ", ether_header.dst_addr)
    print("Ether Type: ", ether_header.type_str)
    print()

    if ether_header.type_str == 'IPv4':
        ip_header = IP(pkt[14:34])
        print("IP src addr: ", ip_header.src_addr)
        print("IP dst addr: ", ip_header.dst_addr)
        print("IP protocol: ", ip_header.protocol)
        print()

    elif ether_header.type_str == 'ARP':
        arp_header = ARP(pkt[14:42])
        print("ARP src IP: ", arp_header.ip_src)
        print("ARP src MAC: ", arp_header.mac_src)
        print("ARP target IP: ", arp_header.ip_target)
        print("ARP target MAC: ", arp_header.mac_target)
        print()

    if ether_header.type_str == 'IPv4':
        if ip_header.protocol == 'TCP':
            try:
                tcp_header = TCP(pkt[34:66])
                print("TCP src port: ", tcp_header.sport_num)
                print("TCP dst port: ", tcp_header.dport_num)
                print("TCP chksum: ", tcp_header.chksum_num)
                if tcp_header.sport_num == 80 or tcp_header.dport_num == 80:
                    print("TCP HTTP packet")
                if tcp_header.sport_num == 443 or tcp_header.dport_num == 443:
                    print("TCP HTTPS packet")
                print()
            except:
                pass

        elif ip_header.protocol == 'UDP':
            udp_header = UDP(pkt[34:42])
            print("UDP src port: ", udp_header.sport_num)
            print("UDP dst port: ", udp_header.dport_num)
            if udp_header.sport_num == 53 or udp_header.dport_num == 53:
                print("UDP DNS packet")
            print()
    print("**********************************************")
    # break
