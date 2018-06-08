#!/usr/bin/env python3

# Python script to alert the user if a http(port==80) request is made to the host specified in whitelist.yaml but the requested path is not whitelisted.
# Assumptions: Every HTTP Request MUST have Host field in its header which is always true for HTTP/1.1. See https://www.ietf.org/rfc/rfc2616.txt.

import scapy.all as scapy
from scapy.layers import http
import yaml
import sys


# Load whitelist file as dictionary
def load_whitelist(location):
    fd = open(location, "r")
    return yaml.load(fd)


# Function to check and then alert if the above criterion is not met.
def check_alert(pkt, whitelist_dict):
    if not pkt.haslayer(http.HTTPRequest):
        return

    http_layer = pkt.getlayer(http.HTTPRequest)
    http_host = http_layer.Host.decode()

    # Ignore if host is not specified in whitelist
    if not http_host in whitelist_dict:
        return
    http_path = http_layer.Path.decode()

    # For boundary case where path = '/'
    if len(http_path) > 1:
        http_path = http_path.rstrip('/')
    # print(http_path, http_host) # DEBUG

    # Ignore if http_path is whitelisted
    if http_path in whitelist_dict[http_host]:
        return

    # ALERT
    print("ALERT: HTTP Request to non-whitelisted path", http_path, \
            "to host", http_host)


# Usage: ./script [pcap_file]
# Default pcap file is http.pcap
if __name__ == "__main__":
    whitelist_dict = load_whitelist('whitelist.yaml')
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = 'http.pcap'
    packets = scapy.rdpcap(filename)
    for pkt in packets:
        check_alert(pkt, whitelist_dict)

