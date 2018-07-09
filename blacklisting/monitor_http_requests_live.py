#!/usr/bin/env python2

# Python script to alert the user if a http(port==80) request is made to the host specified in whitelist.yaml but the requested path is not whitelisted.
# Assumptions: Every HTTP Request MUST have Host field in its header which is always true for HTTP/1.1. See https://www.ietf.org/rfc/rfc2616.txt.

from __future__ import print_function
import sys
import scapy.all as scapy
from scapy.layers import http
import yaml

# Return a dictionary with keys as hostnames
def load_whitelist(location):
    fd = open(location, "r")
    return yaml.load(fd)


def check_alert(whitelist_dict):
    def check(pkt):
        if not pkt.haslayer(http.HTTPRequest):
            return

        http_layer = pkt.getlayer(http.HTTPRequest)
        http_host = http_layer.Host.decode()

        # Ignore if host is not specified in whitelist
        if not http_host in whitelist_dict:
            return
        # Continue only if Method is GET
        if http_layer.Method.decode() != 'GET':
            return
        http_path = http_layer.Path.decode()

        # For boundary case where path = '/'
        if len(http_path) > 1:
            http_path = http_path.rstrip('/')
        # print(http_path, http_host) # DEBUG

        # Ignore if http_path is whitelisted
        if http_path in whitelist_dict[http_host]:
            return

        # GENERATE ALERT
        print("ALERT: HTTP Request to non-whitelisted path", http_path, \
                "to host", http_host)

    return check

# Usage: ./script <interface>
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: <script> <iface>")
        sys.exit(0)
    whitelist_dict = load_whitelist('whitelist.yaml')
    print("Started sniffing...")
    scapy.sniff(iface=sys.argv[1], filter='tcp', prn=check_alert(whitelist_dict))
