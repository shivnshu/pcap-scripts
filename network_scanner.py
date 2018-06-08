#!/usr/bin/env python
import sys
import nmap

if (len(sys.argv) < 2):
    print("Usage: <bin> <ip-address> [port-range]")
    print("Eg. ./scan.py 127.0.0.1 1-100")
    Sys.exit()

mapping_dict = {}

f = open("services.list", "r")
lines = f.readlines()
for line in lines[2:]:
    # print(line)
    l = line.split()
    mapping_dict[l[1]] = l[0]

# print(mapping_dict)
# print(mapping_dict['22/tcp'])

nm = nmap.PortScanner()

if (len(sys.argv) == 2):
    result = nm.scan(sys.argv[1])
else:
    result = nm.scan(sys.argv[1], sys.argv[2])

# print(result)

for ip in result['scan']:
    print("Scan result of " + ip)
    try:
        for port in result['scan'][ip]['tcp']:
            if (result['scan'][ip]['tcp'][port]['state'] == 'open'):
                print(str(port) + ": " + mapping_dict[str(port)+"/tcp"])
    except:
        pass
    print()
