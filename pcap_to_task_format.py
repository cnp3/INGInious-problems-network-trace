#!/usr/bin/env python3
import json
import sys
from base64 import encodebytes

import dpkt

_levels = {
    'network': 0,
    'transport': 1,
    'application': 2
}

if len(sys.argv) <= 2 or sys.argv[2].count('-') > 1:
    print("Usage: {} input_pcap level_range".format(sys.argv[0]))
    print("Examples of use")
    print("    {} input.pcap network  # Only extract IP headers".format(sys.argv[0]))
    print(
        "    {} input.pcap network-application  # Extracts everything starting from the IP header".format(sys.argv[0]))
    print("    {} input.pcap transport-application  # Extracts everything starting from the transport header".format(
        sys.argv[0]))
    exit(-1)

level_range = sys.argv[2]
levels = [_levels[s] for s in level_range.split('-')]

output = []

with open(sys.argv[1], 'rb') as f:
    pcap = dpkt.pcap.Reader(f)
    for _, buf in pcap:
        struct = dpkt.ethernet.Ethernet(buf)
        buf = b''
        level = 0
        while level <= levels[-1]:
            struct = struct.data
            if level >= levels[0]:
                buf += b''.join(struct.pack().rsplit(bytes(struct.data))) if type(struct) is not bytes and struct.data else bytes(struct)
            elif level == levels[-1]:
                buf += struct.pack()
            level += 1

        if buf:
            output.append(buf)

print(json.dumps([encodebytes(b).decode("utf-8") for b in output]))
