#!/usr/bin/env python3
import json
import sys
from base64 import encodebytes

import dpkt

from dpkt.ethernet import ETH_TYPE_IP, ETH_TYPE_IP6

_levels = {
    'network': 0,
    'transport': 1,
    'application': 2
}


def main():
    if len(sys.argv) <= 2 or sys.argv[2].count('-') > 1:
        print("Usage: {} input_pcap level_range".format(sys.argv[0]))
        print("Examples of use")
        print("    {} input.pcap network  # Only extract IP headers".format(sys.argv[0]))
        print("    {} input.pcap network-application  # Extracts everything starting from the IP header".format(sys.argv[0]))
        print("    {} input.pcap transport-application  # Extracts everything starting from the transport header".format(sys.argv[0]))
        exit(-1)

    level_range = sys.argv[2]
    levels = [_levels[s] for s in level_range.split('-')]

    output = []

    with open(sys.argv[1], 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for _, buf in pcap:
            struct = dpkt.ethernet.Ethernet(buf)
            if struct.type not in (ETH_TYPE_IP, ETH_TYPE_IP6):  # This may not be an Ethernet frame
                if (buf[0] & 0xF0) >> 4 is 4:
                    struct = dpkt.ip.IP(buf)
                elif (buf[0] & 0xF0) >> 4 is 6:
                    struct = dpkt.ip.IP6(buf)
                else:
                    print("ERROR: A packet started without an Ethernet or IPv(4|6) header. Aborting.")
                    exit(-1)
                buf = b''.join(struct.pack().rsplit(bytes(struct.data))) if type(struct) is not bytes and struct.data else bytes(struct)
                level = 1
            else:
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

    return output


if __name__ == "__main__":
    print(json.dumps([encodebytes(b).decode("utf-8") for b in main()]))
