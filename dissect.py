import os
from copy import deepcopy
from pprint import pprint

from quic_tracker.dissector import parse_packet_with
from yaml import load

from pcap_to_task_format import main as pcap_to_task_format

_dir_path = os.path.dirname(os.path.abspath(__file__))


def dissect(trace):
    with open(os.path.join(_dir_path, 'inginious-problems-network-trace', 'protocols', 'all.yaml')) as f:
        protocols = load(f)
    return [parse_packet_with(bytearray(p), deepcopy(protocols), context={}) for p in trace]


trace = pcap_to_task_format()
pprint(dissect(trace))
