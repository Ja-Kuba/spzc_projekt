#!/usr/bin/env -S sudo python3
"""
VERY simple port TCP port check, using Scapy
* https://scapy.readthedocs.io/en/latest/usage.html
* https://scapy.readthedocs.io/en/latest/api/scapy.html
* https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/sending_recieving/index.html
* Please check out the original script: https://thepacketgeek.com/scapy/building-network-tools/part-10/
Author: Jose Vicente Nunez <@josevnz@fosstodon.org>
"""
import os
import sys
import traceback
from enum import IntEnum
from pathlib import Path
from random import randint
from typing import Dict, List
from argparse import ArgumentParser
import random 
from scapy.layers.inet import IP, TCP, ICMP
from scapy.packet import Packet
from scapy.sendrecv import sr1, sr

NON_PRIVILEGED_LOW_PORT = 1025
NON_PRIVILEGED_HIGH_PORT = 65534
ICMP_DESTINATION_UNREACHABLE = 3
from random import randint


class TcpFlags(IntEnum):
    """
    https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html
    """
    SYNC_ACK = 0x12
    RST_PSH = 0x14


class IcmpCodes(IntEnum):
    """
    ICMP codes, to decide
    https://www.ibm.com/docs/en/qsip/7.4?topic=applications-icmp-type-code-ids
    """
    Host_is_unreachable = 1
    Protocol_is_unreachable = 2
    Port_is_unreachable = 3
    Communication_with_destination_network_is_administratively_prohibited = 9
    Communication_with_destination_host_is_administratively_prohibited = 10
    Communication_is_administratively_prohibited = 13


FILTERED_CODES = [x.value for x in IcmpCodes]


class RESPONSES(IntEnum):
    """
    Customized responses for our port check
    """
    FILTERED = 0
    CLOSED = 1
    OPEN = 2
    ERROR = 3


def load_machines_port(the_data_file: Path) -> Dict[str, List[int]]:
    port_data = {}
    with open(the_data_file, 'r') as d_scan:
        for line in d_scan:
            host, ports = line.split()
            port_data[host] = [int(p) for p in ports.split(',')]
    return port_data


def test_port(
        address: str,
        dest_ports: int,
        source_ip, 
        verbose: bool = False
) -> RESPONSES:
    """
    Test the address + port combination
    :param address:  Host to check
    :param dest_ports: Ports to check
    :return: Answer and Unanswered packets (filtered)
    """
    src_port = randint(NON_PRIVILEGED_LOW_PORT, NON_PRIVILEGED_HIGH_PORT)
    ip = IP(dst=address, src = source_ip)
    ports = TCP(sport=src_port, dport=dest_ports, flags="S")
    reset_tcp = TCP(sport=src_port, dport=dest_ports, flags="S")
    packet: Packet = ip / ports
    verb_level = 0
    if verbose:
        verb_level = 99
    try:
        answered = sr1(
            packet,
            verbose=verb_level,
            retry=0,
            timeout=.1,
            threaded=True
        )
        if not answered:
            return 'NOT'
        elif answered.haslayer(TCP):
            return 'ANSWERED'

    except TypeError:
        traceback.print_exc(file=sys.stdout)
        return RESPONSES.ERROR




if __name__ == "__main__":
    for ind, bad_ratio in enumerate([0, 0.05, 0.1, 0.2, 0.4, 0.5,0.7, 0.8]):
        source_ip = '192.168.1.' + str(190 + ind)
        n_packets = 50
        good_ports = [i for i in range(9000, 9500)]
        bad_ports = [i for i in range(9500, 10000)]
        for i in range(n_packets):
            machine='192.168.1.34'
            if random.random() < bad_ratio:
                port = random.choice(bad_ports)
                bad_ports.remove(port)
            else:
                port = random.choice(good_ports)
                good_ports.remove(port)
            ans = test_port(address=machine, dest_ports=port, source_ip= source_ip,verbose=False)
        # print(ans)