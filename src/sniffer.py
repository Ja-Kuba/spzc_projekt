# Sniff network
#


import scapy.all as scapy
from src.packets_manager import PacketsManager


class Sniffer:
    def __init__(self, manager=PacketsManager, interface=None):
        self.interface = interface
        self.manager = manager

    def sniff(self, max_packets=None):
        print(f"filter: {self.manager.filter}")
        print("start sniffing...")
        scapy.sniff(
            iface=self.interface,
            filter=self.manager.filter,
            store=False,  # do not store packets by sniff function
            prn=self.manager.manage,
            count=max_packets,  # just for debugging
        )

    @staticmethod
    def get_ifaces_list():
        interfaces = scapy.get_if_list()

        return interfaces

    def print_ifaces(self):
        ifaces = self.get_ifaces_list()
        for i in ifaces:
            print(i)

    def stop(self):
        self.manager.stop()
