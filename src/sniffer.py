import scapy.all as scapy
from packets_manager import PacketsManager, PacketsManagerTcpUdp


class Sniffer:
    def __init__(self, manager=PacketsManager, interface=None) -> None:
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

    def get_ifaces_list(self):
        interfaces = scapy.get_if_list()

        return interfaces

    def print_ifaces(self):
        ifaces = self.get_ifaces_list()
        for i in ifaces:
            print(i)

    def stop(self):
        self.manager.stop()


if __name__ == "__main__":
    p = PacketsManagerTcpUdp()
    s = Sniffer(p)
    s.sniff(max_packets=0)
    s.stop()
    p.save_to_pcap()
