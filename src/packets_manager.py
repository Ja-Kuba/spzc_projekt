from src.trw_processor import TRWProcessor
import scapy.all as scapy
from scapy.layers.inet import TCP, UDP


class PacketsManager:
    def __init__(self, filter_arg) -> None:
        # in Berkeley Packet Filter notation
        self._filter = filter_arg

    @property
    def filter(self):
        return self._filter

    @filter.setter
    def filter(self, val):
        self._filter = val

    def manage(self, packet):
        pass

    def stop(self):
        pass


class PacketsManagerTcpUdp(PacketsManager):
    def __init__(self, *args, **kwargs):
        kwargs['filter_arg'] = 'tcp or udp'
        super().__init__(*args, **kwargs)
        self.dev_proc = TRWProcessor()
        self.recorded_traffic = []

    def __del__(self):
        self.dev_proc.stop()

    def manage(self, packet):
        if packet.haslayer(TCP):
            self.dev_proc.on_packet(packet)
            self.recorded_traffic.append(packet)

        elif packet.haslayer(UDP):
            pass

    def stop(self):
        self.dev_proc.stop()

    def save_to_pcap(self):
        scapy.wrpcap('sniffed.pcap', self.recorded_traffic, append=False)

    @staticmethod
    def print_packet(packet):
        print('-----------------------')
        print("1: ", packet)
        print("2: ", packet.summary)
