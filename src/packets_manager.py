from src.trw_processor import TRWProcessor
import scapy.all as scapy
from scapy.layers.inet import TCP, UDP


class PacketsManager:
    def __init__(self, filter_arg):
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
    def __init__(self, trw_conf: dict, *args, **kwargs):
        kwargs['filter_arg'] = 'tcp or udp'
        super().__init__(*args, **kwargs)
        self.recorded_traffic = []

        self.init_packet_processors(trw_conf)

    def init_packet_processors(self, trw_conf):
        self.dev_proc = TRWProcessor(conf=trw_conf)

    def __del__(self):
        self.dev_proc.stop()

    def manage(self, packet):
        if packet.haslayer(TCP):
            #print(f"p: {packet}")
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
