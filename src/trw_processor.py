from scapy.layers.l2 import Ether
from src.packet_processor import PacketProcessor
from src.network_oracle import NetworkOracle
from src.trw import TRW, TRWPorts
from scapy.layers.inet import IP, TCP


class TRWProcessor(PacketProcessor):
    def __init__(self, conf: dict):
        self.conf = conf
        self.oracle = NetworkOracle(
            wisdom_source=self.conf['oracle_source'],
            local_network=conf['local_network']
        )
        self.trw = TRW(
            Pd=self.conf['Pd'],
            Pf=self.conf['Pf'],
            theta0=self.conf['theta0'],
            theta1=self.conf['theta1'],
        )
        self.trw_ports = TRWPorts(
            Pd=self.conf['Pd'],
            Pf=self.conf['Pf'],
            theta0=self.conf['theta0'],
            theta1=self.conf['theta1'],
            status_file='outputs/status_ports.log',
        )
        super().__init__()
        self.name = "TRWProcessor"
        self.stats_dump_cnt = 0
        self.stats_dump_period = self.conf['stats_dump_period']

    def __del__(self):
        # in super __del__ thread is joined!!!
        super().__del__()
        # self.dumpStats()

    def stop(self):
        super().stop()
        self.dump_stats()

    def dump_stats(self):
        self.trw.store_stats_in_file()
        self.trw_ports.store_stats_in_file()

    def on_packet(self, packet: Ether):
        self.stats_dump_cnt += 1
        if self.stats_dump_cnt % self.stats_dump_period == 0:
            self.stats_dump_cnt = 0
            self.dump_stats()

        return super().on_packet(packet)

    # just IPv4 support for now
    def process_packet(self, packet):
        if not packet['TCP'].flags == 0x02 or not IP in packet:
            # if not IP in packet:
            return

        # print(f"CHECK: {packet}; {packet.flags}")
        dst_port = int(packet[TCP].dport)
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
        # if IPv6 in packet:
        #     ip_dst = packet[IPv6].dst
        #     ip_src = packet[IPv6].src

        # we want to check only if local network is being scanned
        if not self.oracle.if_local_dest(ip_dst):
            return

        self.process_connection(ip_src, ip_dst, dst_port)

    def process_connection(self, ip_src, ip_dst, dst_port):
        # if connection may be successful based on Oracle wisdom
        successful = self.oracle.ask(ip_dst, dst_port)
        self.trw.put(successful, ip_src, ip_dst, None)
        self.trw_ports.put(successful, ip_src, ip_dst, dst_port)
