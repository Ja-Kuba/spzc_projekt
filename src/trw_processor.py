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
            status_file='status_ports.json',
        )
        super().__init__()       
        self.name= "TRWProcessor"
        self.stats_dump_cnt = 0
        self.stats_dump_period = self.conf['stats_dump_period']


    def stop(self):
        super().stop()
        self.dumpStats()

    def dumpStats(self):
        self.trw.storeStatsInFile()
        self.trw_ports.storeStatsInFile()

    def on_packet(self, packet: Ether):
        return super().on_packet(packet)

    def process_packet(self, packet):
        if not packet['TCP'].flags == 0x02 or not IP in packet:
            return
        
        dst_port = int(packet[TCP].dport)
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst


        # we want to check only if local network is being scanned
        if not self.oracle.if_local_dest(ip_dst):
            return

        self.stats_dump_cnt += 1
        if self.stats_dump_cnt % self.stats_dump_period == 0:
            self.stats_dump_cnt=0
            self.dumpStats()

        self.process_connection(ip_src, ip_dst, dst_port)



    def process_connection(self, ip_src, ip_dst, dst_port):
        #cehck if connection may be succesful based on Oracle wisedom
        succesful = self.oracle.ask(ip_dst, dst_port)
        self.trw.put(succesful, str(ip_src), str(ip_dst))
        self.trw_ports.put(succesful, str(ip_src), str(ip_dst), dst_port)

