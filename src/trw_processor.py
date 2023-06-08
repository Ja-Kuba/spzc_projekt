from packet_processor import PacketProcessor
from network_oracle import NetworkOracle
from trw import TRW

from scapy.layers.inet import IP, TCP, UDP


#-----------------------------------------------------
class TRWProcessor(PacketProcessor):
    def __init__(self, *args, **kwargs) -> None:
        self.oracle = NetworkOracle()
        self.trw = TRW(
            Pd = 0.99,
            Pf = 0.01,
            theta0 = 0.8,
            theta1 = 0.2,
        )
        super().__init__(*args, **kwargs)       
        self.name= "TRWProcessor"

    
    #just IPv4 support for now
    def processPacket(self, packet):
        if not packet['TCP'].flags == 0x02 or not IP in packet:
            return
        
        print(f"CHCK: {packet}; {packet.flags}")
        dst_port = packet[TCP].dport
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
        # if IPv6 in packet:
        #     ip_dst = packet[IPv6].dst
        #     ip_src = packet[IPv6].src

        #we want to check only if local network is being scan
        if not self.oracle.ifLocalDest(ip_dst):
            return

        self.proccessConection(ip_src, ip_dst, dst_port)



    def proccessConection(self, ip_src, ip_dst, dst_port):
        #if connection may be succesful based on Oracle wisedom
        succesful = self.oracle.ask(ip_dst, dst_port)
        self.trw.put(succesful, ip_src, ip_dst)

    


    

