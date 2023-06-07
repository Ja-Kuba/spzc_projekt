from abc import ABC, abstractmethod
from scapy.layers.l2 import Ether
import scapy.all as scapy


# Base interface for processor
class PacketProcessor(ABC):
    def __init__(self) -> None:
        super().__init__()

    @abstractmethod
    def process(self, packet):
        raise NotImplementedError()




#-----------------------------------------------------
# Dev processor
class DevProcessor(PacketProcessor):
    def __init__(self) -> None:
        super().__init__()
        

    def process(self, packet:Ether):
        #self.printPacket(packet)
        #self.saveToPcap(packet)


        pass
    
    def saveToPcap(self,packets):
        scapy.wrpcap('sniffed.pcap', packets, append=True)


    def printPacket(self, packet):
        print('-----------------------')
        print("1: ",packet)
        print("2: ",packet.summary)
        print("3: ",packet[Ether].src)
