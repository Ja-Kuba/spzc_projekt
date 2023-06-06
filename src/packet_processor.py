from abc import ABC, abstractmethod
from scapy.layers.l2 import Ether



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
        print(packet)