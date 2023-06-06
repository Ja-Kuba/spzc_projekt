import scapy.all as scapy
from scapy.layers import http
from packet_processor import DevProcessor

class Sniffer:
    def __init__(self, interface = None) -> None:
        self.interface = interface




    def sniff(self):
        p = DevProcessor()
        print("start sniffing...")
        scapy.sniff(iface = self.interface, store=False, prn=p.process)
        #scapy.sniff()


    def getIfacesList(self):
        interfaces = scapy.get_if_list()
        
        return interfaces



if __name__ == "__main__":
    s = Sniffer()
    ifaces = s.getIfacesList()
    for i in ifaces:
        print(i)
    s.sniff()