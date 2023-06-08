from src.packets_manager import PacketsManagerTcpUdp
from src.sniffer import Sniffer

if __name__ == "__main__":
    p = PacketsManagerTcpUdp()
    s = Sniffer(p)
    s.sniff(max_packets=0)
    s.stop()
    p.save_to_pcap()
