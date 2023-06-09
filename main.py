from src.packets_manager import PacketsManagerTcpUdp
from src.sniffer import Sniffer
from sys import argv, exit
from src.conf_reader import ConfReader


if __name__ == "__main__":
    if len(argv) != 2:
        print("Invalid args: ex. python main.py conf_file.ini")
    
    try:
        c =  ConfReader()
        sniffer_conf, trw_conf = c.readConf(argv[1])

        p = PacketsManagerTcpUdp(trw_conf = trw_conf)
        s = Sniffer(p)

        s.sniff(max_packets=sniffer_conf["max_packets"])
        s.stop()
        p.save_to_pcap()

    except KeyError as e:
        print(f"ERROR: {e}")
        exit()
