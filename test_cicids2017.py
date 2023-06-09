from src.packets_manager import PacketsManagerTcpUdp
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from src.conf_reader import ConfReader
from csv import reader


def create_packet(line):
    # print(row)
    # for i, r in enumerate(row):
    # print(f"{i}: {r}")
    protocol = line[5]
    if protocol != "6":
        return None

    SYN = line[50]
    ACK = line[53]
    sip = line[1]
    dip = line[3]
    sport = line[2]
    dport = line[4]
    flags = 0

    if SYN == "1":
        flags += 0x02
    if ACK == "1":
        flags += 0x10

    return make_packet(sip, dip, int(sport), int(dport), flags)


def make_packet(sip, dip, sport, dport, tcp_flags):
    ip = IP(dst=dip, src=sip)
    ports = TCP(sport=sport, dport=dport, flags=tcp_flags)
    packet: Packet = ip / ports

    return packet


def make_traffic(line):
    packet = create_packet(line)
    if packet:
        p.manage(packet)


def show_stats(line):
    SYN = line[50]
    ACK = line[53]
    label = line[-1]
    if label == 'PortScan' and SYN == '1':
        print(f"{label} ACK: {ACK}, SYN: {SYN}")


if __name__ == '__main__':
    c = ConfReader()
    _, trw_conf = c.readConf('conf_CICIDS.ini')
    p = PacketsManagerTcpUdp(trw_conf=trw_conf)

    data_filepath = 'C:\\Projekty\\SPZC\\CICIDS2017\\learn_test\\port_scan_labeled.csv'

    with open(data_filepath) as f:
        csv_r = reader(f)
        for row in csv_r:
            make_traffic(row)
            # showStats(row)

    p.stop()
