from src.packets_manager import PacketsManagerTcpUdp
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from src.conf_reader import ConfReader
from csv import reader
import os
import shutil


def clear_files():
    output_folder = 'outputs'
    for filename in os.listdir(output_folder):
        file_path = os.path.join(output_folder, filename)
        if os.path.isfile(file_path) or os.path.islink(file_path):
            print("EUREKA" + file_path)
            os.unlink(file_path)


def create_packet():
    if row[0] == "Source":
        return None
    # [0'Source', 1'Destination', 2'sport', 3'dport', 4'SYN', 5'ACK', 6'Protocol', 'Info']

    sip = row[0]
    dip = row[1]
    sport = row[2]
    dport = row[3]
    SYN = row[4]
    ACK = row[5]

    flags = ""
    if SYN == 'Set':
        flags += 'S'
    if ACK == 'Set':
        flags += 'A'

    return make_packet(sip, dip, int(sport), int(dport), flags)


def make_packet(sip, dip, sport, dport, tcp_flags):
    ip = IP(dst=dip, src=sip)
    ports = TCP(sport=sport, dport=dport, flags=tcp_flags)
    packet: Packet = ip / ports

    return packet


def make_traffic():
    packet = create_packet()
    if packet:
        p.manage(packet)


def show_stats(line):
    SYN = line[50]
    ACK = line[53]
    label = line[-1]
    if label == 'PortScan' and SYN == '1':
        print(f"{label} ACK: {ACK}, SYN: {SYN}")


if __name__ == '__main__':
    clear_files()
    c = ConfReader()
    _, trw_conf = c.read_conf('input_data/conf_CICIDS.ini')
    p = PacketsManagerTcpUdp(trw_conf=trw_conf)

    data_filepath = 'datasets/raw_tcp_flags_syn_only.csv'

    i = 0
    with open(data_filepath) as f:
        csv_r = reader(f)
        for row in csv_r:
            i += 1
            make_traffic()

            if i % 500 == 0:
                print(f"{i} packets processed")

    print("DONE")
    p.stop()
