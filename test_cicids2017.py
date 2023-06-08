from src.packets_manager import PacketsManagerTcpUdp
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from src.conf_reader import ConfReader
from csv import reader
import tqdm


def createPacket(row):
    # print(row)
    # for i, r in enumerate(row):
        # print(f"{i}: {r}")
    protocol = row[5]
    if protocol != "6": 
        return None
    
    SYN = row[50]
    ACK = row[53]
    sip = row[1]
    dip = row[3]
    sport = row[2]
    dport = row[4]
    flags = 0

    if SYN == "1": flags +=0x02
    if ACK == "1": flags +=0x10
    
    return makePacket(sip, dip, int(sport), int(dport), flags)


def makePacket(sip, dip, sport, dport, tcp_flags):
    ip = IP(dst=dip, src=sip)
    ports = TCP(sport=sport, dport=dport, flags=tcp_flags)
    packet: Packet = ip / ports

    return packet


def maketraffic(line):
    packet = createPacket(line)
    if packet:
        p.manage(packet)                
            

def showStats(row):
    SYN = row[50]
    ACK = row[53]
    label = row[-1]
    if label == 'PortScan' and SYN == '1':
        print(f"{label} ACK: {ACK}, SYN: {SYN}")

if __name__ == '__main__':
    c =  ConfReader()
    _, trw_conf = c.readConf('conf_CICIDS.ini')
    p = PacketsManagerTcpUdp(trw_conf=trw_conf)

    data_filepath = 'C:\\Projekty\\SPZC\\CICIDS2017\\learn_test\\port_scan_labeled.csv'

    with open(data_filepath) as f:
        csv_r = reader(f)
        for row in csv_r:
            maketraffic(row)
            #showStats(row)

    p.stop()



