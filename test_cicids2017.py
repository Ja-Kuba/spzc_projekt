from src.packets_manager import PacketsManagerTcpUdp
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from src.conf_reader import ConfReader
from csv import reader


def createPacket(row):
    # print(row)
    # for i, r in enumerate(row):
        # print(f"{i}: {r}")
    # protocol = row[5]
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

    data_filepath = 'C:\\Projekty\\SPZC\\CICIDS2017\\raw_traffic\\raw_tcp_flags_syn_only.csv'

    i = 0
    with open(data_filepath) as f:
        csv_r = reader(f)
        for row in csv_r:
            i +=1
            maketraffic(row)

            if i % 5000 == 0 :
                print(f"{i} packets processed")
                #break
            #showStats(row)
    
    print("DONE")
    p.stop()



