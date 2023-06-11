from src.packets_manager import PacketsManagerTcpUdp
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from src.conf_reader import ConfReader
from csv import reader
from time import perf_counter
from ipaddress import ip_address


def create_packet(row):
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

    
    return make_packet(sip, dip, int(sport), int(dport), flags)


def make_packet(sip, dip, sport, dport, tcp_flags):
    ip = IP(dst=dip, src=sip)
    ports = TCP(sport=sport, dport=dport, flags=tcp_flags)
    packet: Packet = ip / ports

    return packet




def test_packet(start, end, max_count):
    '''Return IPs in IPv4 range, inclusive.'''
    start_int = int(ip_address(start).packed.hex(), 16)
    end_int = int(ip_address(end).packed.hex(), 16)
    total_count = 0
    for ip in range(start_int, end_int):
        if(total_count > max_count): return
        total_count+=1

        s_addres = ip_address(ip)
        packet = make_packet(
                sip = s_addres,
                dip = '192.168.10.2',
                sport = 24524,
                dport=24565,
                tcp_flags='S'
        )
        if total_count % 5000 == 0:
            print(f'[{total_count}] {s_addres}')
        p.manage(packet)




    

def make_traffic(line, i):
    packet = create_packet(line)
    if packet:
        #print(f'{i}. send')
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

    # data_filepath = 'C:\\Projekty\\SPZC\\CICIDS2017\\raw_traffic\\raw_tcp_flags_syn_only.csv'
    # #data_filepath = 'C:\\Projekty\\SPZC\\CICIDS2017\\raw_traffic\\raw_tcp_test.csv'

    # i = 0
    # with open(data_filepath) as f:
    #     csv_r = reader(f)
    #     start = perf_counter()
    #     for row in csv_r:
    #         i +=1
    #         make_traffic(row, i)

    #         if i % 5000 == 0 :
    #             print(f"{i} packets processed")
    #             #break
    #         #showStats(row)
    #     elapse = perf_counter() - start
    
    # print(f"DONE in: {elapse}")
    
    start = perf_counter()
    
    test_packet('1.1.1.1', '255.255.255.255', max_count=10000)
    #test_packet('1.1.1.1', '255.255.255.255', max_count=100000)

    elapse = perf_counter() - start
    print(f"DONE in: {elapse}")


    p.stop()

