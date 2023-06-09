from dataclasses import dataclass, field
import datetime
# Threshold Random Walk implementation based on:
# Jaeyeon Jung, Vern Paxson, Arthur W. Berger, and Hari Balakrishnan
# "Fast Portscan Detection Using Sequential Hypothesis Testing"

PENDING = 0
BENIGN = 1
SCANNER = 2


@dataclass
class RemoteHostData:
    ip_addr:str
    Ds:set = field(default_factory=set)         #set of ip's to which host has connected to
    Ss:int = PENDING    #decision_state
    Ls:float = 1.          #likelihood ratio
    conn_num:str = 0
    conn_fail:int = 0


class TRW:
    def __init__(self, Pd, Pf, theta0, theta1, 
                 status_file='status.log', detected_file='detected.log') -> None:
        self.hosts_stats:dict[RemoteHostData] = dict()
        self.Pd = Pd 
        self.Pf = Pf
        self.theta0 = theta0
        self.theta1 = theta1
        
        self.n0 = (1 - Pd) / (1 - Pf)
        self.n1 = Pd / Pf

        self.status_file = status_file
        self.f = open(detected_file, 'a', encoding='utf-8')
        self.updates_cnt = 0 

    def __del__(self):
        self.f.close()

    def load_stats_from_file(self, filepath):
        raise NotImplementedError('TO DO...')

    def storeStatsInFile(self):
        with open(self.status_file, 'w', encoding="utf-8") as f:
            for _, hd in self.hosts_stats.items():
                f.write(f'{hd.ip_addr}\n')
                f.write(f'\tSs: {hd.Ss}\n')
                f.write(f'\tLs: {hd.Ls}\n')
                f.write(f'\tconn_num: {hd.conn_num}\n')
                f.write(f'\tconn_fail: {hd.conn_fail}\n')


    def put(self, successful, ip_src, ip_dst):
        key = ip_src
        if key in self.hosts_stats:
            self.update(self.hosts_stats[key], successful, ip_dst)

        else:
            new_host = RemoteHostData(ip_addr=ip_src)
            self.hosts_stats[key] = new_host
            self.update(new_host, successful, ip_dst)

    def update(self, hd: RemoteHostData, successful, ip_dst):
        if ip_dst in hd.Ds:
            # there already was first connection to that localhost
            return
        hd.Ds.add(ip_dst)
        hd.conn_num+=1
        yi = (0 if successful else 1)
        hd.Ls *= self.likelihood_ratio(yi)
        self.update_status(hd)
        if not successful:
            hd.conn_fail+=1

        self.updates_cnt +=1
        if self.updates_cnt %1 == 0:
            print("__STORE STATE_PORTS")
            self.storeStatsInFile()
            self.updates_cnt=0


    def likelihood_ratio(self, yi):
        if yi == 0:
            ratio = self.theta1 / self.theta0
        else:
            ratio = (1 - self.theta1) / (1 - self.theta0)

        return ratio

    def update_status(self, hd: RemoteHostData):
        if hd.conn_num >= 4:
            if hd.Ls >= self.n1:
                if hd.Ss != SCANNER:
                    time_Str = f"{datetime.datetime.now()} "
                    self.f.write(f'[{time_Str}] DETECTED: {hd.ip_addr} conn_cnt={hd.conn_num} conn_failed={hd.conn_fail}\n')
                    self.f.flush()
                hd.Ss = SCANNER
                print(f'SCANNER DETECTED: {hd.ip_addr}')
            elif hd.Ls <= self.n0:
                hd.Ss = BENIGN
                print(f'BENIGN MARKED: {hd.ip_addr}')
            else:
                hd.Ss = PENDING




class TRWPorts(TRW):
    def __init__(self, Pd, Pf, theta0, theta1, 
                 status_file='status_ports.log', detected_file='detected_ports.log') -> None:
        super().__init__(Pd, Pf, theta0, theta1, status_file, detected_file)

    def put(self, succesful, ip_src, ip_dst, dport):
        key = ip_src
        if key in self.hosts_stats:
            self.update(self.hosts_stats[key], succesful, f'{ip_dst}:{dport}')

        else:
            new_host = RemoteHostData(ip_addr=ip_src)
            self.hosts_stats[key] = new_host
            self.update(new_host, succesful, f'{ip_dst}:{dport}')