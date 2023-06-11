from dataclasses import dataclass, field, asdict, is_dataclass
import datetime
from json import JSONDecoder, JSONEncoder
import json
from os.path import isfile
# Threshold Random Walk implementation based on:
# Jaeyeon Jung, Vern Paxson, Arthur W. Berger, and Hari Balakrishnan
# "Fast Portscan Detection Using Sequential Hypothesis Testing"

PENDING ='PENDING' 
BENIGN = 'BENIGN'
SCANNER = 'SCANNER'


class RemoteHostDataJSONEncoder(JSONEncoder):
        class CustomDict(dict):
            def __init__(self, o) -> None:
                if isinstance(o, set):
                    o = list(o)
                return super().__init__(o)
            
        def default(self, o):
            if is_dataclass(o):
                return asdict(o, dict_factory=self.CustomDict)
            if isinstance(o, set):
                return list(o)


            return super().default(o)


class RemoteHostDataJSONDecoder(JSONDecoder):
        def __init__(self, *args, **kwargs):
            JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)
    
        
        def decode(self, o):
            if isinstance(o, dict) :
                return RemoteHostData(**o)
            return super().decode(o)
        
        def object_hook(self, dct):
            if 'Ds' in dct:
                dct['Ds'] = set(dct['Ds'])
                dct['Ls'] = float(dct['Ls'])
                return RemoteHostData(**dct)

            return dct


@dataclass
class RemoteHostData:
    ip_addr:str
    Ds:set = field(default_factory=set)         #set of ip's to which host has connected to
    Ss:str = PENDING    #decision_state
    Ls:float = 1.          #likelihood ratio
    conn_num:str = 0
    conn_fail:int = 0

    def stats_str(self):
        str = ''
        str+=f'{self.ip_addr}\n'
        str+=f'\tSs: {self.Ss}\n'
        str+=f'\tLs: {self.Ls}\n'
        str+=f'\tconn_num: {self.conn_num}\n'
        str+=f'\tconn_fail: {self.conn_fail}'
        return str


    # def store_hist(self):
    #     with open(f'{self.ip_addr}_logs.log', 'a', encoding='utf-8') as f:
    #         w = f'{self.Ss}, {self.Ls}, {self.conn_fail}, {self.conn_num}\n'
    #         f.write(w)

class TRW:
    def __init__(self, Pd, Pf, theta0, theta1, 
                 status_file='status.log', detected_file='detected.log') -> None:
        self.Pd = Pd 
        self.Pf = Pf
        self.theta0 = theta0
        self.theta1 = theta1
        
        self.n0 = (1 - Pd) / (1 - Pf)
        self.n1 = Pd / Pf

        self.status_file = status_file
        self.detected_file = detected_file
        self.hosts_stats:dict[RemoteHostData] = self.load_stats_from_file()

        self.updates_cnt = 0 
        

    
    def load_stats_from_file(self):
        if not isfile(self.status_file):
            return dict()
        try:
            with open(self.status_file, 'r', encoding="utf-8") as f:
                return (json.loads(f.read(), cls=RemoteHostDataJSONDecoder))
        except json.decoder.JSONDecodeError as e:
            print(f'[WARNING]file "{self.status_file}" has invalid format. Init empty status')
            return dict()
    

    def storeStatsInFile(self):
        with open(self.status_file, 'w', encoding="utf-8") as f:
            f.write(json.dumps(self.hosts_stats, cls=RemoteHostDataJSONEncoder))


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

        # hd.store_hist()

        self.updates_cnt +=1
        if self.updates_cnt %1 == 0:
            self.updates_cnt=0


    def likelihood_ratio(self, yi):
        if yi == 0:
            ratio = self.theta1 / self.theta0
        else:
            ratio = (1 - self.theta1) / (1 - self.theta0)

        return ratio

    def update_status(self, hd: RemoteHostData):
        if hd.conn_num >= 4:
            curr_state = hd.Ss
            if hd.Ls >= self.n1:
                hd.Ss = SCANNER
            elif hd.Ls <= self.n0:
                hd.Ss = BENIGN
            else:
                hd.Ss = PENDING
            
            if hd.Ss == SCANNER and hd.Ss != curr_state:
                time_Str = f"{datetime.datetime.now()} "
                with open(self.detected_file, 'a', encoding='utf-8') as f:
                    f.write(f'[{time_Str}] SCANNER DETECTED!!!\n{hd.stats_str()}\n-------\n')
                




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