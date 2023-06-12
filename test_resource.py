# script for testing resource usage 
#

from dataclasses import dataclass, field, asdict, is_dataclass
import datetime
import json
from json import JSONDecoder, JSONEncoder


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

    def toDict(self):
        pass
        

    # def store_hist(self):
    #     with open(f'{self.ip_addr}_logs.log', 'a', encoding='utf-8') as f:
    #         w = f'{self.Ss}, {self.Ls}, {self.conn_fail}, {self.conn_num}\n'
    #         f.write(w)




a = RemoteHostData(
    ip_addr = '1.1.1.1',
    Ds = {'1.1.1.1', '2,2,3,4'},
    Ss = 'PENDING',
    Ls = 45,
    conn_num =  22,
    conn_fail = 14,
)
b = RemoteHostData(
    ip_addr = '1.1.1.1',
    Ds = {'1.1.1.1', '2,2,3,4'},
    Ss = 'PENDING',
    Ls = 45,
    conn_num =  22,
    conn_fail = 14,
)

c = {'1.1.1.1':a, '1.1.1.1':b}

jj = json.dumps(c, cls=RemoteHostDataJSONEncoder)
ja = json.loads(jj, cls=RemoteHostDataJSONDecoder)

print(c)
print(ja)