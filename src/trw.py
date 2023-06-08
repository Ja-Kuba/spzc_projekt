from dataclasses import dataclass, field

# Threshold Random Walk implementation based on:
# Jaeyeon Jung, Vern Paxson, Arthur W. Berger, and Hari Balakrishnan
# "Fast Portscan Detection Using Sequential Hypothesis Testing"

PENDING = 0
BENIGN = 1
SCANNER = 2


@dataclass
class RemoteHostData:
    ip_addr: str
    Ds: set = field(default_factory=set)  # set of ip's to which host has connected to
    Ss: int = PENDING  # decision_state
    Ls: float = 1.  # likelihood ratio
    conn_num: int = 0


class TRW:
    def __init__(self, Pd, Pf, theta0, theta1):
        self.hosts_stats: dict[RemoteHostData] = dict()
        self.Pd = Pd
        self.Pf = Pf
        self.theta0 = theta0
        self.theta1 = theta1

        self.n0 = (1 - Pd) / (1 - Pf)
        self.n1 = Pd / Pf

    def load_stats_from_file(self, filepath):
        raise NotImplementedError('TO DO...')

    def store_stats_in_file(self, filepath):
        raise NotImplementedError('TO DO...')

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
        hd.conn_num += 1
        yi = (0 if successful else 1)
        hd.Ls *= self.likelihood_ratio(yi)
        self.update_status(hd)

    def likelihood_ratio(self, yi):
        if yi == 0:
            ratio = self.theta1 / self.theta0
        else:
            ratio = (1 - self.theta1) / (1 - self.theta0)

        return ratio

    def update_status(self, hd: RemoteHostData):
        if hd.conn_num >= 4:
            if hd.Ls >= self.n1:
                hd.Ss = SCANNER
                print(f'SCANNER DETECTED: {hd.ip_addr}')
            elif hd.Ls <= self.n0:
                hd.Ss = BENIGN
                print(f'BENIGN MARKED: {hd.ip_addr}')
            else:
                hd.Ss = PENDING
