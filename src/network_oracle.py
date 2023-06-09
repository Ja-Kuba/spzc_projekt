import ipaddress


# Based on defined wisdom_source which contains list of open ports on specific host 
# within local network tells if connection may be successful
# Solution requires that list must be updated along wih network modifications 
class NetworkOracle:
    def __init__(self, wisdom_source:str='wisdom.txt', local_network='192.168.1.0/24') -> None:
        print(f"Local network: {local_network}")
        self.wisdom_source = wisdom_source
        self.local_network = local_network
        self.wisdom = set()
        self.load_wisdom()

    def if_local_dest(self, ip_dst):
        return ipaddress.ip_address(ip_dst) in ipaddress.ip_network(self.local_network)

    def load_wisdom(self):
        try:
            with open(self.wisdom_source, 'r', encoding='utf-8') as f:
                for line in f:
                    self.add_prophecy(line.strip())
        except FileNotFoundError:
            raise FileNotFoundError(f'Oracle wisdom source file "{self.wisdom_source}" not found')

    def add_prophecy(self, prop):
        if len(prop)>0 and prop[0] != "#":
            self.wisdom.add(prop)

    def ask(self, ip_dst, dst_port):
        dest = f'{ip_dst}:{dst_port}'
        #print(f"ask: {dest}")
        
        return (True if dest in self.wisdom else False)