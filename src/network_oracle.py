import ipaddress


# Based on defined wisdom_source which contains list of open ports on specific host 
# within local network tells if connection may be succesful
# Solution requires that list must be updated along wih network modifications 
class NetworkOracle:
    def __init__(self, wisdom_source:str='wisdom.txt', localNetwork='192.168.1.0/24') -> None:
        self.wisdom_source = wisdom_source
        self.localNetwork = localNetwork
        self.wisdom = set()

        
    def ifLocalDest(self, ip_dst):
        return ipaddress.ip_address(ip_dst) in ipaddress.ip_network(self.localNetwork)
    
    def loadWisdom(self):
        try:
            with open(self.wisdom_source, 'r', encoding='utf-8') as f:
                for line in f:
                    self.addProphecy(line.strip())
        
        except FileNotFoundError:
            raise FileNotFoundError(f'Oracle wisdom source file "{self.wisdom_source}" not found')


    def addProphecy(self, prop):
        #rgx= r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}:([0-9]):$'
        self.wisdom.add(prop)


    def ask(self, ip_dst, dst_port):
        dest = f'{ip_dst}:{dst_port}'
        print(f"ask: {dest}")
        
        return (True if dest in self.wisdom else False)
        




