from packet_processor import PacketProcessor, DevProcessor



class PacketsManager:
    def __init__(self, filter_arg) -> None:
        #in Berkeley Packet Filter notation
        self._filter = filter_arg 


    @property
    def filter(self):
        return self._filter

    @filter.setter
    def filter(self, val):
        self._filter = val

    def manage(self, packet):
        pass
        


class PacketsManagerTcpUdp(PacketsManager):
    def __init__(self, *args, **kwargs) -> None:
        kwargs['filter_arg'] = 'tcp or udp'
        super().__init__(*args, **kwargs)

    

    def manage(self, packet):
        print(f"p: {packet}")