from abc import ABC, abstractmethod
from scapy.layers.l2 import Ether
import scapy.all as scapy

from threading import Thread, Event
from queue import Queue
from time import sleep


# Base interface for processor
class PacketProcessor():
    def __init__(self) -> None:
        super().__init__()
        self.name= "BASE_PROCESSOR"
        self.run = True
        self.queue = Queue()
        self.thread = self.runPorcessThread()

    def __del__(self):
        if self.thread:
            self.join_thread()

    def ifRunning(self):
        if not self.thread:
            raise AssertionError("Thread not running")
    


    def pushPackets(self, packets:list):
        self.queue.put(packets)


    def process(self, packets:list):
        self.pushPackets(packets)
        




    def stop(self):
        self.run = False
    

    def join_thread(self):
        self.thread.join()
        self.thread = None
    

    def runPorcessThread(self):
        self.thread= Thread(target=self.__threadLoop, args=(self.queue,))
        self.thread.start()


    #
    #  Thread functions should not be called from outside
    #
    def processJob(self, job):
            for p in job:
                print(f"P: {p}")


    def __threadLoop(self, queue):
        while self.run:
            if queue.empty():
                sleep(1)
                continue
            job = queue.get()
            self.processJob(job)
        
        print(f"{self.name} THREAD STOPPED")



#-----------------------------------------------------
# Dev processor
class DevProcessor(PacketProcessor):
    def __init__(self) -> None:
        super().__init__()
        

    def process(self, packet:Ether):
        #self.printPacket(packet)
        #self.saveToPcap(packet)
        pass
    
    
    def processJob(self, job):
        super().processJob(job)
                  


    def saveToPcap(self,packets):
        scapy.wrpcap('sniffed.pcap', packets, append=True)


    def printPacket(self, packet):
        print('-----------------------')
        print("1: ",packet)
        print("2: ",packet.summary)
        print("3: ",packet[Ether].src)
