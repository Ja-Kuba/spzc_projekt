from scapy.layers.l2 import Ether
from threading import Thread
from queue import Queue
from time import sleep




# Base interface for processor
class PacketProcessor():
    def __init__(self) -> None:
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
    

    def onPacket(self, packet:Ether):
        self.pushPacket(packet)


    def pushPacket(self, packets:Ether):
        self.queue.put(packets)


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
    def processPacket(self, packet):
        print(f"P: {packet}")


    def __threadLoop(self, queue):
        while self.run:
            if queue.empty():
                sleep(1)
                continue
            packet = queue.get()
            self.processPacket(packet)
        
        print(f"{self.name} THREAD STOPPED")


