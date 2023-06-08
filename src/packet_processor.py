from scapy.layers.l2 import Ether
from threading import Thread
from queue import Queue
from time import sleep


# Base interface for processor
class PacketProcessor:
    def __init__(self) -> None:
        self.name = "BASE_PROCESSOR"
        self.run = True
        self.queue = Queue()
        self.thread = self.run_process_thread()

    def __del__(self):
        if self.thread:
            self.join_thread()

    def if_running(self):
        if not self.thread:
            raise AssertionError("Thread not running")

    def on_packet(self, packet: Ether):
        self.push_packet(packet)

    def push_packet(self, packets: Ether):
        self.queue.put(packets)

    def stop(self):
        self.run = False

    def join_thread(self):
        self.thread.join()
        self.thread = None

    def run_process_thread(self):
        self.thread = Thread(target=self.__thread_loop, args=(self.queue,))
        self.thread.start()

    #
    #  Thread functions should not be called from outside
    #
    def process_packet(self, packet):
        print(f"P: {packet}")

    def __thread_loop(self, queue):
        while self.run:
            if queue.empty():
                sleep(1)
                continue
            packet = queue.get()
            self.process_packet(packet)

        print(f"{self.name} THREAD STOPPED")
