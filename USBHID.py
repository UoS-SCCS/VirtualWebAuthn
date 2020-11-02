import threading
from abc import ABC, abstractmethod
from HIDPacket import HIDPacket
from CTAPHIDTransaction import CTAPHIDTransaction
from queue import Queue
import sys
import traceback
import os
import logging
class USBHID:
    
    def __init__(self, device):
        self._device = device
        self._is_listening = False
        self._listeners = set()
        self._running = False
        self._packets = {}
        self._write_queue = Queue()

    def start(self):
        if self._is_listening:
            return Exception("start_listening can only be called once")
        self._is_listening = True
        self._running = True
        self._read_thread = threading.Thread(target=self._listen)
        self._read_thread.setDaemon(True)
        self._read_thread.start()
        self._write_thread = threading.Thread(target=self._write)
        self._write_thread.setDaemon(True)
        self._write_thread.start()

    def add_transaction_to_queue(self, transaction: CTAPHIDTransaction):
        self._write_queue.put(transaction)

    def add_listener(self, listener):
        logging.debug("listener added %s", listener)
        self._listeners.add(listener)
    
    def remove_listener(self, listener):
        logging.debug("listener removed %s", listener)
        self._listeners.remove(listener)

    def shutdown(self):
        self._running = False
        logging.debug("Shutdown called")
        

    def _write(self):
        while True:
            transaction = self._write_queue.get()
            logging.debug("Got transaction to write %s",transaction)
            packets = transaction.response.get_HID_packets()
            for packet in packets:
                logging.debug("writing bytes from packet: %s", packet.get_bytes())

                os.write(self._device, packet.get_bytes())
                #self._device.write(packet.get_bytes())
                logging.debug("Finished writing")
                #self._device.flush()
            for listener in self._listeners: 
                listener.response_sent(transaction)

    def _listen(self):
        while self._running:
            try:
                hid_packet = HIDPacket.from_bytes(os.read(self._device,64))
                #hid_packet = HIDPacket.from_bytes(self._device.read(64))
                logging.debug("Received data %s", hid_packet)
                for listener in self._listeners: 
                    listener.received_packet(hid_packet)
            except Exception as e:
                print("Exception reading from device")
                traceback.print_exc()
                print(e)
        print("USBHID no longer listening")

        
class USBHIDListener(ABC):

    @abstractmethod
    def received_packet(self, packet):
        pass

    @abstractmethod
    def response_sent(self, transaction):
        pass




