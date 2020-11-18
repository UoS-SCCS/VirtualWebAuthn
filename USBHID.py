import threading
from abc import ABC, abstractmethod
from HIDPacket import HIDPacket
from CTAPHIDTransaction import CTAPHIDTransaction
from queue import Queue
import sys
import traceback
import os
import logging

log = logging.getLogger('debug')
usblog = logging.getLogger('debug.usbhid')
class USBHID:
    
    def __init__(self, device):
        self._device = device
        self._is_listening = False
        self._listener = None
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
        log.debug("Started listening threads")

    def add_transaction_to_queue(self, transaction: CTAPHIDTransaction):
        log.debug("Transaction added to write queue: %s",transaction)
        self._write_queue.put(transaction)

    def set_listener(self, listener):
        log.debug("listener added %s", listener)
        self._listener = listener
    
    def remove_listener(self, listener):
        log.debug("listener removed %s", listener)
        self._listener = None

    def shutdown(self):
        self._running = False
        log.debug("Shutdown called")
        

    def _write(self):
        while True:
            transaction = self._write_queue.get()
            usblog.debug("Got transaction to write %s",transaction)
            packets = transaction.response.get_HID_packets()
            for packet in packets:
                usblog.debug("\twriting bytes from packet: %s", packet.get_bytes().hex())
                os.write(self._device, packet.get_bytes())
            usblog.debug("Finished writing transaction")
            self._listener.response_sent(transaction)
            

    def _listen(self):
        while self._running:
            try:
                hid_packet = HIDPacket.from_bytes(os.read(self._device,64))
                #hid_packet = HIDPacket.from_bytes(self._device.read(64))
                usblog.debug("Received hid packet: %s",hid_packet)
                self._listener.received_packet(hid_packet)
            except Exception:
                log.error("Exception reading from device")   
        log.debug("USBHID no longer listening")

        
class USBHIDListener(ABC):

    @abstractmethod
    def received_packet(self, packet):
        pass

    @abstractmethod
    def response_sent(self, transaction):
        pass




