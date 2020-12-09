from abc import ABC, abstractmethod
class USBHIDListener(ABC):

    @abstractmethod
    def received_packet(self, packet):
        pass

    @abstractmethod
    def response_sent(self, transaction):
        pass
