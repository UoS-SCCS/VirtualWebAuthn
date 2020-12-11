"""Listener abstract class

This needs to be in its only module due to issues
with circular references
"""
from abc import ABC, abstractmethod
from hid.packets import HIDPacket
from ctap.transaction import CTAPHIDTransaction
class USBHIDListener(ABC):
    """Abstract listener class to receive packets and
    notifications of when packets have been written.

    """
    @abstractmethod
    def received_packet(self, packet:HIDPacket):
        """Fired when an HIDPacket has been received

        Args:
            packet (HIDPacket): packet that has been received
        """

    @abstractmethod
    def response_sent(self, transaction:CTAPHIDTransaction):
        """Fired when the response has been set indicating the
        transaction is now complete

        Args:
            transaction (CTAPHIDTransaction): transaction from which
                the response was sent
        """
