from USBHID import USBHIDListener
from HIDPacket import HIDPacket
import CTAPHIDConstants

from CTAPHIDMsg import CTAPHIDCMD
from queue import SimpleQueue
from CTAPHIDTransaction import CTAPHIDTransaction
import os
from CTAPHIDExceptions import ChannelNotFoundException
from CTAPHIDMsg import CTAPHIDInitRequest
from CTAPHIDMsg import CTAPHIDInitResponse
from CTAPHIDMsg import CTAPHIDMsgRequest
from CTAPHIDMsg import CTAPHIDMsgResponse
from CTAPHIDMsg import CTAPHIDCBORRequest
from CTAPHIDMsg import CTAPHIDCBORResponse
from CTAPHIDMsg import CTAPHIDPingRequest
from CTAPHIDMsg import CTAPHIDPingResponse
from CTAPHIDMsg import CTAPHIDCancelRequest
from CTAPHIDMsg import CTAPHIDCancelResponse
from abc import ABC, abstractmethod
class CTAPHID(USBHIDListener):
    _BROADCAST_ID = b'\xff\xff\xff\xff'
    def __init__(self, usbhid):
        self._usbhid = usbhid
        self._channels = {}

    def channel_exists(self, channel_id):
        return channel_id in self._channels
    
    def get_channel(self, channel_id):
        if not channel_id in self._channels:
            raise ChannelNotFoundException("Channel not found")
        return self._channels.get(channel_id)

    def received_packet(self, packet: HIDPacket):
        #TODO add listener code
        if packet.CMDTYPE == CTAPHIDConstants.CMD_TYPE.INITIALIZATION:
            ctap_msg = CTAPHIDCMD.create_message(packet)
            if ctap_msg.is_complete() and ctap_msg.get_CMD() == CTAPHIDConstants.CTAP_CMD.CTAPHID_INIT:
                self.process_init_request(ctap_msg)
            elif ctap_msg.get_CMD() == CTAPHIDConstants.CTAP_CMD.CTAPHID_MSG:
                self.process_msg_request(ctap_msg)
            elif ctap_msg.get_CMD() == CTAPHIDConstants.CTAP_CMD.CTAPHID_CBOR:
                self.process_cbor_request(ctap_msg)
            elif ctap_msg.get_CMD() == CTAPHIDConstants.CTAP_CMD.CTAPHID_PING:
                self.process_ping_request(ctap_msg)
            elif ctap_msg.get_CMD() == CTAPHIDConstants.CTAP_CMD.CTAPHID_CANCEL:
                self.process_cancel_request(ctap_msg)

    def process_cancel_request(self, msg_request: CTAPHIDCancelRequest):
        if self.channel_exists(msg_request.get_CID()) == False:
            #send error
            pass
        else:
            transaction  = self.get_channel(msg_request.get_CID())
            if msg_request.is_complete():
                response = CTAPHIDCancelResponse(transaction.get_CID())
                transaction.cancel(response)
                self.send_response(transaction)
    
    def process_ping_request(self, msg_request: CTAPHIDPingRequest):
        if self.channel_exists(msg_request.get_CID()) == False:
            #send error
            pass
        else:
            transaction  = self.get_channel(msg_request.get_CID())
            transaction.set_request(msg_request)
            if msg_request.is_complete():
                response = CTAPHIDPingResponse(transaction.get_CID(),transaction.request.get_payload())
                transaction.set_response(response)
                self.send_response(transaction)

    def process_cbor_request(self, msg_request: CTAPHIDCBORRequest):
        if self.channel_exists(msg_request.get_CID()) == False:
            #send error
            pass
        else:
            transaction  = self.get_channel(msg_request.get_CID())
            transaction.set_request(msg_request)
    
    def process_msg_request(self, msg_request: CTAPHIDMsgRequest):
        if self.channel_exists(msg_request.get_CID()) == False:
            #send error
            pass
        else:
            transaction  = self.get_channel(msg_request.get_CID())
            transaction.set_request(msg_request)
            

    def process_init_request(self, init_request: CTAPHIDInitRequest):
        
        if init_request.get_CID() == self._BROADCAST_ID:
            transaction = self.create_channel_id()
            transaction.set_request(init_request)
            response = CTAPHIDInitResponse()
            response.set_nonce(init_request.get_payload())
            response.set_channel_id(transaction.get_channel_id())
            transaction.set_response(response)
            self.send_response(transaction)
        else:
            #TODO reset channel
            pass

    def response_sent(self, transaction: CTAPHIDTransaction):
        transaction.reset()
        
    def create_channel_id(self):
        # TODO How do channel IDs get recycled?
        channel_id = bytes(os.urandom(4))
        runaway_counter=0
        while channel_id in self._channels:
            runaway_counter += 1
            channel_id = bytes(os.urandom(4))
            if runaway_counter>1000:
                raise Exception("Attempted to generate a channel id 1000 times and failed to find a unique ID")
        self._channels[channel_id]=CTAPHIDTransaction(channel_id)
        return self._channels[channel_id]
        
    def _get_sequence(self, bytes):
        #self._message_length = int.from_bytes(bytes[5:6], "big")
        pass

    def send_response(self, transaction: CTAPHIDTransaction):
        self._usbhid.add_transaction_to_queue(transaction)

    
