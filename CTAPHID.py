from USBHID import USBHIDListener
from HIDPacket import HIDPacket
import CTAPHIDConstants
import logging
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
from CTAPHIDMsg import CTAPHIDErrorResponse
from CTAPHIDMsg import CTAPHIDKeepAliveResponse
from DICEAuthenticator import DICEAuthenticator
from CTAPHIDKeepAlive import CTAPHIDKeepAlive
from abc import ABC, abstractmethod




class CTAPHID(USBHIDListener):
    _BROADCAST_ID = b'\xff\xff\xff\xff'
    def __init__(self, usbhid):
        self._usbhid = usbhid
        self._channels = {}
        self._transaction = None
        self._authenticator:DICEAuthenticator = None
        self._keepAlive = CTAPHIDKeepAlive(self)

    def set_authenticator(self, authenticator:DICEAuthenticator):
        self._authenticator=authenticator
        print("Set Authenticator")
        print(self._authenticator)

    def channel_exists(self, channel_id):
        return channel_id in self._channels
    
    def get_channel(self, channel_id):
        return self._transaction
        #if not channel_id in self._channels:
        #    raise ChannelNotFoundException("Channel not found")
        #return self._channels.get(channel_id)

    def received_packet(self, packet: HIDPacket):
        logging.debug("Received Packet")
        if packet.CMDTYPE == CTAPHIDConstants.CMD_TYPE.INITIALIZATION:
            
            
            logging.debug("Packet is Initialization")
            ctap_msg = CTAPHIDCMD.create_message(packet)
            self._keepAlive.set_CID(ctap_msg.get_CID())
            logging.debug("Packet is size: %s", ctap_msg.get_length())
            if not self._transaction == None and not ctap_msg.get_CID() == self._transaction.get_channel_id():
                self.send_error_response(CTAPHIDErrorResponse(ctap_msg.get_CID(),CTAPHIDConstants.CTAPHID_ERROR.ERR_CHANNEL_BUSY))
            else:
                logging.debug("Created transaction")
                self._transaction = CTAPHIDTransaction(ctap_msg.get_CID())
                self._transaction.set_request(ctap_msg)
        elif packet.CMDTYPE == CTAPHIDConstants.CMD_TYPE.CONTINUATION:
            logging.debug("Received Continuation Packet: %s", packet.get_sequence())
            self._transaction.request.append_continuation_packet(packet)
        logging.debug("Is message complete: %s", self._transaction.request.is_complete())
        logging.debug("Message remaining bytes: %s", self._transaction.request.remaining_bytes)
        #If we have finished receiving packets, process the request
        if self._transaction.request.is_complete(): 
            if self._transaction.request.get_CMD() == CTAPHIDConstants.CTAP_CMD.CTAPHID_INIT:
                self.process_init_request(self._transaction.request)
            elif self._transaction.request.get_CMD() == CTAPHIDConstants.CTAP_CMD.CTAPHID_MSG:
                self.process_msg_request(self._transaction.request)
            elif self._transaction.request.get_CMD() == CTAPHIDConstants.CTAP_CMD.CTAPHID_CBOR:
                self.process_cbor_request(self._transaction.request)
            elif self._transaction.request.get_CMD() == CTAPHIDConstants.CTAP_CMD.CTAPHID_PING:
                self.process_ping_request(self._transaction.request)
            elif self._transaction.request.get_CMD() == CTAPHIDConstants.CTAP_CMD.CTAPHID_CANCEL:
                self.process_cancel_request(self._transaction.request)

    def send_error_response(self, msg_response: CTAPHIDErrorResponse):
        temp_transaction = CTAPHIDTransaction(msg_response.get_CID())
        temp_transaction.error(msg_response)
        self.send_response(temp_transaction) 
    
    def send_keep_alive_response(self, msg_response: CTAPHIDKeepAliveResponse):
        temp_transaction = CTAPHIDTransaction(msg_response.get_CID())
        temp_transaction.error(msg_response)
        self.send_response(temp_transaction) 
    
    def process_cancel_request(self, msg_request: CTAPHIDCancelRequest):
        if self.channel_exists(msg_request.get_CID()) == False:
            #send error
            pass
        else:
            if msg_request.is_complete():
                response = CTAPHIDCancelResponse(self._transaction.get_CID())
                self._transaction.cancel(response)
                self.send_response(self._transaction)

    def process_ping_request(self, msg_request: CTAPHIDPingRequest):
        if self.channel_exists(msg_request.get_CID()) == False:
            #send error
            pass
        else:
            transaction  = self.get_channel(msg_request.get_CID())
            #transaction.set_request(msg_request)
            if msg_request.is_complete():
                response = CTAPHIDPingResponse(self._transaction.get_CID(),transaction.request.get_payload())
                transaction.set_response(response)
                self.send_response(transaction)

    def process_cbor_request(self, msg_request: CTAPHIDCBORRequest):
        if self.channel_exists(msg_request.get_CID()) == False:
            #send error
            pass
        else:
            
            transaction  = self.get_channel(msg_request.get_CID())
            #transaction.set_request(msg_request)
            if not self._authenticator is None:
                #TODO add try catch to return error status code
                resp = self._authenticator.process_cbor(msg_request.get_payload(), self._keepAlive)
                print(resp)
                transaction.set_response(CTAPHIDCBORResponse(self._transaction.get_CID(),CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_OK,resp))
                self.send_response(transaction)
                
            

    
    def process_msg_request(self, msg_request: CTAPHIDMsgRequest):
        if self.channel_exists(msg_request.get_CID()) == False:
            #send error
            pass
        else:
            transaction  = self.get_channel(msg_request.get_CID())
            logging.debug("Received CTAPHID MSG: %s", transaction)
            #transaction.set_request(msg_request)
            

    def process_init_request(self, init_request: CTAPHIDInitRequest):
        
        if init_request.get_CID() == self._BROADCAST_ID:
            channel_id = self.create_channel_id()
            #self._transaction.set_request(init_request)
            response = CTAPHIDInitResponse()
            response.set_nonce(init_request.get_payload())
            response.set_channel_id(channel_id)
            self._transaction.set_response(response)
            self.send_response(self._transaction)
        else:
            #TODO reset channel
            pass

    def response_sent(self, transaction: CTAPHIDTransaction):
        logging.debug("Response set resetting transaction: %s, %s, %s", transaction.is_error_transaction(),transaction,self._transaction)
        if not transaction.is_error_transaction() and transaction == self._transaction:
            #Return to idle state
            logging.debug("Returning to idle state")
            self._transaction.reset()
            self._transaction = None
        else:
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
        self._channels[channel_id]=None
        return channel_id
        
    def _get_sequence(self, bytes):
        #self._message_length = int.from_bytes(bytes[5:6], "big")
        pass

    def send_response(self, transaction: CTAPHIDTransaction):
        self._usbhid.add_transaction_to_queue(transaction)

    
