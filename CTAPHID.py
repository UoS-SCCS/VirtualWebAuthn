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
from CTAPHIDMsg import CTAPHIDWinkRequest
from CTAPHIDMsg import CTAPHIDWinkResponse
from CTAPHIDMsg import CTAPHIDErrorResponse
from CTAPHIDMsg import CTAPHIDKeepAliveResponse
from DICEAuthenticator import DICEAuthenticator
from CTAPHIDKeepAlive import CTAPHIDKeepAlive
from DICEAuthenticator import DICEAuthenticatorException
from abc import ABC, abstractmethod

log = logging.getLogger('debug')
ctap = logging.getLogger('debug.ctap')
auth = logging.getLogger('debug.auth')


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
        log.debug("Authenticator set: %s",self._authenticator )

    def channel_exists(self, channel_id):
        return channel_id in self._channels
    
    def get_channel(self, channel_id):
        return self._transaction
        #if not channel_id in self._channels:
        #    raise ChannelNotFoundException("Channel not found")
        #return self._channels.get(channel_id)

    def received_packet(self, packet: HIDPacket):
        if packet.CMDTYPE == CTAPHIDConstants.CMD_TYPE.INITIALIZATION:
            log.debug("Received initialization packet")
                    
            ctap_msg = CTAPHIDCMD.create_message(packet)
            ctap.debug("Received initialization packet: %s", ctap_msg)
            self._keepAlive.set_CID(ctap_msg.get_CID())
            if not self._transaction == None and not ctap_msg.get_CID() == self._transaction.get_channel_id():
                self.send_error_response(CTAPHIDErrorResponse(ctap_msg.get_CID(),CTAPHIDConstants.CTAPHID_ERROR.ERR_CHANNEL_BUSY), True)
            else:
                self._transaction = CTAPHIDTransaction(ctap_msg.get_CID())
                self._transaction.set_request(ctap_msg)
                ctap.debug("Created transaction: %s", self._transaction)
        elif packet.CMDTYPE == CTAPHIDConstants.CMD_TYPE.CONTINUATION:
            ctap.debug("Received Continuation Packet - seqNo: %s", packet.get_sequence())
            self._transaction.request.append_continuation_packet(packet)
        
        #If we have finished receiving packets, process the request
        if self._transaction.request.is_complete(): 
            ctap.debug("Message is complete: %s", self._transaction)
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
            elif self._transaction.request.get_CMD() == CTAPHIDConstants.CTAP_CMD.CTAPHID_WINK:
                self.process_wink_request(self._transaction.request)
        else:
            ctap.debug("Message incomplete remaining bytes: %s", self._transaction.request.remaining_bytes)
        
    def send_error_response(self, msg_response: CTAPHIDErrorResponse, is_init_error:bool=False):
        ctap.debug("Sending error response: %s", msg_response)
        
        if not self._transaction == None and is_init_error == False:
            self._transaction.error(msg_response)
            self.send_response(self._transaction) 
        else:
            temp_transaction = CTAPHIDTransaction(msg_response.get_CID())
            temp_transaction.error(msg_response)
            self.send_response(temp_transaction) 
    
    def send_keep_alive_response(self, msg_response: CTAPHIDKeepAliveResponse):
        temp_transaction = CTAPHIDTransaction(msg_response.get_CID())
        temp_transaction.error(msg_response)
        self.send_response(temp_transaction) 
    
    def process_cancel_request(self, msg_request: CTAPHIDCancelRequest):
        ctap.debug("Received cancel request: %s", msg_request)
        if self.channel_exists(msg_request.get_CID()) == False:
            self.send_error_response(CTAPHIDErrorResponse(msg_request.get_CID(),CTAPHIDConstants.CTAPHID_ERROR.ERR_INVALID_CHANNEL))
        else:
            if msg_request.is_complete():
                response = CTAPHIDCancelResponse(self._transaction.get_CID())
                self._transaction.cancel(response)
                self.send_response(self._transaction)
    
    def process_wink_request(self, msg_request: CTAPHIDWinkRequest):
        ctap.debug("Received Wink request: %s", msg_request)
        if self.channel_exists(msg_request.get_CID()) == False:
            self.send_error_response(CTAPHIDErrorResponse(msg_request.get_CID(),CTAPHIDConstants.CTAPHID_ERROR.ERR_INVALID_CHANNEL))
        else:
            
            transaction  = self.get_channel(msg_request.get_CID())
            #transaction.set_request(msg_request)
            if not self._authenticator is None:
                #TODO add try catch to return error status code
                try:
                    resp = self._authenticator.process_wink(msg_request.get_payload(), self._keepAlive)
                    transaction.set_response(CTAPHIDWinkResponse(self._transaction.get_CID(),resp))
                    self.send_response(transaction)
                except DICEAuthenticatorException as e:
                    auth.error("Exception from authenticator",exc_info=True)
                    self.send_error_response(CTAPHIDErrorResponse(msg_request.get_CID(),e.get_error_code()))

    def process_ping_request(self, msg_request: CTAPHIDPingRequest):
        ctap.debug("Received ping request: %s", msg_request)
        if self.channel_exists(msg_request.get_CID()) == False:
            self.send_error_response(CTAPHIDErrorResponse(msg_request.get_CID(),CTAPHIDConstants.CTAPHID_ERROR.ERR_INVALID_CHANNEL))
        else:
            transaction  = self.get_channel(msg_request.get_CID())
            #transaction.set_request(msg_request)
            if msg_request.is_complete():
                response = CTAPHIDPingResponse(self._transaction.get_CID(),transaction.request.get_payload())
                transaction.set_response(response)
                self.send_response(transaction)

    def process_cbor_request(self, msg_request: CTAPHIDCBORRequest):
        ctap.debug("Received CBOR request: %s", msg_request)
        if self.channel_exists(msg_request.get_CID()) == False:
            self.send_error_response(CTAPHIDErrorResponse(msg_request.get_CID(),CTAPHIDConstants.CTAPHID_ERROR.ERR_INVALID_CHANNEL))
        else:
            
            transaction  = self.get_channel(msg_request.get_CID())
            #transaction.set_request(msg_request)
            if not self._authenticator is None:
                #TODO add try catch to return error status code
                try:
                    resp = self._authenticator.process_cbor(msg_request.get_payload(), self._keepAlive)
                    transaction.set_response(CTAPHIDCBORResponse(self._transaction.get_CID(),CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_OK,resp))
                    self.send_response(transaction)
                except DICEAuthenticatorException as e:
                    auth.error("Exception from authenticator", exc_info=True)
                    self.send_error_response(CTAPHIDErrorResponse(msg_request.get_CID(),e.get_error_code()))
                    #transaction.reset()
            

    
    def process_msg_request(self, msg_request: CTAPHIDMsgRequest):
        ctap.debug("Received MSG request: %s", msg_request)
        if self.channel_exists(msg_request.get_CID()) == False:
            self.send_error_response(CTAPHIDErrorResponse(msg_request.get_CID(),CTAPHIDConstants.CTAPHID_ERROR.ERR_INVALID_CHANNEL))
        else:
            transaction  = self.get_channel(msg_request.get_CID())
            
            #transaction.set_request(msg_request)
            

    def process_init_request(self, init_request: CTAPHIDInitRequest):
        ctap.debug("Received INIT request: %s", init_request)
        if init_request.get_CID() == self._BROADCAST_ID:
            channel_id = self.create_channel_id()
            #self._transaction.set_request(init_request)
            response = CTAPHIDInitResponse(self._authenticator.get_version())
            response.set_nonce(init_request.get_payload())
            response.set_channel_id(channel_id)
            self._transaction.set_response(response)
            self.send_response(self._transaction)
        else:
            ctap.debug("Channel exists, resync channel")
            self._transaction.reset()
            response = CTAPHIDInitResponse(self._authenticator.get_version())
            response.set_nonce(init_request.get_payload())
            response.set_channel_id(init_request.get_CID())
            self._transaction.set_response(response)
            self.send_response(self._transaction)

    def response_sent(self, transaction: CTAPHIDTransaction):
        ctap.debug("Response sent. Resetting transaction to idle state - isError:%s, %s", transaction.is_error_transaction(), transaction)
        if transaction == self._transaction:
            #Return to idle state
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

    def send_response(self, transaction: CTAPHIDTransaction):
        self._usbhid.add_transaction_to_queue(transaction)

    
