
from abc import ABC, abstractmethod
from enum import Enum, unique
from CTAPHIDExceptions import TransactionStateException, TransactionChannelIDException
import CTAPHIDConstants

from CTAPHIDMsg import CTAPHIDCMD, CTAPHIDInitRequest, CTAPHIDInitResponse, CTAPHIDCancelResponse, CTAPHIDErrorResponse
from HIDPacket import HIDPacket

@unique
class TRANSACTION_STATE(Enum):
    EMPTY = 0
    REQUEST_RECV = 1
    RESPONSE_SET = 2
    CANCEL = 8
    ERROR = 9

class CTAPHIDTransaction:
    def __init__(self, channel_id:bytes):
        self.request = None
        self.response = None
        self.state = TRANSACTION_STATE.EMPTY        
        self.channel_id = channel_id
         
    def get_channel_id(self):
        return self.channel_id

    def get_CID(self):
        return self.channel_id
    def is_error_transaction(self):
        return (self.state == TRANSACTION_STATE.ERROR)
        

    def set_request(self, request: CTAPHIDCMD):
        if not self.verify_state(TRANSACTION_STATE.REQUEST_RECV):
            print("State:%s",self.state)
            raise TransactionStateException("Invalid state, cannot set request")
        if request.get_CID() != CTAPHIDConstants.BROADCAST_ID and request.get_CID() != self.channel_id:
            raise TransactionChannelIDException("Invalid channel ID for transaction")
        self.state = TRANSACTION_STATE.REQUEST_RECV
        self.request = request
        
    def set_response(self, response: CTAPHIDCMD):
        if not self.verify_state(TRANSACTION_STATE.RESPONSE_SET):
            raise TransactionStateException("Invalid state, cannot set response")
        if response.get_CID() != CTAPHIDConstants.BROADCAST_ID and response.get_CID() != self.channel_id:
            raise TransactionChannelIDException("Invalid channel ID for transaction")
        self.state = TRANSACTION_STATE.REQUEST_RECV
        self.response = response

    def reset(self):
        self.request = None
        self.response = None
        self.state = TRANSACTION_STATE.EMPTY

    def cancel(self, response: CTAPHIDCancelResponse):
        self.reset()
        self.state = TRANSACTION_STATE.CANCEL
        self.response = response

    def error(self, response: CTAPHIDCancelResponse):
        self.reset()
        self.state = TRANSACTION_STATE.ERROR
        self.response = response


    def verify_state(self, target_state: TRANSACTION_STATE):
        """Verifies the state machine of the CTAP HID Transaction.

        If a request has been received it must be followed by a response being
        sent before the next request can be received.

        Parameters
        ----------
        target_state : TRANSACTION_STATE
            Enum of target transaction state
        
        Returns
        -------
        bool
            True if valid, False if not
        """
        if target_state.value == (self.state.value + 1) and target_state.value <= TRANSACTION_STATE.RESPONSE_SET.value:
            return True
        else:
            return False


