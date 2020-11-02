from abc import ABC, abstractmethod
from CTAPHID import CTAPHIDTransaction
class DICEKey:

    def __init__(self, ctap_hid:CTAPHID):
        self._ctap_hid = ctap_hid
    
    @abstractmethod
    def process_CTAPHID_MSG(self, transaction:CTAPHIDTransaction):
        pass
    
    @abstractmethod
    def process_CTAPHID_CBOR(self, transaction:CTAPHIDTransaction):
        pass

     @abstractmethod
    def process_CTAPHID_PING(self, transaction:CTAPHIDTransaction):
        pass

     @abstractmethod
    def process_CTAPHID_CANCEL(self, transaction:CTAPHIDTransaction):
        pass

     @abstractmethod
    def process_CTAPHID_ERROR(self, transaction:CTAPHIDTransaction):
        pass
    
     @abstractmethod
    def process_CTAPHID_KEEPALIVE(self, transaction:CTAPHIDTransaction):
        pass
