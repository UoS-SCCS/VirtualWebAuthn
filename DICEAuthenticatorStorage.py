from abc import ABC, abstractmethod
import logging
from PublicKeyCredentialSource import PublicKeyCredentialSource

class DICEAuthenticatorStorage:

    def __init__(self):
        pass

    @abstractmethod
    def is_initialised(self)->bool:
        pass

    @abstractmethod
    def get_master_secret(self)->bytes:
        pass

    @abstractmethod
    def init_new(self,master_secret:bytes):
        pass

    @abstractmethod
    def get_signature_counter(self)->int:
        pass

    @abstractmethod
    def update_signature_counter(self, new_counter:int)->bool:
        pass

    @abstractmethod
    def increment_signature_counter(self)->bool:
        pass

    @abstractmethod
    def add_credential_source(self,rp_id:str,user_id:bytes, credential_source:PublicKeyCredentialSource)->bool:
        pass

    @abstractmethod
    def get_credential_source(self,rp_id:str,user_id:bytes)->PublicKeyCredentialSource:
        pass

    @abstractmethod
    def get_credential_by_rp(self,rp_id:str, allow_list=None)->{PublicKeyCredentialSource}:
        pass
    
    @abstractmethod
    def get_pin_retries(self)->int:
        pass

    @abstractmethod
    def get_pin(self)->bytes:
        pass

    @abstractmethod
    def set_pin_retries(self)->int:
        pass
    
    @abstractmethod
    def set_pin(self, pin:bytes):
        pass

    @abstractmethod
    def decrement_pin_retries(self)->int:
        pass

    @abstractmethod
    def reset(self)->bool:
        pass
    
    def convert_allow_list_to_map(self, allow_list):
        allow = {}
        for allowed in allow_list:
            allow[allowed["id"]]=allowed["type"]
        return allow
class DICEAuthenticatorStorageException(Exception):
    """Exception raised when accessing the storage medium

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message="Storage Exception"):
        self.message = message
        super().__init__(self.message)
    