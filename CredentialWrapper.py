from abc import ABC, abstractmethod
from PublicKeyCredentialSource import PublicKeyCredentialSource
class CredentialWrapper:
    def __init__(self):
        self.name = "Base"

    @abstractmethod
    def wrap(self, key:bytes, credential:PublicKeyCredentialSource)->bytes:
        pass
    
    @abstractmethod
    def unwrap(self, key:bytes, wrapped_credential:bytes)->PublicKeyCredentialSource:
        pass

    @abstractmethod
    def generate_key(self)->bytes:
        pass