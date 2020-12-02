from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.backends import default_backend
from abc import ABC, abstractmethod
from PublicKeyCredentialSource import PublicKeyCredentialSource
from CredentialWrapper import CredentialWrapper
import os
class AESCredentialWrapper(CredentialWrapper):
    def __init__(self):
        super().__init__()
        self.name = "AES"
    
    def wrap(self, key:bytes, credential:PublicKeyCredentialSource)->bytes:
        return keywrap.aes_key_wrap_with_padding(key,credential.get_bytes(True),default_backend())
    
    def unwrap(self, key:bytes, wrapped_credential:bytes)->PublicKeyCredentialSource:
        unwrapped = keywrap.aes_key_unwrap_with_padding(key,wrapped_credential,default_backend())
        cred = PublicKeyCredentialSource()
        cred.from_bytes(unwrapped,True)
        cred.set_id(wrapped_credential)
        return cred
    
    def generate_key(self)->bytes:
        return os.urandom(32)