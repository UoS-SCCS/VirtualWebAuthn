from abc import ABC, abstractmethod
import logging
from fido2.cose import CoseKey, ES256, RS256, UnsupportedKey
from cryptography.hazmat.backends import default_backend
    
class AuthenticatorCryptoPublicKey:
    def __init__(self, public_key):
        self._pk = public_key
    
    def get_public_key(self):
        return self._pk
    
    @abstractmethod
    def get_encoded(self)->bytes:
        pass 

    @abstractmethod
    def get_as_cose(self):
        pass

class AuthenticatorCryptoPrivateKey:
    def __init__(self, private_key):
        self._sk = private_key
    
    def get_private_key(self):
        return self._sk

    @abstractmethod
    def get_encoded(self)->bytes:
        pass
        
class AuthenticatorCryptoKeyPair:
    def __init__(self, public_key:AuthenticatorCryptoPublicKey, private_key:AuthenticatorCryptoPrivateKey):
        self._pk = public_key
        self._sk = private_key
    
    def get_public_key(self)->AuthenticatorCryptoPublicKey:
        return self._pk
    
    def get_private_key(self)->AuthenticatorCryptoPrivateKey:
        return self._sk
    
    @abstractmethod
    def get_encoded(self)->bytes:
        #This might encode just the private key if the public key can be derived from solely the public key
        pass
    

CRYPTO_PROVIDERS = {}
class AuthenticatorCryptoProvider:
    
    def __init__(self):
        self._alg = None
        
    def get_alg(self):
        return self._alg

    @classmethod
    def add_provider(cls,provider):
        CRYPTO_PROVIDERS[provider.get_alg()]=provider

    @abstractmethod
    def create_new_key_pair(self)->AuthenticatorCryptoKeyPair:
        pass

    @abstractmethod
    def load_key_pair(self, data:bytes)->AuthenticatorCryptoKeyPair:
        pass
    
    @abstractmethod
    def public_key_from_cose(self, cose_data:{})->AuthenticatorCryptoPublicKey:
        pass