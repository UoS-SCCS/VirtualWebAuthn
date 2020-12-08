import os
import logging
import json
from AuthenticatorCryptoProvider import AuthenticatorCryptoKeyPair
from AuthenticatorCryptoProvider import CRYPTO_PROVIDERS
from CTAPHIDConstants import AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR
from CTAPHIDConstants import PUBLICKEY_CREDENTIAL_USER_ENTITY
from CTAPHIDConstants import AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE

import CTAPHIDConstants

log = logging.getLogger('debug')

#TODO Move string to constants
class PublicKeyCredentialSource():
    def __init__(self):
        self._alg = None
        self._type="public-key"
        self._id=None
        self._rp_id=None
        self._sk = None
        self._keypair = None
        self._user_handle = None
        self._other_ui=None
        self._signature_counter= b'\x00\x00\x00\x00'.hex()

    #TODO user_entity should be PublicKeyCredentialUserEntity but that creates a circular reference
    def init_new(self,alg, key_pair:AuthenticatorCryptoKeyPair, rp_id, user_entity,keytype="public-key"):
        self._alg=alg
        self._type=keytype
        self.generate_id()
        self._rp_id = rp_id
        self._keypair = key_pair
        self._user_handle = user_entity.get_id()
        other_ui = user_entity.get_as_dict()
        other_ui.pop(PUBLICKEY_CREDENTIAL_USER_ENTITY.ID.value)
        self._other_ui=other_ui
    def generate_id(self):
        self._id=os.urandom(CTAPHIDConstants.CREDENTIAL_ID_SIZE)
    
    def get_alg(self):
        return self._alg

    def get_bytes(self, without_id=False)->bytes:
        data = {}
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.TYPE.value] = self._type
        if not without_id:
            data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.ID.value] = self._id.hex()
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.ALG.value] = self._alg
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.RP_ID.value] = self._rp_id
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.USER_HANDLE.value] = self._user_handle.hex()
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.OTHER_UI.value] = self._other_ui
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.SIGNATURE_COUNTER.value] = self._signature_counter
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.KEY_PAIR.value] = self._keypair.get_encoded().decode('utf-8')
        return bytes(json.dumps(data), 'utf-8')

    def get_public_key_credential_descriptor(self):
        #PublicKeyCredentialDescriptor
        desc = {}
        desc[AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.ID.value]=self._id
        desc[AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.TYPE.value]=AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.TYPE_PUBLIC_KEY.value
        #desc["transports"]=["usb"]
        return desc

    def from_bytes(self,data:bytes, without_id=False):
        data = json.loads(data.decode('utf-8'))
        self._type=data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.TYPE.value]
        if not without_id:
            self._id= bytes.fromhex(data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.ID.value])
        self._alg = data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.ALG.value]
        self._rp_id = data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.RP_ID.value]
        self._signature_counter = data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.SIGNATURE_COUNTER.value]
        self._keypair=CRYPTO_PROVIDERS[self._alg].load_key_pair(data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.KEY_PAIR.value].encode('utf-8'))
        self._user_handle = bytes.fromhex(data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.USER_HANDLE.value])
        self._other_ui=data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.OTHER_UI.value]

  
    def get_cose_public_key(self):
        return self._keypair.get_public_key().get_as_cose()
        
    
    def get_signature_counter_bytes(self):
        return bytes.fromhex(self._signature_counter)
    
    def get_private_key(self):
        return self._keypair.get_private_key()

    def get_signature_counter(self):
        return int.from_bytes(bytes.fromhex(self._signature_counter),"big")
    
    def increment_signature_counter(self):
        self._signature_counter=(self.get_signature_counter() + 1).to_bytes(4, 'big')

    def set_id(self, user_id:bytes):
        self._id = user_id
    
    def get_id(self)->bytes:
        return self._id
    
    def set_private_key(self, private_key):
        self._sk = private_key
    
    def set_type(self, cred_type:str):
        self._type = cred_type
    
    def get_type(self):
        return self._type
    
    def set_rp_id(self, rp_id:str):
        self._rp_id = rp_id

    def get_rp_id(self):
        return self._rp_id
    def set_user_handle(self, user_handle):
        self._user_handle=user_handle
    
    def get_user_handle(self, include_identifiable:bool=False):       
        result = {}
        if include_identifiable:
            result = self._other_ui.copy()
            result[PUBLICKEY_CREDENTIAL_USER_ENTITY.ID.value] = self._user_handle
            return result
        else:
            
            result[PUBLICKEY_CREDENTIAL_USER_ENTITY.ID.value] = self._user_handle
            return result
    
    def set_other_ui(self, other_ui:dict):
        self._other_ui = other_ui

    def get_other_ui(self)->dict:
        return self._other_ui
    
"""

type

    whose value is of PublicKeyCredentialType, defaulting to public-key.
id

    A Credential ID.
privateKey

    The credential private key.
rpId

    The Relying Party Identifier, for the Relying Party this public key credential source is scoped to.
userHandle

    The user handle associated when this public key credential source was created. This item is nullable.
otherUI

    OPTIONAL other information used by the authenticator to inform its UI. For example, this might include the user’s displayName.
"""
