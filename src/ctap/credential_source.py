"""Provides a class to manage a credential source

Classes:

 * :class:`PublicKeyCredentialSource`
"""
"""
 © Copyright 2020-2021 University of Surrey

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

"""
import os
import logging
import json
from crypto.crypto_provider import (AuthenticatorCryptoKeyPair,
    CRYPTO_PROVIDERS,AuthenticatorCryptoPrivateKey)
from ctap.constants import AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR
from ctap.constants import AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY
from ctap.constants import AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE
from authenticator.datatypes import PublicKeyCredentialRpEntity
import ctap.constants
log = logging.getLogger('debug')

class PublicKeyCredentialSource():
    """Manages a PublicKeyCredentialSource
    """
    def __init__(self):
        """Initializes a new PublicKeyCredentialSource with default values
        """
        self._alg = None
        self._type="public-key"
        self._id=None
        self._rp_entity=None
        self._sk = None
        self._keypair = None
        self._user_handle = None
        self._other_ui=None
        self._signature_counter= b'\x00\x00\x00\x00'.hex()

    def init_new(self,alg:int, key_pair:AuthenticatorCryptoKeyPair,
        rp_entity:'PublicKeyCredentialRpEntity', user_entity:'PublicKeyCredentialUserEntity',
        keytype="public-key"):
        """Initalises a new credential source, generating a new channel ID. This should
        be called when creating new credential sources only, not when reloading a
        previously generated one

        Args:
            alg (int): COSE algorithm for this credential source
            key_pair (AuthenticatorCryptoKeyPair): Crypto key pair for credential
            rp_id (PublicKeyCredentialRpEntity): Relying Party entity
            user_entity (PublicKeyCredentialUserEntity): User Entity
            keytype (str, optional): type. Defaults to "public-key".
        """
        self._alg=alg
        self._type=keytype
        self.generate_id()
        self._rp_entity = rp_entity
        self._keypair = key_pair
        self._user_handle = user_entity.get_id()
        other_ui = user_entity.get_as_dict()
        other_ui.pop(AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.ID.value)
        self._other_ui=other_ui
    def generate_id(self):
        """Generates a new random credential ID of size CREDENTIAL_ID_SIZE and
        sets its value to _id in this credential source
        """
        self._id=os.urandom(ctap.constants.CREDENTIAL_ID_SIZE)

    def get_alg(self)->int:
        """Gets the algorithm for this credential

        Returns:
            int: COSE algorithm identifier
        """
        return self._alg

    def get_bytes(self, without_id=False)->bytes:
        """Constructs a JSON object containing the data associated with
        this credential source and encodes the JSON String as bytes. This should
        be used for storing the credential source to disk or when
        the credential source is going to be wrapped and set on the server,
        for example, a non-resident key.

        without_id allows excluding the ID parameter, which in the case of a
        non-resident key will be the wrapped encrypted data itself.

        Args:
            without_id (bool, optional): If set to True excludes the ID from the
                data. Defaults to False.

        Returns:
            bytes: [description]
        """
        data = {}
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.TYPE.value] = self._type
        if not without_id:
            data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.ID.value] = self._id.hex()
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.ALG.value] = self._alg
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.RP_ID.value] = self._rp_entity.get_as_dict()
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.USER_HANDLE.value] = self._user_handle.hex()
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.OTHER_UI.value] = self._other_ui
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.SIGNATURE_COUNTER.value] = self._signature_counter
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.KEY_PAIR.value] = \
            self._keypair.get_encoded().decode('utf-8')
        return bytes(json.dumps(data), 'utf-8')

    def debug(self)->dict:
        """Constructs a JSON str of the data within this credential

        Returns:
            dict: json debug object
        """
        data = {}
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.TYPE.value] = self._type
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.ID.value] = self._id.hex()
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.ALG.value] = self._alg
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.RP_ID.value] = self._rp_entity.get_as_dict()
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.USER_HANDLE.value] = self._user_handle.hex()
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.OTHER_UI.value] = self._other_ui
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.SIGNATURE_COUNTER.value] = self._signature_counter
        data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.KEY_PAIR.value] = \
            self._keypair.get_encoded().decode('utf-8')
        return data

    def get_public_key_credential_descriptor(self)->dict:
        """Returns a dictionary containing the public key
        credential description, consisting of the credential
        ID and the type.

        The optional transports parameter is currently not set
        but could be.

        Returns:
            dict: containing credential ID and type
        """
        #PublicKeyCredentialDescriptor
        desc = {}
        desc[AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.ID.value]=self._id
        desc[AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.TYPE.value]=\
            AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.TYPE_PUBLIC_KEY.value
        #desc["transports"]=["usb"]
        return desc

    def from_bytes(self,data:bytes, without_id=False):
        """Loads a credential source from bytes. This should be called when
        reloading a credential source from storage or after decrypting
        a non-resident key.

        without_id is used to indicate whether the id attribute should
        be set, in the case of a non-resident key this should be True
        due to the id being the encrypted contents of this.

        Args:
            data (bytes): bytes to load
            without_id (bool, optional): True to exclude the ID (non-resident
            key), False to set the ID. Defaults to False.
        """
        data = json.loads(data.decode('utf-8'))
        self._type=data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.TYPE.value]
        if not without_id:
            self._id= bytes.fromhex(data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.ID.value])
        self._alg = data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.ALG.value]
        self._rp_entity = PublicKeyCredentialRpEntity(data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.RP_ID.value])
        self._signature_counter = data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.SIGNATURE_COUNTER.value]
        self._keypair=CRYPTO_PROVIDERS[self._alg].load_key_pair(
            data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.KEY_PAIR.value].encode('utf-8'))
        self._user_handle = bytes.fromhex(
                data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.USER_HANDLE.value])
        self._other_ui=data[AUTHN_PUBLIC_KEY_CREDENTIAL_SOURCE.OTHER_UI.value]


    def get_cose_public_key(self):
        """Encodes the public key in a COSE compatible format

        Returns:
            cose: COSE encoded public key
        """
        return self._keypair.get_public_key().get_as_cose()


    def get_signature_counter_bytes(self)->bytes:
        """Gets the signatures counter as bytes

        Returns:
            bytes: signature counter
        """
        return bytes.fromhex(self._signature_counter)

    def get_private_key(self)->AuthenticatorCryptoPrivateKey:
        """Gets the private key

        Returns:
            AuthenticatorCryptoPrivateKey: private key
        """
        return self._keypair.get_private_key()

    def get_signature_counter(self)->int:
        """Gets the signature counter as an integer

        Returns:
            int: integer encoded signature counter
        """
        return int.from_bytes(bytes.fromhex(self._signature_counter),"big")

    def increment_signature_counter(self):
        """Increments the signature counter
        """
        self._signature_counter=(self.get_signature_counter() + 1).to_bytes(4, 'big')

    def set_id(self, user_id:bytes):
        """Sets the credential id

        Args:
            user_id (bytes): id to set
        """
        self._id = user_id

    def get_id(self)->bytes:
        """Get the credential id

        Returns:
            bytes: credential id as bytes
        """
        return self._id

    def set_private_key(self, private_key:AuthenticatorCryptoPrivateKey):
        """Sets the private key to private_key

        Args:
            private_key (AuthenticatorCryptoPrivateKey): private key to set
        """
        self._sk = private_key

    def set_type(self, cred_type:str):
        """Sets the type for this credential

        Args:
            cred_type (str): credential type, normally public-key
        """
        self._type = cred_type

    def get_type(self)->str:
        """Gets the type of this credential

        Returns:
            str: credential type, usually public-key
        """
        return self._type

    def set_rp_entity(self, rp_entity:'PublicKeyCredentialRpEntity'):
        """Sets the rp entity

        Args:
            rp_entity (PublicKeyCredentialRpEntity): RP entity to set
        """
        self._rp_entity = rp_entity

    def get_rp_entity(self)->'PublicKeyCredentialRpEntity':
        """Gets the associated RP Entity

        Returns:
            PublicKeyCredentialRpEntity: rp entity associated with credential source
        """
        return self._rp_entity
    def set_user_handle(self, user_handle:bytes):
        """Sets the user handle

        Args:
            user_handle (bytes): user handle to set
        """
        self._user_handle=user_handle

    def get_user_entity(self, include_identifiable:bool=False)->dict:
        """Gets the user entity for this credential source

        if include_identifiable is set it will include user identifiable
        information in the dictionary (other_ui), otherwise it will not

        Args:
            include_identifiable (bool, optional): set to True to include
                user identifiable information. Defaults to False.

        Returns:
            dict: contain a minimum of the user handle (id) and possibly
                other_ui as well
        """
        result = {}
        if include_identifiable:
            result = self._other_ui.copy()
            result[AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.ID.value] = self._user_handle
            return result
        result[AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.ID.value] = self._user_handle
        return result

    def set_other_ui(self, other_ui:dict):
        """Sets the other UI components

        Args:
            other_ui (dict): dictionary of other UI data from the user entity
        """
        self._other_ui = other_ui

    def get_other_ui(self)->dict:
        """Gets the other UI components from the user entity

        Returns:
            dict: containing other ui elements
        """
        return self._other_ui
