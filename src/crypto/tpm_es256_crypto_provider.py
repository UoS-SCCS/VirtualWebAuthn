"""TPM Based ES256 Crypto Provider

Concrete implementation of a TPM based ES256 crypto functions

Classes:

 * :class:`TPMECCryptoKeyPair`
 * :class:`TPMECCryptoPrivateKey`
 * :class:`TPMECCryptoPublicKey`
 * :class:`TPMES256CryptoProvider`
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
import json
from binascii import b2a_hex

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (EllipticCurvePublicKey,
    EllipticCurvePublicNumbers)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from fido2.cose import ES256
from crypto.crypto_provider import (AuthenticatorCryptoProvider,
    AuthenticatorCryptoKeyPair, AuthenticatorCryptoPublicKey,
    AuthenticatorCryptoPrivateKey)

from crypto.tpm.ibmtpm import TPM,DICEKeyData, DICERelyingPartyKey

class TPMECCryptoKeyPair(AuthenticatorCryptoKeyPair):
    """Creates Elliptic Curve Key Pair
    """
    def __init__(self, private_key:DICERelyingPartyKey, tpm:TPM):
        """Initialise Elliptic Curve Crypto Key Pair from private key

        Args:
            private_key (EllipticCurvePrivateKeyWithSerialization): Underlying python crypto
                private key
        """

        super().__init__(TPMECCryptoPublicKey(private_key.get_as_ec_public_key()),
            TPMECCryptoPrivateKey(private_key,tpm))
        self._private_key = private_key

    def get_encoded(self)->bytes:
        return json.dumps(self._private_key.as_json()).encode("UTF-8")

class TPMECCryptoPrivateKey(AuthenticatorCryptoPrivateKey):
    """Represents an Elliptic Curve private key
    """
    def __init__(self, private_key:DICERelyingPartyKey, tpm:TPM):
        """Initialise Elliptic Curve Crypto Private Key instance

        Args:
            private_key (EllipticCurvePrivateKeyWithSerialization): underlying private key
        """
        super().__init__(private_key)
        self._private_key = private_key
        self._tpm = tpm

    def get_private_key(self):
        return self._private_key

    def sign(self,msg:bytes):
        hash_alg = hashes.Hash(hashes.SHA256(),default_backend())
        hash_alg.update(msg)
        digest= hash_alg.finalize()
        return self._tpm.sign_using_rp_key(self._private_key.username,digest,
            self._private_key.password).get_as_der_encoded_signature()

    def get_encoded(self)->bytes:
        return json.dumps(self._private_key.as_json()).encode("UTF-8")

class TPMECCryptoPublicKey(AuthenticatorCryptoPublicKey):
    """Elliptic Curve Public Key

    """
    def __init__(self, public_key:EllipticCurvePublicKey):
        """Initialises an Elliptic Curve Public Key

        Args:
            public_key (EllipticCurvePublicKey): underlying python crypto public key
        """
        super().__init__(public_key)
        self._pk = public_key

    def get_encoded(self)->bytes:
        return self._pk.public_bytes()

    def get_public_key(self):
        return self._pk

    def get_as_cose(self):
        return ES256.from_cryptography_key(self._pk)

    @staticmethod
    def from_cose(cose_data:{})->'ECCryptoPublicKey':
        """Instantiates an instance of this class from a COSE encoded
        public key.

        Returns:
            ECCryptoPublicKey: instance of the public key
        """
        return TPMECCryptoPublicKey(EllipticCurvePublicNumbers(
                int(b2a_hex(cose_data[-2]), 16),int(b2a_hex(cose_data[-3]), 16),
                ec.SECP256R1()).public_key(default_backend()))

class TPMES256CryptoProvider(AuthenticatorCryptoProvider):
    """Instaniates an ES256 Crypto Provider

    """
    def __init__(self):
        super().__init__()
        self._alg = -7 #cose algorithm number
        self._tpm = TPM()
        self._tpm.start_up_tpm(data_dir="./data/tpm")
        self._user_key_data = None

    def create_user_key(self, username:str, password:str)->str:
        """Creates a TPM user key and returns it encoded as string for storage

        Args:
            username (str): username
            password (str): password

        Returns:
            (str): JSON encoded string of the user key
        """
        self._user_key_data=self._tpm.create_and_load_user_key(username,password)
        return json.dumps(self._user_key_data.as_json())

    def load_user_key(self, key_data:str):
        """Loads the user key from JSON encoded key data

        Args:
            key_data (str): JSON encoded string data
        """
        self._user_key_data = DICEKeyData.from_json(json.loads(key_data))
        self._tpm.load_user_key(self._user_key_data)

    def create_new_key_pair(self, relying_party:str=None)->AuthenticatorCryptoKeyPair:
        #https://tools.ietf.org/html/draft-ietf-cose-webauthn-algorithms-04 specifies SECP256K1
        return TPMECCryptoKeyPair(self._tpm.create_and_load_rp_key(relying_party,
            os.urandom(16).hex(),self._user_key_data.password),self._tpm)

    def load_key_pair(self, data:bytes)->TPMECCryptoKeyPair:
        dice_relying_party_key = DICERelyingPartyKey.from_json(json.loads(data.decode("UTF-8")))
        self._tpm.load_rp_key(dice_relying_party_key,self._user_key_data.password)
        return TPMECCryptoKeyPair(dice_relying_party_key,self._tpm)

    def public_key_from_cose(self, cose_data:{})->TPMECCryptoPublicKey:
        return TPMECCryptoPublicKey.from_cose(cose_data)

    def shutdown(self):
        self.clean_up()
    def clean_up(self):
        """Cleans up the underlying TPM and unloads it from memory
        """
        self._tpm.flush()
        self._tpm.uninstall()
