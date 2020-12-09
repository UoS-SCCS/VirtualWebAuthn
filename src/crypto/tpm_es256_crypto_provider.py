"""ES256 Crypto Provider

Concrete implementation of ES256 crypto functions using
python cryptography

Classes:
    ECCryptoKeyPair
    ECCryptoPrivateKey
    ECCryptoPublicKey
    ES256CryptoProvider
"""
from binascii import b2a_hex

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (PrivateFormat,
    Encoding, NoEncryption)
from cryptography.hazmat.primitives.asymmetric.ec import (EllipticCurvePublicKey,
    EllipticCurvePublicNumbers, EllipticCurvePrivateKeyWithSerialization)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from fido2.cose import ES256
from crypto.crypto_provider import (AuthenticatorCryptoProvider,
    AuthenticatorCryptoKeyPair, AuthenticatorCryptoPublicKey,
    AuthenticatorCryptoPrivateKey)

class ECCryptoKeyPair(AuthenticatorCryptoKeyPair):
    """Creates Elliptic Curve Key Pair
    """
    def __init__(self, private_key:EllipticCurvePrivateKeyWithSerialization):
        """Initialise Elliptic Curve Crypto Key Pair from private key

        Args:
            private_key (EllipticCurvePrivateKeyWithSerialization): Underlying python crypto
                private key
        """
        super().__init__(ECCryptoPublicKey(private_key.public_key()),
            ECCryptoPrivateKey(private_key))

    def get_encoded(self)->bytes:
        return self._sk.get_private_key().private_bytes(Encoding.PEM,
            PrivateFormat.PKCS8,NoEncryption())

class ECCryptoPrivateKey(AuthenticatorCryptoPrivateKey):
    """Represents an Elliptic Curve private key
    """
    def __init__(self, private_key:EllipticCurvePrivateKeyWithSerialization):
        """Initialise Elliptic Curve Crypto Private Key instance

        Args:
            private_key (EllipticCurvePrivateKeyWithSerialization): underlying private key
        """
        super().__init__(private_key)
        self._sk = private_key

    def get_private_key(self):
        return self._sk

    def sign(self,msg:bytes):
        return self._sk.sign(msg,ec.ECDSA(hashes.SHA256()))

    def get_encoded(self)->bytes:
        self._sk.get_private_key().private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption())

    def exchange(self,other_public_key:EllipticCurvePublicKey)->bytes:
        """Performs first part of DH Key Exchange. This is required for
        the PIN handling in CTAP. Note, this is not required for non-ES256
        classes since the algorithm for PIN handling is fixed

        This is not a standard ECDH key exchange, only part of it as per CTAP

        Args:
            other_public_key (EllipticCurvePublicKey): The other public key in the exchange

        Returns:
            bytes: hashed result of exchange as per CTAP standard
        """
        hash_alg = hashes.Hash(hashes.SHA256(),default_backend())
        hash_alg.update(self._sk.exchange(ec.ECDH(), other_public_key))
        return hash_alg.finalize()

class ECCryptoPublicKey(AuthenticatorCryptoPublicKey):
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
        return ECCryptoPublicKey(EllipticCurvePublicNumbers(
                int(b2a_hex(cose_data[-2]), 16),int(b2a_hex(cose_data[-3]), 16),
                ec.SECP256R1()).public_key(default_backend()))

class TPMES256CryptoProvider(AuthenticatorCryptoProvider):
    """Instaniates an ES256 Crypto Provider

    """
    def __init__(self):
        super().__init__()
        self._alg = -7 #cose algorithm number

    def create_new_key_pair(self)->AuthenticatorCryptoKeyPair:
        #https://tools.ietf.org/html/draft-ietf-cose-webauthn-algorithms-04 specifies SECP256K1
        return ECCryptoKeyPair(ec.generate_private_key(ec.SECP256R1,default_backend()))

    def load_key_pair(self, data:bytes)->ECCryptoKeyPair:
        return ECCryptoKeyPair(serialization.load_pem_private_key(data,
            None, backend=default_backend()))

    def public_key_from_cose(self, cose_data:{})->ECCryptoPublicKey:
        return ECCryptoPublicKey.from_cose(cose_data)
        