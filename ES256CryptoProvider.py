from AuthenticatorCryptoProvider import AuthenticatorCryptoProvider
from AuthenticatorCryptoProvider import AuthenticatorCryptoKeyPair
from AuthenticatorCryptoProvider import AuthenticatorCryptoPublicKey
from AuthenticatorCryptoProvider import AuthenticatorCryptoPrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import  PrivateFormat
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import KeySerializationEncryption
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurveSignatureAlgorithm
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKeyWithSerialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.backends import default_backend
from fido2.cose import CoseKey, ES256, RS256, UnsupportedKey

class ECCryptoKeyPair(AuthenticatorCryptoKeyPair):
    def __init__(self, private_key:EllipticCurvePrivateKeyWithSerialization):
        
        super().__init__(ECCryptoPublicKey(private_key.public_key()),ECCryptoPrivateKey(private_key))
    
    def get_encoded(self)->bytes:
        return self._sk.get_private_key().private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption())
        
class ECCryptoPrivateKey(AuthenticatorCryptoPrivateKey):
    def __init__(self, private_key:EllipticCurvePrivateKeyWithSerialization):
        self._sk = private_key
        
    def get_private_key(self):
        return self._sk
    
    def sign(self,msg:bytes):
        return self._sk.sign(msg,ec.ECDSA(hashes.SHA256()))


            

class ECCryptoPublicKey(AuthenticatorCryptoPublicKey):
    def __init__(self, public_key:EllipticCurvePublicKey):
        self._pk = public_key
    
    def get_public_key(self):
        return self._pk
        
    def get_as_cose(self):
        return ES256.from_cryptography_key(self._pk)
    

class ES256CryptoProvider(AuthenticatorCryptoProvider):
    def __init__(self):
        self._alg = -7 #cose algorithm number
    
    def create_new_key_pair(self)->AuthenticatorCryptoKeyPair:
        #https://tools.ietf.org/html/draft-ietf-cose-webauthn-algorithms-04 specifies SECP256K1
        return ECCryptoKeyPair(ec.generate_private_key(ec.SECP256R1,default_backend()))
    
    def load_key_pair(self, data:bytes)->ECCryptoKeyPair:
        return ECCryptoKeyPair(serialization.load_pem_private_key(data,None, backend=default_backend()))