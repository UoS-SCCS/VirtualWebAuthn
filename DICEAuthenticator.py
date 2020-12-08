from abc import ABC, abstractmethod
from CTAPHID import CTAPHIDTransaction
from HIDPacket import HIDPacket
from USBHID import USBHID
from USBHID import USBHIDListener
#from CTAPHID import CTAPHID
import shutil
import CTAPHIDConstants
from CTAPHIDConstants import AUTHN_GET_CLIENT_PIN
from CTAPHIDConstants import AUTHN_GET_ASSERTION
from CTAPHIDConstants import AUTHN_MAKE_CREDENTIAL
from CTAPHIDConstants import AUTHN_GETINFO
from CTAPHIDConstants import AUTHN_GETINFO_OPTION
from CTAPHIDConstants import AUTHN_GETINFO_PARAMETER
from CTAPHIDConstants import AUTHN_GETINFO_PIN_UV_PROTOCOL
from CTAPHIDConstants import AUTHN_GETINFO_TRANSPORT
from CTAPHIDConstants import AUTHN_CMD
from CTAPHIDConstants import AUTHN_GETINFO_VERSION
from CTAPHIDConstants import AUTHN_GET_CLIENT_PIN_SUBCMD
from CTAPHIDConstants import AUTHN_GET_CLIENT_PIN_RESP
from CTAPHIDConstants import AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR
from CTAPHIDConstants import PUBLICKEY_CREDENTIAL_USER_ENTITY
from AuthenticatorVersion import AuthenticatorVersion
from CTAPHIDKeepAlive import CTAPHIDKeepAlive
from AuthenticatorCryptoProvider import AuthenticatorCryptoProvider
from AuthenticatorCryptoProvider import CRYPTO_PROVIDERS
from ES256CryptoProvider import ES256CryptoProvider
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from DICEAuthenticatorUI import DICEAuthenticatorListener, DICEAuthenticatorUI, ConsoleAuthenticatorUI
from enum import Enum, unique
from uuid import UUID
from fido2 import cbor
from PublicKeyCredentialSource import PublicKeyCredentialSource
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import json
import os
import time
log = logging.getLogger('debug')
auth = logging.getLogger('debug.auth')



@unique
class PUBLIC_KEY_ALG(Enum):
    RS512 =	-259 #	RSASSA-PKCS1-v1_5 using SHA-512 	IESG 	[RFC8812] 	No
    RS384 =	-258 #	RSASSA-PKCS1-v1_5 using SHA-384 	IESG 	[RFC8812] 	No
    RS256 =	-257 #	RSASSA-PKCS1-v1_5 using SHA-256 	IESG 	[RFC8812] 	No
    HSS_LMS = -46
    RSAES_OAEP_with_SHA_512 = -42
    RSAES_OAEP_with_SHA_256 = -41
    RSAES_OAEP_with_RFC_8017_default_parameters = -40
    PS512 = -39
    PS384 = -38
    PS256 = -37
    ES512 = -36
    ES384 = -35
    ECDH_SS_A256KW = -34
    ECDH_SS_A192KW = -33
    ECDH_SS_A128KW = -32
    ECDH_ES_A256KW = -31
    ECDH_ES_A192KW = -30
    ECDH_ES_A128KW = -29
    ECDH_SS_HKDF_512 = -28
    ECDH_SS_HKDF_256 = -27
    ECDH_ES_HKDF_512 = -26
    ECDH_ES_HKDF_256 = -25
    direct_HKDF_AES_256 = -13
    direct_HKDF_AES_128 = -12
    direct_HKDF_SHA_512 = -11
    direct_HKDF_SHA_256 = -10
    EdDSA = -8  # EdDSA   [RFC8152]  Yes
    ES256 = -7  # ECDSA w/ SHA-256   [RFC8152]  Yes
    direct = -6  # Direct use of CEK   [RFC8152]  Yes
    A256KW = -5  # AES Key Wrap w/ 256-bit key   [RFC8152]  Yes
    A192KW = -4  # AES Key Wrap w/ 192-bit key   [RFC8152]  Yes
    A128KW = -3  # AES Key Wrap w/ 128-bit key   [RFC8152]  Yes
    A128GCM = 1  # AES-GCM mode w/ 128-bit key, 128-bit tag   [RFC8152]  Yes
    A192GCM = 2  # AES-GCM mode w/ 192-bit key, 128-bit tag   [RFC8152]  Yes
    A256GCM = 3  # AES-GCM mode w/ 256-bit key, 128-bit tag   [RFC8152]  Yes
    HMAC_256_64 = 4  # HMAC w/ SHA-256 truncated to 64 bits   [RFC8152]  Yes
    HMAC_256_256 = 5  # HMAC w/ SHA-256   [RFC8152]  Yes
    HMAC_384_384 = 6  # HMAC w/ SHA-384   [RFC8152]  Yes
    HMAC_512_512 = 7  # HMAC w/ SHA-512   [RFC8152]  Yes
    # AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce   [RFC8152]  Yes
    AES_CCM_16_64_128 = 10
    # AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce   [RFC8152]  Yes
    AES_CCM_16_64_256 = 11
    # AES_CCM mode 128_bit key, 64_bit tag, 7_byte nonce   [RFC8152]  Yes
    AES_CCM_64_64_128 = 12
    # AES_CCM mode 256_bit key, 64_bit tag, 7_byte nonce   [RFC8152]  Yes
    AES_CCM_64_64_256 = 13
    AES_MAC_128_64 = 14  # AES_MAC 128_bit key, 64_bit tag 		[RFC8152] 	Yes
    AES_MAC_256_64 = 15  # AES_MAC 256_bit key, 64_bit tag 		[RFC8152] 	Yes
    # ChaCha20/Poly1305 w/ 256_bit key, 128_bit tag   [RFC8152]  Yes
    ChaCha20_Poly1305 = 24
    AES_MAC_128_128 = 25  # AES_MAC 128_bit key, 128_bit tag   [RFC8152]  Yes
    AES_MAC_256_128 = 26  # AES_MAC 256_bit key, 128_bit tag   [RFC8152]  Yes
    # AES_CCM mode 128_bit key, 128_bit tag, 13_byte nonce   [RFC8152]  Yes
    AES_CCM_16_128_128 = 30
    # AES_CCM mode 256_bit key, 128_bit tag, 13_byte nonce   [RFC8152]  Yes
    AES_CCM_16_128_256 = 31
    # AES_CCM mode 128_bit key, 128_bit tag, 7_byte nonce   [RFC8152]  Yes
    AES_CCM_64_128_128 = 32
    # AES_CCM mode 256_bit key, 128_bit tag, 7_byte nonce 		[RFC8152] 	Yes
    AES_CCM_64_128_256 = 33



class PublicKeyCredentialParameters(dict):
    def __init__(self, algo: PUBLIC_KEY_ALG, type="public-key"):
        super(PublicKeyCredentialParameters,self).__init__()
        self.__setitem__("type",type)
        self.__setitem__("alg",algo.value)

class PublicKeyCredentialUserEntity():
    def __init__(self, data:dict):
        self.parameters = data
        self.verify()
    
    def get_as_dict(self):
        return self.parameters
        
    def verify(self):
        if not PUBLICKEY_CREDENTIAL_USER_ENTITY.ID.value in self.parameters:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"Missing ID in UserEntity")
        if not PUBLICKEY_CREDENTIAL_USER_ENTITY.DISPLAYNAME.value in self.parameters:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"Missing displayName in UserEntity")
        
        if not type(self.parameters[PUBLICKEY_CREDENTIAL_USER_ENTITY.ID.value]) is bytes:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"id in UserEntity not bytes")
        if not type(self.parameters[PUBLICKEY_CREDENTIAL_USER_ENTITY.DISPLAYNAME.value]) is str:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"displayName in UserEntity not str")
        
        if PUBLICKEY_CREDENTIAL_USER_ENTITY.NAME.value in self.parameters:
            if not type(self.parameters[PUBLICKEY_CREDENTIAL_USER_ENTITY.NAME.value]) is str:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"name in UserEntity not str")
        
        if PUBLICKEY_CREDENTIAL_USER_ENTITY.ICON.value in self.parameters:
            if not type(self.parameters[PUBLICKEY_CREDENTIAL_USER_ENTITY.ICON.value]) is str:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"icon in UserEntity not str")

    def get_id(self):
        return self.parameters[PUBLICKEY_CREDENTIAL_USER_ENTITY.ID.value]
    
    def get_display_name(self):
        return self.parameters[PUBLICKEY_CREDENTIAL_USER_ENTITY.DISPLAYNAME.value]
    
    def get_name(self):
        if PUBLICKEY_CREDENTIAL_USER_ENTITY.NAME.value in self.parameters:
            return self.parameters[PUBLICKEY_CREDENTIAL_USER_ENTITY.NAME.value]
        else:
            return None
    
    def get_icon(self):
        if PUBLICKEY_CREDENTIAL_USER_ENTITY.ICON.value in self.parameters:
            return self.parameters[PUBLICKEY_CREDENTIAL_USER_ENTITY.ICON.value]
        else:
            return None
    


class CBORResponse:
    def __init__(self):
        self.content = {}

    def __str__(self):
        out = {}
        out["type"] = str(type(self))
        out["content"]={}
        for key in self.content:
            if type(self.content[key])==bytes:
                auth.debug("Converting value to hex")
                out["content"][key]=self.content[key].hex()
        return json.dumps(out)

    def get_encoded(self):
        if len(self.content) == 0:
            return bytes(0)
        return cbor.encode(self.content)

def keys_exist_in_dict(keys:[],dict:{})->bool:
    for key in keys:
        if not key in dict:
            return False
    return True
def keys_do_not_exist_in_dict(keys:[],dict:{})->bool:
    for key in keys:
        if key in dict:
            return False
    return True
def only_keys_in_dict(keys,dict:{})->bool:
    if type(keys) is Enum:
        for e in keys:
            if not e.value in dict:
                return False
        if len(dict) != len(keys.__members__):
            return False
    else:
        for key in keys:
            if not key in dict:
                return False
        if len(dict) != len(keys):
            return False
    return True



class AuthenticatorGetClientPINParameters:
    """
    pinProtocol (0x01) 	Unsigned Integer 	Required 	PIN protocol version chosen by the client. For this version of the spec, this SHALL be the number 1.
    subCommand (0x02) 	Unsigned Integer 	Required 	The authenticator Client PIN sub command currently being requested
    keyAgreement (0x03) 	COSE_Key 	Optional 	Public key of platformKeyAgreementKey. The COSE_Key-encoded public key MUST contain the optional "alg" parameter and MUST NOT contain any other optional parameters. The "alg" parameter MUST contain a COSEAlgorithmIdentifier value.
    pinAuth (0x04) 	Byte Array 	Optional 	First 16 bytes of HMAC-SHA-256 of encrypted contents using sharedSecret. See Setting a new PIN, Changing existing PIN and Getting pinToken from the authenticator for more details.
    newPinEnc (0x05) 	Byte Array 	Optional 	Encrypted new PIN using sharedSecret. Encryption is done over UTF-8 representation of new PIN.
    pinHashEnc (0x06) 	Byte Array 	Optional 	Encrypted first 16 bytes of SHA-256 of PIN using sharedSecret. """

    def __init__(self, cbor_data:bytes):
        self.parameters = cbor.decode(cbor_data)
        auth.debug("Decoded GetClientPINParameters: %s", self.parameters)        
        self.verify()

    def verify(self):
        if not AUTHN_GET_CLIENT_PIN.PIN_PROTOCOL.value in self.parameters:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"pinProtocol missing")
        
        if not AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value in self.parameters:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"subCommand missing")
        
        if not type(self.parameters[AUTHN_GET_CLIENT_PIN.PIN_PROTOCOL.value]) == int:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"pinProtocol not integer")
        
        if not type(self.parameters[AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value]) == int:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"subCommand not integer")

        if AUTHN_GET_CLIENT_PIN.KEY_AGREEMENT.value in self.parameters:
            #Verify Key Agreement
            if not type(self.parameters[AUTHN_GET_CLIENT_PIN.KEY_AGREEMENT.value]) is dict:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"pinAgreement not dictionary")
            if not 3 in self.parameters[AUTHN_GET_CLIENT_PIN.KEY_AGREEMENT.value]:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"missing alg parameter")
            #TODO verify COSE key
        
        if AUTHN_GET_CLIENT_PIN.PIN_AUTH.value in self.parameters:
            if not type(self.parameters[AUTHN_GET_CLIENT_PIN.PIN_AUTH.value]) is bytes:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"pinAuth not bytes")
        
        if AUTHN_GET_CLIENT_PIN.NEW_PIN_ENC.value in self.parameters:
            if not type(self.parameters[AUTHN_GET_CLIENT_PIN.NEW_PIN_ENC.value]) is bytes:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"newPinEnc not bytes")

        if AUTHN_GET_CLIENT_PIN.PIN_HASH_ENC.value in self.parameters:
            if not type(self.parameters[AUTHN_GET_CLIENT_PIN.PIN_HASH_ENC.value]) is bytes:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"pinHashEnc not bytes")
        
        sub_command = self.parameters[AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value]
        if not (sub_command >=1 and sub_command<=5):
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_COMMAND,"invalid subCommand")

        if sub_command == 1 or sub_command == 2:
            if not only_keys_in_dict([AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value,AUTHN_GET_CLIENT_PIN.PIN_PROTOCOL.value],self.parameters):
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER,"invalid parameters found")

        if sub_command == 3:
            if not only_keys_in_dict([AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value,AUTHN_GET_CLIENT_PIN.PIN_PROTOCOL.value,AUTHN_GET_CLIENT_PIN.NEW_PIN_ENC.value,AUTHN_GET_CLIENT_PIN.PIN_AUTH.value,AUTHN_GET_CLIENT_PIN.KEY_AGREEMENT.value],self.parameters):
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER,"invalid parameters found")
        
        if sub_command == 4:
            if not only_keys_in_dict([AUTHN_GET_CLIENT_PIN],self.parameters):
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER,"invalid parameters found")
        
        if sub_command == 5:
            if not only_keys_in_dict([AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value,AUTHN_GET_CLIENT_PIN.PIN_PROTOCOL.value,AUTHN_GET_CLIENT_PIN.KEY_AGREEMENT.value,AUTHN_GET_CLIENT_PIN.PIN_HASH_ENC.value],self.parameters):
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER,"invalid parameters found")
        
    def get_protocol(self):
        return self.parameters[AUTHN_GET_CLIENT_PIN.PIN_PROTOCOL.value]
    
    def get_sub_command(self):
        return self.parameters[AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value]
    
    def get_key_agreement(self):
        return self.parameters[AUTHN_GET_CLIENT_PIN.KEY_AGREEMENT.value]
    
    def get_pin_auth(self):
        return self.parameters[AUTHN_GET_CLIENT_PIN.PIN_AUTH.value]
    
    def get_new_pin_enc(self):
        return self.parameters[AUTHN_GET_CLIENT_PIN.NEW_PIN_ENC.value]

    def get_pin_hash_enc(self):
        return self.parameters[AUTHN_GET_CLIENT_PIN.PIN_HASH_ENC.value]

class PublicKeyCredentialDescriptor:
    def __init__(self, desc:dict):
        self.parameters = desc
        self.verify()
    
    def get_id(self)->bytes:
        return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.ID.value]
    
    def get_type(self)->str:
        return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.TYPE.value]
    
    def get_transports(self):
        return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.TRANSPORTS.value]

    def verify(self):
        if not AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.TYPE.value in self.parameters:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"PublicKeyCredentialDesc missing type")
        if not AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.ID.value in self.parameters:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"PublicKeyCredentialDesc missing id")
        if not self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.TYPE.value] == AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.TYPE_PUBLIC_KEY.value:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"PublicKeyCredentialDesc type not recognised")
        if not type(self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.ID.value]) is bytes:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"PublicKeyCredentialDesc id not bytes")
        
class AuthenticatorGetAssertionParameters:
    """
    rpId 	String 	Required 	Relying party identifier. See [WebAuthN].
    clientDataHash 	Byte Array 	Required 	Hash of the serialized client data collected by the host. See [WebAuthN].
    allowList 	Sequence of PublicKeyCredentialDescriptors 	Optional 	A sequence of PublicKeyCredentialDescriptor structures, each denoting a credential, as specified in [WebAuthN]. If this parameter is present and has 1 or more entries, the authenticator MUST only generate an assertion using one of the denoted credentials.
    extensions	CBOR map of extension identifier → authenticator extension input values 	Optional 	Parameters to influence authenticator operation. These parameters might be authenticator specific.
    options	Map of authenticator options 	Optional 	Parameters to influence authenticator operation, as specified in the table below.
    pinAuth	Byte Array 	Optional 	First 16 bytes of HMAC-SHA-256 of clientDataHash using pinToken which platform got from the authenticator: HMAC-SHA-256(pinToken, clientDataHash).
    pinProtocol 	Unsigned Integer 	Optional 	PIN protocol version selected by client. 
    """
    def __init__(self, cbor_data:bytes):
        self.parameters = cbor.decode(cbor_data)
        
        self.allow_list = []
        for allowed in self.parameters[AUTHN_GET_ASSERTION.ALLOW_LIST.value]:
            self.allow_list.append(PublicKeyCredentialDescriptor(allowed))
        self.verify()
        auth.debug("Decoded GetAssertionParameters: %s", self.parameters)        
        

    def verify(self):
        if not AUTHN_GET_ASSERTION.RP_ID.value in self.parameters:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"rpId missing")
        
        if not AUTHN_GET_ASSERTION.HASH.value in self.parameters:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"clientDataHash missing")
        
        if not type(self.parameters[AUTHN_GET_ASSERTION.RP_ID.value]) == str:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"rpId not string")
        
        if not type(self.parameters[AUTHN_GET_ASSERTION.HASH.value]) == bytes:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"clientDataHash not bytes")

        if AUTHN_GET_ASSERTION.ALLOW_LIST.value in self.parameters:
            if not type(self.parameters[AUTHN_GET_ASSERTION.ALLOW_LIST.value]) == list:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"allowList not sequence")
        if AUTHN_GET_ASSERTION.PIN_AUTH.value in self.parameters:
            if not type(self.parameters[AUTHN_GET_ASSERTION.PIN_AUTH.value]) == bytes:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"pinAuth not bytes")
        if AUTHN_GET_ASSERTION.PIN_PROTOCOL.value in self.parameters:
            if not type(self.parameters[AUTHN_GET_ASSERTION.PIN_PROTOCOL.value]) == int:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"pinProtocol not int")
        #TODO verify options and extensions
        

    def get_hash(self):
        return self.parameters[AUTHN_GET_ASSERTION.HASH.value]
    
    def get_rp_id(self):
        return self.parameters[AUTHN_GET_ASSERTION.RP_ID.value]

    def get_require_resident_key(self):
        return self.parameters[AUTHN_GET_ASSERTION.OPTIONS.value][AUTHN_MAKE_CREDENTIAL.OPTIONS_RK.value]
    def get_user_presence(self):
        return True#Not present in the current version of CTAP. Authenticators are assumed to always check user presence.
    def require_user_verification(self):
        return self.parameters[AUTHN_GET_ASSERTION.OPTIONS.value][AUTHN_MAKE_CREDENTIAL.OPTIONS_UV.value]
        #TODO options.uv or pinAuth/pinProtocol
    def get_allow_list(self)->[PublicKeyCredentialDescriptor]:
        return self.allow_list
        #self.parameters[AUTHN_GET_ASSERTION.ALLOW_LIST.value]
    
    def get_extensions(self):
        return self.parameters[AUTHN_GET_ASSERTION.EXTENSIONS.value]
    
    def get_pin_auth(self):
        if not AUTHN_GET_ASSERTION.PIN_AUTH.value in self.parameters:
            return None
        return self.parameters[AUTHN_GET_ASSERTION.PIN_AUTH.value]
    
    def get_pin_protocol(self):
        if not AUTHN_GET_ASSERTION.PIN_PROTOCOL.value in self.parameters:
            return -1
        return self.parameters[AUTHN_GET_ASSERTION.PIN_PROTOCOL.value]
class AuthenticatorMakeCredentialParameters:
    """
    clientDataHash 	Byte Array 	Required 	Hash of the ClientData contextual binding specified by host. See [WebAuthN].
    rp 	PublicKeyCredentialRpEntity 	Required 	This PublicKeyCredentialRpEntity data structure describes a Relying Party with which the new public key credential will be associated. It contains the Relying party identifier, (optionally) a human-friendly RP name, and (optionally) a URL referencing a RP icon image. The RP name is to be used by the authenticator when displaying the credential to the user for selection and usage authorization.
    user 	PublicKeyCredentialUserEntity 	Required 	This PublicKeyCredentialUserEntity data structure describes the user account to which the new public key credential will be associated at the RP. It contains an RP-specific user account identifier, (optionally) a user name, (optionally) a user display name, and (optionally) a URL referencing a user icon image (of a user avatar, for example). The authenticator associates the created public key credential with the account identifier, and MAY also associate any or all of the user name, user display name, and image data (pointed to by the URL, if any).
    pubKeyCredParams 	CBOR Array 	Required 	A sequence of CBOR maps consisting of pairs of PublicKeyCredentialType (a string) and cryptographic algorithm (a positive or negative integer), where algorithm identifiers are values that SHOULD be registered in the IANA COSE Algorithms registry [IANA-COSE-ALGS-REG]. This sequence is ordered from most preferred (by the RP) to least preferred.
    excludeList 	Sequence of PublicKeyCredentialDescriptors 	Optional 	A sequence of PublicKeyCredentialDescriptor structures, as specified in [WebAuthN]. The authenticator returns an error if the authenticator already contains one of the credentials enumerated in this sequence. This allows RPs to limit the creation of multiple credentials for the same account on a single authenticator.
    extensions 	CBOR map of extension identifier → authenticator extension input values 	Optional 	Parameters to influence authenticator operation, as specified in [WebAuthN]. These parameters might be authenticator specific.
    options 	Map of authenticator options 	Optional 	Parameters to influence authenticator operation, as specified in in the table below.
    pinAuth Byte Array 	Optional 	First 16 bytes of HMAC-SHA-256 of clientDataHash using pinToken which platform got from the authenticator: HMAC-SHA-256(pinToken, clientDataHash).
    pinProtocol 	Unsigned Integer 	Optional 	PIN protocol version chosen by the client 
    """
    def __init__(self, cbor_data:bytes):
        self.parameters = cbor.decode(cbor_data)
        auth.debug("Decoded MakeCredentialParameters: %s", self.parameters)
        self.verify()
        self.user_entity = PublicKeyCredentialUserEntity(self.parameters[AUTHN_MAKE_CREDENTIAL.USER.value])
        self.exclude_list = []
        if AUTHN_MAKE_CREDENTIAL.EXCLUDE_LIST.value in self.parameters:
            for exclude in self.parameters[AUTHN_MAKE_CREDENTIAL.EXCLUDE_LIST.value]:
                self.exclude_list.append(PublicKeyCredentialDescriptor(exclude))
    
    def verify(self):
        if not AUTHN_MAKE_CREDENTIAL.RP.value in self.parameters:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"rpId missing")

        if not AUTHN_MAKE_CREDENTIAL.HASH.value in self.parameters:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"clientDataHash missing")
        
        if not AUTHN_MAKE_CREDENTIAL.USER.value in self.parameters:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"user missing")

        if not AUTHN_MAKE_CREDENTIAL.PUBKEY_CRED_PARAMS.value in self.parameters:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"publicKeyCredentials missing")
        
        if not type(self.parameters[AUTHN_MAKE_CREDENTIAL.PUBKEY_CRED_PARAMS.value]) == list:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"publicKeyCredentials not list")

        for cred in self.parameters[AUTHN_MAKE_CREDENTIAL.PUBKEY_CRED_PARAMS.value]:
            if not type(cred) == dict:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"publicKeyCredential not dictionary")
            if not "type" in cred:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"publicKeyCredential type missing")
            if not "alg" in cred:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"publicKeyCredential alg missing")

        
        if not type(self.parameters[AUTHN_MAKE_CREDENTIAL.RP.value]) == dict:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"rp not dictionary")
        if not type(self.parameters[AUTHN_MAKE_CREDENTIAL.USER.value]) == dict:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"user not dictionary")
        #TODO rp entity verification
        
        if not type(self.parameters[AUTHN_MAKE_CREDENTIAL.HASH.value]) == bytes:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"clientDataHash not bytes")

        if AUTHN_MAKE_CREDENTIAL.PIN_AUTH.value in self.parameters:
            if not type(self.parameters[AUTHN_MAKE_CREDENTIAL.PIN_AUTH.value]) == bytes:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"pinAuth not bytes")
        if AUTHN_MAKE_CREDENTIAL.PIN_PROTOCOL.value in self.parameters:
            if not type(self.parameters[AUTHN_MAKE_CREDENTIAL.PIN_PROTOCOL.value]) == int:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"pinProtocol not int")
        
        if AUTHN_MAKE_CREDENTIAL.OPTIONS.value in self.parameters:
            if not type(self.parameters[AUTHN_MAKE_CREDENTIAL.OPTIONS.value][AUTHN_MAKE_CREDENTIAL.OPTIONS_RK.value]) == bool:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"option rk not boolean")
            if not type(self.parameters[AUTHN_MAKE_CREDENTIAL.OPTIONS.value][AUTHN_MAKE_CREDENTIAL.OPTIONS_UV.value]) == bool:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"option uv not boolean")

    def get_hash(self):
        return self.parameters[AUTHN_MAKE_CREDENTIAL.HASH.value]
    def get_rp_entity(self):
        return self.parameters[AUTHN_MAKE_CREDENTIAL.RP.value]

    def get_user_entity(self):
        return self.user_entity
    def get_require_resident_key(self):
        if AUTHN_MAKE_CREDENTIAL.OPTIONS.value in self.parameters:
            if AUTHN_MAKE_CREDENTIAL.OPTIONS_RK.value in self.parameters[AUTHN_MAKE_CREDENTIAL.OPTIONS.value]:
                return self.parameters[AUTHN_MAKE_CREDENTIAL.OPTIONS.value][AUTHN_MAKE_CREDENTIAL.OPTIONS_RK.value]
            else:
                return False
        else:
            return False
    def get_user_presence(self):
        return True#Not present in the current version of CTAP. Authenticators are assumed to always check user presence.
    def require_user_verification(self):
        if AUTHN_MAKE_CREDENTIAL.OPTIONS.value in self.parameters:
            if AUTHN_MAKE_CREDENTIAL.OPTIONS_UV.value in self.parameters[AUTHN_MAKE_CREDENTIAL.OPTIONS.value]:
                return self.parameters[AUTHN_MAKE_CREDENTIAL.OPTIONS.value][AUTHN_MAKE_CREDENTIAL.OPTIONS_UV.value]
            else:
                return False
        else:
            return False
    def get_cred_types_and_pubkey_algs(self):
        return self.parameters[AUTHN_MAKE_CREDENTIAL.PUBKEY_CRED_PARAMS.value]
    def get_exclude_credential_descriptor_list(self):
        return self.exclude_list
        #return self.parameters[AUTHN_MAKE_CREDENTIAL.EXCLUDE_LIST.value]
    
    def get_extensions(self):
        
        return self.parameters[AUTHN_MAKE_CREDENTIAL.EXTENSIONS.value]
   
    def get_pin_auth(self):
        if not AUTHN_MAKE_CREDENTIAL.PIN_AUTH.value in self.parameters:
            return None
        return self.parameters[AUTHN_MAKE_CREDENTIAL.PIN_AUTH.value]
    
    def get_pin_protocol(self):
        if not AUTHN_MAKE_CREDENTIAL.PIN_PROTOCOL.value in self.parameters:
            return -1
        return self.parameters[AUTHN_MAKE_CREDENTIAL.PIN_PROTOCOL.value]

class GetClientPINResp(CBORResponse):

    def __init__(self,key_agreement:{} = None, pin_token:bytes=None,retries:int=None):
        super(GetClientPINResp,self).__init__()
        self.content = {}
        if not key_agreement is None:
            self.content[AUTHN_GET_CLIENT_PIN_RESP.KEY_AGREEMENT.value] = key_agreement
            self.content[AUTHN_GET_CLIENT_PIN_RESP.KEY_AGREEMENT.value][3]=-25
        if not pin_token is None:
            self.content[AUTHN_GET_CLIENT_PIN_RESP.PIN_TOKEN.value] = pin_token
        if not retries is None:
            self.content[AUTHN_GET_CLIENT_PIN_RESP.RETRIES.value] = retries

class MakeCredentialResp(CBORResponse):

    def __init__(self,content):
        super(MakeCredentialResp,self).__init__()
        self.content = content

class GetAssertionResp(CBORResponse):

    def __init__(self,content, count):
        super(GetAssertionResp,self).__init__()
        self.content = content
        self.count=count

    def get_count(self)->int:
        return self.count
class GetNextAssertionResp(CBORResponse):

    def __init__(self,content, count:int):
        super(GetNextAssertionResp,self).__init__()
        self.content = content
        self.count = count

    def get_count(self)->int:
        return self.count

class ResetResp(CBORResponse):

    def __init__(self):
        super(ResetResp,self).__init__()
        

class GetInfoResp(CBORResponse):

    def __init__(self):
        super(GetInfoResp,self).__init__()
        self.set_check = {}
        # Default to internal AAGUID
        self.content[AUTHN_GETINFO.AAGUID.value] = DICEAuthenticator.AUTHENTICATOR_AAGUID.bytes
        #self.set_default_options()
        pass

    def set_default_options(self):
        self.set_option(AUTHN_GETINFO_OPTION.PLATFORM_DEVICE, False)
        self.set_option(AUTHN_GETINFO_OPTION.RESIDENT_KEY, False)
        self.set_option(AUTHN_GETINFO_OPTION.USER_PRESENCE, True)
        self.set_option(AUTHN_GETINFO_OPTION.USER_VERIFICATION_TOKEN, False)
        self.set_option(AUTHN_GETINFO_OPTION.CONFIG, False)

    def _add_to_dict(self, parameter: AUTHN_GETINFO, field: AUTHN_GETINFO_PARAMETER, value):
        if not parameter.value in self.content:
            self.content[parameter.value] = {}
        self.content[parameter.value][field.value]=value

    def _add_dict_to_list(self, parameter: AUTHN_GETINFO, value: dict):
        if not parameter.value in self.content:
            self.content[parameter.value] = []
        self.content[parameter.value].append(value)
        

    def _add_to_list(self, parameter: AUTHN_GETINFO, value: AUTHN_GETINFO_PARAMETER):
        if not parameter.value in self.content:
            self.content[parameter.value] = []
            self.set_check[parameter.value] = set()
        if not value.value in self.set_check[parameter.value]:
            self.content[parameter.value].append(value.value)
            self.set_check[parameter.value].add(value.value)
        else:
            raise Exception("Duplicate value in list or sequence")

    def add_version(self, version: AUTHN_GETINFO_VERSION):
        self._add_to_list(AUTHN_GETINFO.VERSIONS, version)

    def add_pin_uv_supported_protocol(self, protocol: AUTHN_GETINFO_PIN_UV_PROTOCOL):
        self._add_to_list(AUTHN_GETINFO.PIN_UV_AUTH_PROTOCOLS, protocol)

    def get(self, parameter: AUTHN_GETINFO):
        return self.content[parameter.value]

    def add_extension(self, extension):
        self._add_to_list(AUTHN_GETINFO.EXTENSIONS, extension)

    def set_auguid(self, aaguid: UUID):
        self.content[AUTHN_GETINFO.AAGUID.value] = aaguid.bytes

    def set_option(self, option: AUTHN_GETINFO_OPTION, value: bool):
        self._add_to_dict(AUTHN_GETINFO.OPTIONS, option, value)

    def set(self, parameter: AUTHN_GETINFO, value):
        self.content[parameter.value] = value

    def add_transport(self, transport: AUTHN_GETINFO_TRANSPORT):
        self._add_to_list(AUTHN_GETINFO.TRANSPORTS, transport)

    def add_algorithm(self, algorithm: PublicKeyCredentialParameters):
        self._add_dict_to_list(AUTHN_GETINFO.ALGORITHMS, algorithm)

        
class DICEAuthenticator(DICEAuthenticatorListener):
    AUTHENTICATOR_AAGUID = UUID("695e437f-c0cd-4fe8-b545-d39084f5c805")
    PIN_TOKEN_LENGTH = 64
    def __init__(self, pin_token_length=PIN_TOKEN_LENGTH, ui:DICEAuthenticatorUI=ConsoleAuthenticatorUI()):
        self._create_debug_logs()
        self._last_get_assertion_cid = None
        self._last_get_assertion_params =  None
        self._last_get_assertion_time = None
        self._last_get_assertion_idx = None
        self._storage = None
        self._pin_crypto_provider= ES256CryptoProvider()
        #self._ctap_hid = ctap_hid
        self._generate_authenticatorKeyAgreementKey()
        self._generate_pinToken(pin_token_length)
        self._ui = ui
        if not self._ui is None:
            self._ui.add_listener(self)
        
    def shutdown(self):
        self._usbhid.shutdown()

    def _start(self,device:str="/dev/dicekey"):
        self._usbdevice = os.open(device, os.O_RDWR)
        self._usbhid = USBHID(self._usbdevice)
        import CTAPHID
        self._ctaphid = CTAPHID.CTAPHID(self._usbhid)
        self._ctaphid.set_authenticator(self)
        self._usbhid.set_listener(self._ctaphid)
        self._usbhid.start()
        if not self._ui is None:
            self._ui.start()

        """
        while 1:
            for line in sys.stdin:
                if line.rstrip() == "quit":
                    log.debug("Quit Called")
                    #This doesn't actually kill the thread because python handles threads in a bizarre way
                    usbhid.shutdown()
                    sys.exit()
        else:
            log.debug("Unknown command entered on CLI: %s",line.rstrip() )
        """

    def _create_debug_logs(self):
        timestr = time.strftime("%Y%m%d-%H%M%S")    
        if not os.path.exists("./logs/"):
            os.mkdir("./logs/")
        else:
            source_dir = './logs/'
            target_dir = './logs/archive/'
            if not os.path.exists(target_dir):
                os.mkdir(target_dir)
            file_names = os.listdir(source_dir)
            for file_name in file_names:
                shutil.move(os.path.join(source_dir, file_name), target_dir)

        self._setup_logger('debug', r'./logs/debug_'+timestr+'.log')
        self._setup_logger('debug.usbhid', r'./logs/usbhid_'+timestr+'.log')
        self._setup_logger('debug.ctap', r'./logs/ctap_'+timestr+'.log')
        self._setup_logger('debug.auth', r'./logs/auth_'+timestr+'.log')
    
    def _setup_logger(self, logger_name, log_file, level=logging.DEBUG):
        l = logging.getLogger(logger_name)
        
        formatter = logging.Formatter('%(asctime)s : %(levelname)s : %(message)s')
        fileHandler = logging.FileHandler(log_file, mode='w')
        if logger_name=="debug":
            formatter = logging.Formatter('%(asctime)s : %(levelname)s : %(message)s')
            fileHandler.setFormatter(formatter)
            streamHandler = logging.StreamHandler()
            streamHandler.setFormatter(formatter)
            l.addHandler(streamHandler)    
            l.propagate = False
        else:
            fileHandler.setFormatter(formatter)
            l.propagate = True
        l.setLevel(level)
        l.addHandler(fileHandler)

    def _generate_pinToken(self,pin_token_length:int):
        auth.debug("Generating new pinToken")
        self._pin_token = os.urandom(pin_token_length)
    def _generate_authenticatorKeyAgreementKey(self):
        auth.debug("Generating new authenticatorKeyAgreementKey")
        self._authenticatorKeyAgreementKey = self._get_pin_crypto_provider().create_new_key_pair()

    def get_AAGUID(self):
        return DICEAuthenticator.AUTHENTICATOR_AAGUID

    def process_cbor(self, cbor_data:bytes, keep_alive: CTAPHIDKeepAlive, CID:bytes=None):
        if not bytes is None:
            self.check_get_last_assertion_cid(CID)

        cmd = cbor_data[:1]
        auth.debug("Received %s CBOR: %s", AUTHN_CMD(cmd).name, cbor_data.hex())
        if cmd == AUTHN_CMD.AUTHN_MakeCredential.value:
            params = AuthenticatorMakeCredentialParameters(cbor_data[1:])
            return self.authenticatorMakeCredential(params, keep_alive).get_encoded()
        elif cmd == AUTHN_CMD.AUTHN_GetAssertion.value:
            params = AuthenticatorGetAssertionParameters(cbor_data[1:])
            get_assertion_resp = self.authenticatorGetAssertion(params, keep_alive)
            if get_assertion_resp.get_count() > 1:
                self.set_get_assertion_params_start_timer(CID,params,1)
            else:
                self.clear_get_last_assertion()
            return get_assertion_resp.get_encoded()
        elif cmd == AUTHN_CMD.AUTHN_GetInfo.value:
            return self.authenticatorGetInfo(keep_alive).get_encoded()
        elif cmd == AUTHN_CMD.AUTHN_ClientPIN.value:
            params = AuthenticatorGetClientPINParameters(cbor_data[1:])
            return self.authenticatorGetClientPIN(params, keep_alive).get_encoded()
        elif cmd == AUTHN_CMD.AUTHN_Reset.value:
            return self.authenticatorReset(keep_alive).get_encoded()
        elif cmd == AUTHN_CMD.AUTHN_GetNextAssertion.value:
            last = self.get_last_assertion_params(CID)
            get_next_resp = self.authenticatorGetNextAssertion(last["params"], last["idx"], keep_alive)
            self.set_get_assertion_params_idx_reset_timer(last["idx"]+1)
            return get_next_resp.get_encoded()
        elif cmd == AUTHN_CMD.AUTHN_BioEnrollment.value:
            pass
        elif cmd == AUTHN_CMD.AUTHN_CredentialManagement.value:
            pass
        elif cmd == AUTHN_CMD.AUTHN_PlatformConfig.value:
            pass
        elif cmd == AUTHN_CMD.AUTHN_CredentialManagement.value:
            pass
        elif cmd == AUTHN_CMD.AUTHN_VendorFirst.value:
            pass
        elif cmd == AUTHN_CMD.AUTHN_VendorLast.value:
            pass

    @abstractmethod
    def process_wink(self, payload:bytes, keep_alive: CTAPHIDKeepAlive)->bytes:
        pass

    def set_get_assertion_params_start_timer(self, CID:bytes,params:AuthenticatorGetAssertionParameters, idx:int):
        auth.debug("Setting getAssertion %s for Channel: %s with Index: %s", params, CID, idx)
        self._last_get_assertion_cid = CID
        self._last_get_assertion_params =  params
        self._last_get_assertion_time = int(time.time())
        self._last_get_assertion_idx = idx
    
    def set_get_assertion_params_idx_reset_timer(self, idx:int):
        auth.debug("Incrementing getAssertion Index: %s", idx)
        self._last_get_assertion_idx = idx
        self._last_get_assertion_time = int(time.time())

    def clear_get_last_assertion(self):
        auth.debug("Clearing get assertion")
        self._last_get_assertion_cid = None
        self._last_get_assertion_params =  None
        self._last_get_assertion_time = None
        self._last_get_assertion_idx = None
    
    def get_last_assertion_cid(self):
        return self._last_get_assertion_cid

    def check_get_last_assertion_cid(self, CID:bytes)->bool:
        auth.debug("Checking last assertion Channel: %s with incoming: %s", self.get_last_assertion_cid(), CID)
        if not self.get_last_assertion_cid() is None and self._last_get_assertion_cid != bytes:
            auth.debug("Channels don't match, clearing last assertion")
            self.clear_get_last_assertion()
            return False
        auth.debug("Channels match, last assertion not cleared")
        return True
    
    def get_last_assertion_params(self, CID:bytes):
        if self._last_get_assertion_time is None:
            auth.debug("No last assertions found")
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED,"No last assertions found")
        if int(time.time())-self._last_get_assertion_time >30:
            auth.debug("Last assertion has timed out")
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED,"Last assertion has timed out")
        if not self.check_get_last_assertion_cid(CID):
            auth.debug("Last assertion mismatched channel ID")
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED,"Mismatched channel ID")
        ret = {}
        ret["params"]=self._last_get_assertion_params
        ret["idx"]=self._last_get_assertion_idx
        auth.debug("Returning stored last assertion: %s",ret)
        return ret

    @abstractmethod
    def authenticatorGetInfo(self, keep_alive:CTAPHIDKeepAlive) -> GetInfoResp:
        pass

    @abstractmethod
    def authenticatorMakeCredential(self, params:AuthenticatorMakeCredentialParameters,keep_alive:CTAPHIDKeepAlive) -> MakeCredentialResp:
        pass

    @abstractmethod
    def authenticatorGetAssertion(self, params:AuthenticatorGetAssertionParameters,keep_alive:CTAPHIDKeepAlive) -> GetAssertionResp:
        pass

    def authenticatorGetClientPIN(self, params:AuthenticatorGetClientPINParameters,keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        subcmd = params.get_sub_command()
        if subcmd == AUTHN_GET_CLIENT_PIN_SUBCMD.GET_RETRIES.value:
            return self.authenticatorGetClientPIN_getRetries(params,keep_alive)
        elif subcmd == AUTHN_GET_CLIENT_PIN_SUBCMD.GET_KEY_AGREEMENT.value:
            return self.authenticatorGetClientPIN_getKeyAgreement(params,keep_alive)
        elif subcmd == AUTHN_GET_CLIENT_PIN_SUBCMD.SET_PIN.value:
            return self.authenticatorGetClientPIN_setPIN(params,keep_alive)
        elif subcmd == AUTHN_GET_CLIENT_PIN_SUBCMD.CHANGE_PIN.value:
            return self.authenticatorGetClientPIN_changePIN(params,keep_alive)
        elif subcmd == AUTHN_GET_CLIENT_PIN_SUBCMD.GET_PIN_TOKEN.value:
            return self.authenticatorGetClientPIN_getPINToken(params,keep_alive)
        else:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER,"Invalid sub command")

    @abstractmethod
    def authenticatorGetClientPIN_getRetries(self, params:AuthenticatorGetClientPINParameters,keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        pass

    @abstractmethod
    def authenticatorGetClientPIN_getKeyAgreement(self, params:AuthenticatorGetClientPINParameters,keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        pass

    @abstractmethod
    def authenticatorGetClientPIN_setPIN(self, params:AuthenticatorGetClientPINParameters,keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        pass
    @abstractmethod
    def authenticatorGetClientPIN_changePIN(self, params:AuthenticatorGetClientPINParameters,keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        pass
    
    @abstractmethod
    def authenticatorGetClientPIN_getPINToken(self, params:AuthenticatorGetClientPINParameters,keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        pass

    @abstractmethod
    def authenticatorGetNextAssertion(self, params:AuthenticatorGetAssertionParameters, idx:int, keep_alive:CTAPHIDKeepAlive) -> GetNextAssertionResp:
        pass

    @abstractmethod
    def authenticatorReset(self, keep_alive:CTAPHIDKeepAlive) -> ResetResp:
        pass 
 
    @abstractmethod
    def get_version(self)->AuthenticatorVersion:
        pass
    def _get_credential_data(self,credential_source:PublicKeyCredentialSource):
        """	                    Length (in bytes) 	Description
            aaguid 	            16 	                The AAGUID of the authenticator.
            credentialIdLength 	2 	                Byte length L of Credential ID, 16-bit unsigned big-endian integer.
            credentialId 	    L 	                Credential ID
            credentialPublicKey variable 	        The credential public key encoded in COSE_Key format, as defined in Section 7 of [RFC8152], using the CTAP2 canonical CBOR encoding form. The COSE_Key-encoded credential public key MUST contain the "alg" parameter and MUST NOT contain any other OPTIONAL parameters. The "alg" parameter MUST contain a COSEAlgorithmIdentifier value. The encoded credential public key MUST also contain any additional REQUIRED parameters stipulated by the relevant key type specification, i.e., REQUIRED for the key type "kty" and algorithm "alg" (see Section 8 of [RFC8152]). 
        """
        credential_data = self.get_AAGUID().bytes
        credential_data += len(credential_source.get_id()).to_bytes(2,"big")
        credential_data += credential_source.get_id()
        credential_data += cbor.encode(credential_source.get_cose_public_key())
        return credential_data
    
    def _get_authenticator_data_minus_creds(self, credential_source:PublicKeyCredentialSource, up:bool, uv:bool=False,extensions:bytes=None):
        """
        Name 	Length (in bytes) 	Description
        rpIdHash 	32 	SHA-256 hash of the RP ID the credential is scoped to.
        flags 	1 	Flags (bit 0 is the least significant bit):
                        Bit 0: User Present (UP) result.
                            1 means the user is present.
                            0 means the user is not present.
                        Bit 1: Reserved for future use (RFU1).
                        Bit 2: User Verified (UV) result.
                            1 means the user is verified.
                            0 means the user is not verified.
                        Bits 3-5: Reserved for future use (RFU2).
                        Bit 6: Attested credential data included (AT).
                            Indicates whether the authenticator added attested credential data.
                        Bit 7: Extension data included (ED).
                            Indicates if the authenticator data has extensions.
        signCount 	4 	Signature counter, 32-bit unsigned big-endian integer.
        extensions 	variable (if present) 	Extension-defined authenticator data. This is a CBOR [RFC7049] map with extension identifiers as keys, and authenticator extension outputs as values. See §9 WebAuthn Extensions for details. 
        """
        digest = hashes.Hash(hashes.SHA256(),default_backend())
        digest.update(credential_source.get_rp_id().encode('UTF-8'))
        data = digest.finalize()
        flags = 0
        
        if up:
            flags = flags ^ (1 << 0)
        if uv:
            flags = flags ^ (1 << 2)
        
        data += flags.to_bytes(1,"big")
        #data[32] = data[32] ^ (0 << 7) set extension flag
        data += credential_source.get_signature_counter_bytes()
        return data

    def _get_authenticator_data(self, credential_source:PublicKeyCredentialSource, up:bool, uv:bool=False,extensions:bytes=None):
        """
        Name 	Length (in bytes) 	Description
        rpIdHash 	32 	SHA-256 hash of the RP ID the credential is scoped to.
        flags 	1 	Flags (bit 0 is the least significant bit):
                        Bit 0: User Present (UP) result.
                            1 means the user is present.
                            0 means the user is not present.
                        Bit 1: Reserved for future use (RFU1).
                        Bit 2: User Verified (UV) result.
                            1 means the user is verified.
                            0 means the user is not verified.
                        Bits 3-5: Reserved for future use (RFU2).
                        Bit 6: Attested credential data included (AT).
                            Indicates whether the authenticator added attested credential data.
                        Bit 7: Extension data included (ED).
                            Indicates if the authenticator data has extensions.
        signCount 	4 	Signature counter, 32-bit unsigned big-endian integer.
        attestedCredentialData 	variable (if present) 	attested credential data (if present). See §6.4.1 Attested Credential Data for details. Its length depends on the length of the credential ID and credential public key being attested.
        extensions 	variable (if present) 	Extension-defined authenticator data. This is a CBOR [RFC7049] map with extension identifiers as keys, and authenticator extension outputs as values. See §9 WebAuthn Extensions for details. 
        """
        digest = hashes.Hash(hashes.SHA256(),default_backend())
        digest.update(credential_source.get_rp_id().encode('UTF-8'))
        data = digest.finalize()
        flags = 0
        
        if up:
            flags = flags ^ (1 << 0)
        if uv:
            flags = flags ^ (1 << 2)
        flags = flags ^ (1 << 6)
        data += flags.to_bytes(1,"big")
        #data[32] = data[32] ^ (0 << 7) set extension flag
        data += credential_source.get_signature_counter_bytes()
        data += self._get_credential_data(credential_source)
        return data
    
    def _get_pin_crypto_provider(self)->AuthenticatorCryptoProvider:
        return self._pin_crypto_provider
    
    def _generate_shared_secret(self,key_agreement:{})->bytes:
        platformKeyAgreementKey = self._get_pin_crypto_provider().public_key_from_cose(key_agreement)
        return self._authenticatorKeyAgreementKey.get_private_key().exchange(platformKeyAgreementKey.get_public_key())
    
    def _calculate_pin_auth(self, *args)->bytes:
        h = hmac.HMAC(args[0], hashes.SHA256(),default_backend())
        argitr = iter(args)
        next(argitr)
        for val in argitr:
            h.update(val)
        return h.finalize()
    
    def _decrypt_value(self, shared_secret, ciphertext)->bytes:
        cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(bytes(16)),default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext)
    
    def _encrypt_value(self, shared_secret, plaintext)->bytes:
        cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(bytes(16)),default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()
    def _extract_pin(self, pin_bytes:bytes)->str:
        for i in range(len(pin_bytes)):
            if pin_bytes[i]== b'\x00'[0]:
                return pin_bytes[:i].decode('utf-8')
    
    def _sha256(self, value)->bytes:   
        digest = hashes.Hash(hashes.SHA256(),default_backend())
        
        if type(value) is str:
            digest.update(value.encode())
        else:
            digest.update(value)
        return digest.finalize()

    def _check_pin(self, pin_auth:bytes, pin_protocol:int, client_hash:bytes, error_on_no_auth=True)->bool:
        
        if not pin_auth is None and pin_protocol == 1:
            if self._storage.get_pin() is None:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_INVALID,"PIN Invalid")
            #verify PIN
            if pin_auth[:16] == self._calculate_pin_auth(self._pin_token,client_hash)[:16]:
                auth.debug("PIN Verified")
                return True
            else:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_INVALID,"PIN Invalid")
        elif not pin_auth is None and pin_protocol != 1:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_INVALID,"Unsupport PIN Protocol")
        elif not self._storage.get_pin() is None and (not pin_auth is None or pin_protocol != 1):
            if error_on_no_auth:
                raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_REQUIRED,"PIN Required")
            else:
                return False
class DICEAuthenticatorException(Exception):
    """Exception raised when accessing the storage medium

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, err_code:CTAPHIDConstants.CTAP_STATUS_CODE,message="Storage Exception"):
        self.message = message
        self.err_code = err_code
        super().__init__(self.message)
    
    def get_error_code(self):
        return self.err_code
   