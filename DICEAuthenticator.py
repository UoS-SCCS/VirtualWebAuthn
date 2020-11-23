from abc import ABC, abstractmethod
from CTAPHID import CTAPHIDTransaction
import CTAPHIDConstants
from CTAPHIDKeepAlive import CTAPHIDKeepAlive
from enum import Enum, unique
from uuid import UUID
from fido2 import cbor
from PublicKeyCredentialSource import PublicKeyCredentialSource
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import json
log = logging.getLogger('debug')
auth = logging.getLogger('debug.auth')
@unique
class AUTHN_GETINFO_PARAMETER(Enum):
    pass

@unique
class AUTHN_GETINFO_OPTION(AUTHN_GETINFO_PARAMETER):
    PLATFORM_DEVICE = "plat"  # default false - true if cannot be moved from device
    RESIDENT_KEY = "rk"  # default false - true is device capable of storing keys on itself and therefore can satisfy the authenticatorGetAssertion request with the allowList parameter omitted
    # no default, if present, true indicates PIN supported and set, false indicates PIN supported not set, absent PIN not supported
    CLIENT_PIN = "clientPin"
    USER_PRESENCE = "up"  # default true, indicates device is capable of testing user presence
    USER_VERIFICATION = "uv"  # no default, if present, true indicates device is capable of user verification and has been configured, false indicates capability but not configured, absent indicates no capability - PIN only does not constitute user verification
    # default false, indicates the device is capable of built in user verification token feature
    USER_VERIFICATION_TOKEN = "uvToken"
    CONFIG = "config"  # default false, indicates supports authenticatorConfig command


@unique
class AUTHN_GETINFO_VERSION(AUTHN_GETINFO_PARAMETER):
    CTAP2 = "FIDO_2_0"
    CTAP1 = "U2F_V2"


  


@unique
class AUTHN_GETINFO_PIN_UV_PROTOCOL(AUTHN_GETINFO_PARAMETER):
    VERSION_1 = 1


@unique
class AUTHN_GETINFO_TRANSPORT(AUTHN_GETINFO_PARAMETER):
    USB = "usb"
    NFC = "nfc"
    BLE = "ble"
    INTERNAL = "internal"


@unique
class AUTHN_GETINFO(Enum):
    VERSIONS = 1
    EXTENSIONS =2
    AAGUID = 3
    OPTIONS = 4
    MAX_MSG_SIZE = 5
    PIN_UV_AUTH_PROTOCOLS = 6
    MAX_CREDENTIAL_COUNT_IN_LIST = 7
    MAX_CREDENTIAL_ID_LENGTH = 8
    TRANSPORTS = 9
    ALGORITHMS = 10
    MAX_AUTHENTICATOR_CONFIG_LENGTH = 11
    DEFAULT_CRED_PROTECT = 12

@unique 
class AUTHN_MAKE_CREDENTIAL(Enum):
    HASH= 1
    RP= 2
    USER = 3
    PUBKEY_CRED_PARAMS=4
    EXCLUDE_LIST = 5
    EXTENSIONS = 6
    OPTIONS = 7
    PIN_AUTH = 8
    PIN_PROTOCOL = 9
    OPTIONS_RK = "rk"
    OPTIONS_UV = "UV"

@unique 
class AUTHN_GET_ASSERTION(Enum):
    RP_ID= 1
    HASH= 2
    ALLOW_LIST=3
    EXTENSIONS = 4
    OPTIONS=5
    PIN_AUTH = 6
    PIN_PROTOCOL = 7
    OPTIONS_RK = "rk"
    OPTIONS_UV = "UV"

@unique
class AUTHN_CMD(Enum):
    AUTHN_MakeCredential = b'\x01'
    AUTHN_GetAssertion = b'\x02'
    AUTHN_GetInfo = b'\x04'
    AUTHN_ClientPIN = b'\x06'
    AUTHN_Reset = b'\x07'
    AUTHN_GetNextAssertion = b'\x08'
    AUTHN_BioEnrollment = b'\x09'
    AUTHN_CredentialManagement = b'\x0A'
    AUTHN_PlatformConfig = b'\x0c'
    AUTHN_VendorFirst = b'\x40'
    AUTHN_VendorLast = b'\xBF'


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

class CBORResponse:
    def __init__(self):
        self.content = {}

    def __str__(self):
        out = {}
        out["type"] = type(self)
        out["content"]=self.content
        return json.dumps(out)

    def get_encoded(self):
        return cbor.encode(self.content)

class AuthenticatorGetAssertionParameters:
    def __init__(self, cbor_data:bytes):
        self.parameters = cbor.decode(cbor_data)
        auth.debug("Decoded GetAssertionParameters: %s", self.parameters)        
    
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
    def get_allow_list(self):
        return self.parameters[AUTHN_GET_ASSERTION.ALLOW_LIST.value]
    
    def get_extensions(self):
        return self.parameters[AUTHN_GET_ASSERTION.EXTENSIONS.value]

class AuthenticatorMakeCredentialParameters:
    def __init__(self, cbor_data:bytes):
        self.parameters = cbor.decode(cbor_data)
        auth.debug("Decoded MakeCredentialParameters: %s", self.parameters)   
    
    def get_hash(self):
        return self.parameters[AUTHN_MAKE_CREDENTIAL.HASH.value]
    def get_rp_entity(self):
        return self.parameters[AUTHN_MAKE_CREDENTIAL.RP.value]

    def get_user_entity(self):
        return self.parameters[AUTHN_MAKE_CREDENTIAL.USER.value]
    def get_require_resident_key(self):
        return self.parameters[AUTHN_MAKE_CREDENTIAL.OPTIONS.value][AUTHN_MAKE_CREDENTIAL.OPTIONS_RK.value]
    def get_user_presence(self):
        return True#Not present in the current version of CTAP. Authenticators are assumed to always check user presence.
    def require_user_verification(self):
        return self.parameters[AUTHN_MAKE_CREDENTIAL.OPTIONS.value][AUTHN_MAKE_CREDENTIAL.OPTIONS_UV.value]
        #TODO options.uv or pinAuth/pinProtocol
    def get_cred_types_and_pubkey_algs(self):
        return self.parameters[AUTHN_MAKE_CREDENTIAL.PUBKEY_CRED_PARAMS.value]
    def get_exclude_credential_descriptor_list(self):
        return self.parameters[AUTHN_MAKE_CREDENTIAL.EXCLUDE_LIST.value]
    
    def get_extensions(self):
        return self.parameters[AUTHN_MAKE_CREDENTIAL.EXTENSIONS.value]
   

class MakeCredentialResp(CBORResponse):

    def __init__(self,content):
        super(MakeCredentialResp,self).__init__()
        self.content = content

class GetAssertionResp(CBORResponse):

    def __init__(self,content):
        super(GetAssertionResp,self).__init__()
        self.content = content

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

class DICEAuthenticator:
    AUTHENTICATOR_AAGUID = UUID("695e437f-c0cd-4fe8-b545-d39084f5c805")
    def __init__(self):

        #self._ctap_hid = ctap_hid
        pass

    def get_AAGUID(self):
        return DICEAuthenticator.AUTHENTICATOR_AAGUID

    def process_cbor(self, cbor_data:bytes, keep_alive: CTAPHIDKeepAlive):
        cmd = cbor_data[:1]
        auth.debug("Received %s CBOR: %s", AUTHN_CMD(cmd).name, cbor_data.hex())
        if cmd == AUTHN_CMD.AUTHN_MakeCredential.value:
            params = AuthenticatorMakeCredentialParameters(cbor_data[1:])
            return self.authenticatorMakeCredential(params, keep_alive).get_encoded()
        elif cmd == AUTHN_CMD.AUTHN_GetAssertion.value:
            params = AuthenticatorGetAssertionParameters(cbor_data[1:])
            return self.authenticatorGetAssertion(params, keep_alive).get_encoded()
        elif cmd == AUTHN_CMD.AUTHN_GetInfo.value:
            return self.authenticatorGetInfo(keep_alive).get_encoded()
        elif cmd == AUTHN_CMD.AUTHN_ClientPIN.value:
            pass
        elif cmd == AUTHN_CMD.AUTHN_Reset.value:
            return self.authenticatorReset(keep_alive).get_encoded()
        elif cmd == AUTHN_CMD.AUTHN_GetNextAssertion.value:
            pass
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
    def authenticatorGetInfo(self, keep_alive:CTAPHIDKeepAlive) -> GetInfoResp:
        pass

    @abstractmethod
    def authenticatorMakeCredential(self, params:AuthenticatorMakeCredentialParameters,keep_alive:CTAPHIDKeepAlive) -> MakeCredentialResp:
        pass

    @abstractmethod
    def authenticatorGetAssertion(self, params:AuthenticatorGetAssertionParameters,keep_alive:CTAPHIDKeepAlive) -> GetAssertionResp:
        pass

    @abstractmethod
    def authenticatorReset(self, keep_alive:CTAPHIDKeepAlive) -> GetAssertionResp:
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