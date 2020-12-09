from enum import Enum, unique
from crypto.algs import PUBLIC_KEY_ALG
import ctap.constants
from ctap.constants import (AUTHN_GET_ASSERTION,AUTHN_MAKE_CREDENTIAL, 
    AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY, 
    AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY,AUTHN_GET_CLIENT_PIN,
    AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR)
import fido2
import logging
log = logging.getLogger('debug')
auth = logging.getLogger('debug.auth')

def keys_exist_in_dict(keys:[],dict_value:{})->bool:
    for key in keys:
        if not key in dict_value:
            return False
    return True
def keys_do_not_exist_in_dict(keys:[],dict_value:{})->bool:
    for key in keys:
        if key in dict_value:
            return False
    return True
def only_keys_in_dict(keys,dict_value:{})->bool:
    if type(keys) is Enum:
        for e in keys:
            if not e.value in dict_value:
                return False
        if len(dict_value) != len(keys.__members__):
            return False
    else:
        for key in keys:
            if not key in dict_value:
                return False
        if len(dict_value) != len(keys):
            return False
    return True

class AuthenticatorVersion:
    def __init__(self, ctaphid_protocol_version:int=2, major_version:int=1, minor_version:int=0, build_version:int=0):
        self.ctaphid_protocol_version=ctaphid_protocol_version
        self.major_version=major_version
        self.minor_version=minor_version
        self.build_version=build_version

class PublicKeyCredentialParameters(dict):
    def __init__(self, algo: PUBLIC_KEY_ALG, type="public-key"):
        super(PublicKeyCredentialParameters,self).__init__()
        self.__setitem__("type",type)
        self.__setitem__("alg",algo.value)

class PublicKeyCredentialRpEntity():
    def __init__(self, data:dict):
        self.parameters = data
        self.verify()
    
    def get_as_dict(self):
        return self.parameters
        
    def verify(self):
        if not AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.ID.value in self.parameters:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"Missing ID in rpEntity")
        
        if not type(self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.ID.value]) is str:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"id in rpEntity not str")
        
        if AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.NAME.value in self.parameters:
            if not type(self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.NAME.value]) is str:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"name in rpEntity not str")
        
        if AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.ICON.value in self.parameters:
            if not type(self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.ICON.value]) is str:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"icon in rpEntity not str")

    def get_id(self):
        return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.ID.value]
    
    
    def get_name(self):
        if AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.NAME.value in self.parameters:
            return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.NAME.value]
        else:
            return None
    
    def get_icon(self):
        if AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.ICON.value in self.parameters:
            return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.ICON.value]
        else:
            return None
    
class PublicKeyCredentialUserEntity():
    def __init__(self, data:dict):
        self.parameters = data
        self.verify()
    
    def get_as_dict(self):
        return self.parameters
        
    def verify(self):
        if not AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.ID.value in self.parameters:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"Missing ID in UserEntity")
        if not AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.DISPLAYNAME.value in self.parameters:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"Missing displayName in UserEntity")
        
        if not type(self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.ID.value]) is bytes:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"id in UserEntity not bytes")
        if not type(self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.DISPLAYNAME.value]) is str:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"displayName in UserEntity not str")
        
        if AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.NAME.value in self.parameters:
            if not type(self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.NAME.value]) is str:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"name in UserEntity not str")
        
        if AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.ICON.value in self.parameters:
            if not type(self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.ICON.value]) is str:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"icon in UserEntity not str")

    def get_id(self):
        return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.ID.value]
    
    def get_display_name(self):
        return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.DISPLAYNAME.value]
    
    def get_name(self):
        if AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.NAME.value in self.parameters:
            return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.NAME.value]
        else:
            return None
    
    def get_icon(self):
        if AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.ICON.value in self.parameters:
            return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.ICON.value]
        else:
            return None


class AuthenticatorGetClientPINParameters:
    """
    pinProtocol (0x01) 	Unsigned Integer 	Required 	PIN protocol version chosen by the client. For this version of the spec, this SHALL be the number 1.
    subCommand (0x02) 	Unsigned Integer 	Required 	The authenticator Client PIN sub command currently being requested
    keyAgreement (0x03) 	COSE_Key 	Optional 	Public key of platformKeyAgreementKey. The COSE_Key-encoded public key MUST contain the optional "alg" parameter and MUST NOT contain any other optional parameters. The "alg" parameter MUST contain a COSEAlgorithmIdentifier value.
    pinAuth (0x04) 	Byte Array 	Optional 	First 16 bytes of HMAC-SHA-256 of encrypted contents using sharedSecret. See Setting a new PIN, Changing existing PIN and Getting pinToken from the authenticator for more details.
    newPinEnc (0x05) 	Byte Array 	Optional 	Encrypted new PIN using sharedSecret. Encryption is done over UTF-8 representation of new PIN.
    pinHashEnc (0x06) 	Byte Array 	Optional 	Encrypted first 16 bytes of SHA-256 of PIN using sharedSecret. """

    def __init__(self, cbor_data:bytes):
        self.parameters = fido2.cbor.decode(cbor_data)
        auth.debug("Decoded GetClientPINParameters: %s", self.parameters)        
        self.verify()

    def verify(self):
        if not AUTHN_GET_CLIENT_PIN.PIN_PROTOCOL.value in self.parameters:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"pinProtocol missing")
        
        if not AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value in self.parameters:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"subCommand missing")
        
        if not type(self.parameters[AUTHN_GET_CLIENT_PIN.PIN_PROTOCOL.value]) == int:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"pinProtocol not integer")
        
        if not type(self.parameters[AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value]) == int:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"subCommand not integer")

        if AUTHN_GET_CLIENT_PIN.KEY_AGREEMENT.value in self.parameters:
            #Verify Key Agreement
            if not type(self.parameters[AUTHN_GET_CLIENT_PIN.KEY_AGREEMENT.value]) is dict:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"pinAgreement not dictionary")
            if not 3 in self.parameters[AUTHN_GET_CLIENT_PIN.KEY_AGREEMENT.value]:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"missing alg parameter")
            #TODO verify COSE key
        
        if AUTHN_GET_CLIENT_PIN.PIN_AUTH.value in self.parameters:
            if not type(self.parameters[AUTHN_GET_CLIENT_PIN.PIN_AUTH.value]) is bytes:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"pinAuth not bytes")
        
        if AUTHN_GET_CLIENT_PIN.NEW_PIN_ENC.value in self.parameters:
            if not type(self.parameters[AUTHN_GET_CLIENT_PIN.NEW_PIN_ENC.value]) is bytes:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"newPinEnc not bytes")

        if AUTHN_GET_CLIENT_PIN.PIN_HASH_ENC.value in self.parameters:
            if not type(self.parameters[AUTHN_GET_CLIENT_PIN.PIN_HASH_ENC.value]) is bytes:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"pinHashEnc not bytes")
        
        sub_command = self.parameters[AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value]
        if not (sub_command >=1 and sub_command<=5):
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_COMMAND,"invalid subCommand")

        if sub_command == 1 or sub_command == 2:
            if not only_keys_in_dict([AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value,AUTHN_GET_CLIENT_PIN.PIN_PROTOCOL.value],self.parameters):
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER,"invalid parameters found")

        if sub_command == 3:
            if not only_keys_in_dict([AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value,AUTHN_GET_CLIENT_PIN.PIN_PROTOCOL.value,AUTHN_GET_CLIENT_PIN.NEW_PIN_ENC.value,AUTHN_GET_CLIENT_PIN.PIN_AUTH.value,AUTHN_GET_CLIENT_PIN.KEY_AGREEMENT.value],self.parameters):
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER,"invalid parameters found")
        
        if sub_command == 4:
            if not only_keys_in_dict([AUTHN_GET_CLIENT_PIN],self.parameters):
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER,"invalid parameters found")
        
        if sub_command == 5:
            if not only_keys_in_dict([AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value,AUTHN_GET_CLIENT_PIN.PIN_PROTOCOL.value,AUTHN_GET_CLIENT_PIN.KEY_AGREEMENT.value,AUTHN_GET_CLIENT_PIN.PIN_HASH_ENC.value],self.parameters):
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER,"invalid parameters found")
        
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
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"PublicKeyCredentialDesc missing type")
        if not AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.ID.value in self.parameters:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"PublicKeyCredentialDesc missing id")
        if not self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.TYPE.value] == AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.TYPE_PUBLIC_KEY.value:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"PublicKeyCredentialDesc type not recognised")
        if not type(self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.ID.value]) is bytes:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"PublicKeyCredentialDesc id not bytes")
        
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
        self.parameters = fido2.cbor.decode(cbor_data)
        
        self.allow_list = []
        for allowed in self.parameters[AUTHN_GET_ASSERTION.ALLOW_LIST.value]:
            self.allow_list.append(PublicKeyCredentialDescriptor(allowed))
        self.verify()
        auth.debug("Decoded GetAssertionParameters: %s", self.parameters)        
        

    def verify(self):
        if not AUTHN_GET_ASSERTION.RP_ID.value in self.parameters:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"rpId missing")
        
        if not AUTHN_GET_ASSERTION.HASH.value in self.parameters:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"clientDataHash missing")
        
        if not type(self.parameters[AUTHN_GET_ASSERTION.RP_ID.value]) == str:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"rpId not string")
        
        if not type(self.parameters[AUTHN_GET_ASSERTION.HASH.value]) == bytes:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"clientDataHash not bytes")

        if AUTHN_GET_ASSERTION.ALLOW_LIST.value in self.parameters:
            if not type(self.parameters[AUTHN_GET_ASSERTION.ALLOW_LIST.value]) == list:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"allowList not sequence")
        if AUTHN_GET_ASSERTION.PIN_AUTH.value in self.parameters:
            if not type(self.parameters[AUTHN_GET_ASSERTION.PIN_AUTH.value]) == bytes:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"pinAuth not bytes")
        if AUTHN_GET_ASSERTION.PIN_PROTOCOL.value in self.parameters:
            if not type(self.parameters[AUTHN_GET_ASSERTION.PIN_PROTOCOL.value]) == int:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"pinProtocol not int")
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
        self.parameters = fido2.cbor.decode(cbor_data)
        auth.debug("Decoded MakeCredentialParameters: %s", self.parameters)
        self.verify()
        self.user_entity = PublicKeyCredentialUserEntity(self.parameters[AUTHN_MAKE_CREDENTIAL.USER.value])
        self.rp_entity = PublicKeyCredentialRpEntity(self.parameters[AUTHN_MAKE_CREDENTIAL.RP.value])
        self.exclude_list = []
        if AUTHN_MAKE_CREDENTIAL.EXCLUDE_LIST.value in self.parameters:
            for exclude in self.parameters[AUTHN_MAKE_CREDENTIAL.EXCLUDE_LIST.value]:
                self.exclude_list.append(PublicKeyCredentialDescriptor(exclude))
    
    def verify(self):
        if not AUTHN_MAKE_CREDENTIAL.RP.value in self.parameters:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"rpId missing")

        if not AUTHN_MAKE_CREDENTIAL.HASH.value in self.parameters:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"clientDataHash missing")
        
        if not AUTHN_MAKE_CREDENTIAL.USER.value in self.parameters:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"user missing")

        if not AUTHN_MAKE_CREDENTIAL.PUBKEY_CRED_PARAMS.value in self.parameters:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"publicKeyCredentials missing")
        
        if not type(self.parameters[AUTHN_MAKE_CREDENTIAL.PUBKEY_CRED_PARAMS.value]) == list:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"publicKeyCredentials not list")

        for cred in self.parameters[AUTHN_MAKE_CREDENTIAL.PUBKEY_CRED_PARAMS.value]:
            if not type(cred) == dict:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"publicKeyCredential not dictionary")
            if not "type" in cred:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"publicKeyCredential type missing")
            if not "alg" in cred:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"publicKeyCredential alg missing")

        
        if not type(self.parameters[AUTHN_MAKE_CREDENTIAL.RP.value]) == dict:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"rp not dictionary")
        if not type(self.parameters[AUTHN_MAKE_CREDENTIAL.USER.value]) == dict:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"user not dictionary")
        
        if not type(self.parameters[AUTHN_MAKE_CREDENTIAL.HASH.value]) == bytes:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"clientDataHash not bytes")

        if AUTHN_MAKE_CREDENTIAL.PIN_AUTH.value in self.parameters:
            if not type(self.parameters[AUTHN_MAKE_CREDENTIAL.PIN_AUTH.value]) == bytes:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"pinAuth not bytes")
        if AUTHN_MAKE_CREDENTIAL.PIN_PROTOCOL.value in self.parameters:
            if not type(self.parameters[AUTHN_MAKE_CREDENTIAL.PIN_PROTOCOL.value]) == int:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"pinProtocol not int")
        
        if AUTHN_MAKE_CREDENTIAL.OPTIONS.value in self.parameters:
            if not type(self.parameters[AUTHN_MAKE_CREDENTIAL.OPTIONS.value][AUTHN_MAKE_CREDENTIAL.OPTIONS_RK.value]) == bool:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"option rk not boolean")
            if not type(self.parameters[AUTHN_MAKE_CREDENTIAL.OPTIONS.value][AUTHN_MAKE_CREDENTIAL.OPTIONS_UV.value]) == bool:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,"option uv not boolean")

    def get_hash(self):
        return self.parameters[AUTHN_MAKE_CREDENTIAL.HASH.value]
    def get_rp_entity(self):
        return self.rp_entity

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

class DICEAuthenticatorException(Exception):
    """Exception raised when accessing the storage medium

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, err_code:ctap.constants.CTAP_STATUS_CODE,message="Storage Exception"):
        self.message = message
        self.err_code = err_code
        super().__init__(self.message)
    
    def get_error_code(self):
        return self.err_code