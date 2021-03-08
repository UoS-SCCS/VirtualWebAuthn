"""Contains classes for the various different parameters and
datatypes that are used by messages and CTAP, as well as the
exception class used by authenticators
Classes:
    AuthenticatorVersion
    PublicKeyCredentialParameters
    PublicKeyCredentialRpEntity
    PublicKeyCredentialUserEntity
    AuthenticatorGetClientPINParameters
    PublicKeyCredentialDescriptor
    AuthenticatorGetAssertionParameters
    AuthenticatorMakeCredentialParameters
    DICEAuthenticatorException
"""
from enum import Enum
import logging
import fido2
from crypto.algs import PUBLIC_KEY_ALG
import ctap.constants
from ctap.constants import (AUTHN_GET_ASSERTION,AUTHN_MAKE_CREDENTIAL,
    AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY,
    AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY,AUTHN_GET_CLIENT_PIN,
    AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR)
log = logging.getLogger('debug')
auth = logging.getLogger('debug.auth')

def keys_exist_in_dict(keys:[],dict_value:{})->bool:
    """Checks if all keys in list exist within the dictionary

    Args:
        keys (list): list of keys to check
        dict_value (dict): dictionary to check

    Returns:
        bool: True if all keys listed exist, otherwise False
    """
    for key in keys:
        if not key in dict_value:
            return False
    return True
def keys_do_not_exist_in_dict(keys:[],dict_value:{})->bool:
    """Checks that all the keys in the list do not exist
    in the dictionary

    Args:
        keys (list): list of keys to check
        dict_value (dict): dictionary to check

    Returns:
        bool: True if none of the keys exists, otherwise False
    """
    for key in keys:
        if key in dict_value:
            return False
    return True

def only_keys_in_dict(keys,dict_value:{})->bool:
    """Checks the values specified in keys are the only
    keys that exist in the dictionary.

    keys can be a enum or a list. In the case of enum,
    it will iterate through all members

    Args:
        keys (enum or list): keys to check
        dict_value (dict): dictionary to check

    Returns:
        bool: True if the dictionary contains all and
        only those keys specified in keys/
    """
    if isinstance(keys,Enum):
        for field in keys:
            if not field.value in dict_value:
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
    """Utility class to hold the Authenticator Version
    """
    def __init__(self, ctaphid_protocol_version:int=2,
        major_version:int=1, minor_version:int=0, build_version:int=0):
        self.ctaphid_protocol_version=ctaphid_protocol_version
        self.major_version=major_version
        self.minor_version=minor_version
        self.build_version=build_version

class PublicKeyCredentialParameters(dict):
    """Utility method to hold the PublicKeyCredential parameters

    """
    def __init__(self, algo: PUBLIC_KEY_ALG, cred_type="public-key"):
        super().__init__()
        self.__setitem__("type",cred_type)
        self.__setitem__("alg",algo.value)

class PublicKeyCredentialRpEntity():
    """Credential Relying Party Entity
    """
    def __init__(self, data:dict):
        self.parameters = data
        self.verify()

    def get_as_dict(self)->dict:
        """Return the fields in the entity as a dictionary

        Returns:
            dict: dictionary of parameters
        """
        return self.parameters

    def verify(self):
        """Verifies the parameters against the standard to
        ensure presence and type are correct.

        Raises:
            DICEAuthenticatorException: thrown if verification fails

        """
        if not AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.ID.value in self.parameters:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"Missing ID in rpEntity")

        if not isinstance(self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.ID.value],str):
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"id in rpEntity not str")

        if AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.NAME.value in self.parameters:
            if not isinstance(
                    self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.NAME.value],str):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,
                        "name in rpEntity not str")

        if AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.ICON.value in self.parameters:
            if not isinstance(
                    self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.ICON.value], str):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,
                        "icon in rpEntity not str")

    def get_id(self)->str:
        """Gets the entity ID

        Returns:
            str: entity ID, ususally the URL
        """
        return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.ID.value]


    def get_name(self)->str:
        """Gets the name of the entity. This is optional and will return
        None if not present

        Returns:
            str: name of entity or None if not set
        """
        if AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.NAME.value in self.parameters:
            return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.NAME.value]
        return None

    def get_icon(self)->str:
        """Gets the URL of the entity icon if present, or None

        Returns:
            str: URL of icon or None if not set
        """
        if AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.ICON.value in self.parameters:
            return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY.ICON.value]
        return None

class PublicKeyCredentialUserEntity():
    """Public Key User Entity
    """
    def __init__(self, data:dict):
        self.parameters = data
        self.verify()

    def get_as_dict(self)->dict:
        """Gets the User entity as a dictionary

        Returns:
            dict: dictionary of underlying parameters
        """
        return self.parameters

    def verify(self):
        """Verifies the parameters against the standard to
        ensure presence and type are correct.

        Raises:
            DICEAuthenticatorException: thrown if verification fails

        """
        if not AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.ID.value in self.parameters:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"Missing ID in UserEntity")
        #Display name is optional
        #if not AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.DISPLAYNAME.value in self.parameters:
        #    raise DICEAuthenticatorException(
        #        ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,
        #            "Missing displayName in UserEntity")

        if not isinstance(self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.ID.value],bytes):
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,"id in UserEntity not bytes")
        if AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.DISPLAYNAME.value in self.parameters:
            if not isinstance(
                    self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.DISPLAYNAME.value],str):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,
                        "displayName in UserEntity not str")

        if AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.NAME.value in self.parameters:
            if not isinstance(
                    self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.NAME.value],str):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,
                        "name in UserEntity not str")

        if AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.ICON.value in self.parameters:
            if not isinstance(
                    self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.ICON.value],str):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,
                        "icon in UserEntity not str")

    def get_id(self)->bytes:
        """Gets the user entity Id, often called the user handle

        Returns:
            bytes: user entity id
        """
        return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.ID.value]

    def get_display_name(self)->str:
        """Gets a user friendly display string

        Returns:
            str: friendly display string
        """
        return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.DISPLAYNAME.value]

    def get_name(self)->str:
        """Gets the user entity name

        Returns:
            str: user entity name or None if not set
        """
        if AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.NAME.value in self.parameters:
            return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.NAME.value]
        return None

    def get_icon(self)->str:
        """Gets the URL of the icon for the user entity

        Returns:
            str: URL of user icon or None if not set
        """
        if AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.ICON.value in self.parameters:
            return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY.ICON.value]
        return None


class AuthenticatorGetClientPINParameters:
    """
    GetClientPIN Parameters consisting of:

    pinProtocol (0x01)
        Unsigned Integer    Required
        PIN protocol version chosen by the client. For this version of
        the spec, this SHALL be the number 1.\n
    subCommand (0x02)
        Unsigned Integer 	Required
        The authenticator Client PIN sub command currently being requested\n
    keyAgreement (0x03)
        COSE_Key 	Optional
        Public key of platformKeyAgreementKey. The COSE_Key-encoded
        public key MUST contain the optional "alg" parameter and MUST NOT
        contain any other optional parameters. The "alg" parameter MUST
        contain a COSEAlgorithmIdentifier value.\n
    pinAuth (0x04)
        Byte Array 	Optional
        First 16 bytes of HMAC-SHA-256 of encrypted contents using
        sharedSecret. See Setting a new PIN, Changing existing PIN
        and Getting pinToken from the authenticator for more details.\n
    newPinEnc (0x05)
        Byte Array 	Optional
        Encrypted new PIN using sharedSecret. Encryption is done
        over UTF-8 representation of new PIN.\n
    pinHashEnc (0x06)
        Byte Array 	Optional
        Encrypted first 16 bytes of SHA-256 of PIN using sharedSecret.\n """

    def __init__(self, cbor_data:bytes):
        self.parameters = fido2.cbor.decode(cbor_data)
        auth.debug("Decoded GetClientPINParameters: %s", self.parameters)
        self.verify()

    def verify(self):
        """Verifies the parameters against the standard to
        ensure presence and type are correct.

        Raises:
            DICEAuthenticatorException: thrown if verification fails

        """
        if not AUTHN_GET_CLIENT_PIN.PIN_PROTOCOL.value in self.parameters:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"pinProtocol missing")

        if not AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value in self.parameters:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,"subCommand missing")

        if not isinstance(self.parameters[AUTHN_GET_CLIENT_PIN.PIN_PROTOCOL.value],int):
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                "pinProtocol not integer")

        if not isinstance(self.parameters[AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value], int):
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                "subCommand not integer")

        if AUTHN_GET_CLIENT_PIN.KEY_AGREEMENT.value in self.parameters:
            #Verify Key Agreement
            if not isinstance(self.parameters[AUTHN_GET_CLIENT_PIN.KEY_AGREEMENT.value],dict):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                    "pinAgreement not dictionary")
            if not 3 in self.parameters[AUTHN_GET_CLIENT_PIN.KEY_AGREEMENT.value]:
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,
                    "missing alg parameter")
            #TODO verify COSE key

        if AUTHN_GET_CLIENT_PIN.PIN_AUTH.value in self.parameters:
            if not isinstance(self.parameters[AUTHN_GET_CLIENT_PIN.PIN_AUTH.value], bytes):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                    "pinAuth not bytes")

        if AUTHN_GET_CLIENT_PIN.NEW_PIN_ENC.value in self.parameters:
            if not isinstance(self.parameters[AUTHN_GET_CLIENT_PIN.NEW_PIN_ENC.value],bytes):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                    "newPinEnc not bytes")

        if AUTHN_GET_CLIENT_PIN.PIN_HASH_ENC.value in self.parameters:
            if not isinstance(self.parameters[AUTHN_GET_CLIENT_PIN.PIN_HASH_ENC.value],bytes):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                    "pinHashEnc not bytes")

        sub_command = self.parameters[AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value]
        if not (sub_command >=1 and sub_command<=5):
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_COMMAND,"invalid subCommand")

        if sub_command == 1 or sub_command == 2:
            if not only_keys_in_dict([AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value,
                                    AUTHN_GET_CLIENT_PIN.PIN_PROTOCOL.value],self.parameters):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER,
                    "invalid parameters found")

        if sub_command == 3:
            if not only_keys_in_dict([AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value,
                                    AUTHN_GET_CLIENT_PIN.PIN_PROTOCOL.value,
                                    AUTHN_GET_CLIENT_PIN.NEW_PIN_ENC.value,
                                    AUTHN_GET_CLIENT_PIN.PIN_AUTH.value,
                                    AUTHN_GET_CLIENT_PIN.KEY_AGREEMENT.value],self.parameters):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER,
                    "invalid parameters found")

        if sub_command == 4:
            if not only_keys_in_dict([AUTHN_GET_CLIENT_PIN],self.parameters):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER,
                    "invalid parameters found")

        if sub_command == 5:
            if not only_keys_in_dict([AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value,
                                    AUTHN_GET_CLIENT_PIN.PIN_PROTOCOL.value,
                                    AUTHN_GET_CLIENT_PIN.KEY_AGREEMENT.value,
                                    AUTHN_GET_CLIENT_PIN.PIN_HASH_ENC.value],self.parameters):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER,
                    "invalid parameters found")

    def get_protocol(self)->int:
        """Get the protocol version

        Returns:
            int: protocol version
        """
        return self.parameters[AUTHN_GET_CLIENT_PIN.PIN_PROTOCOL.value]

    def get_sub_command(self)->int:
        """Get the subcommand value

        Returns:
            int: subcommand
        """
        return self.parameters[AUTHN_GET_CLIENT_PIN.SUB_COMMAND.value]

    def get_key_agreement(self)->dict:
        """Get the key agreement

        Returns:
            dict: key agreement spec
        """
        return self.parameters[AUTHN_GET_CLIENT_PIN.KEY_AGREEMENT.value]

    def get_pin_auth(self)->bytes:
        """Get the PIN auth hash

        Returns:
            bytes: hash of PIN auth
        """
        return self.parameters[AUTHN_GET_CLIENT_PIN.PIN_AUTH.value]

    def get_new_pin_enc(self)->bytes:
        """Get the encrypted New PIN

        Returns:
            bytes: New PIN encryption
        """
        return self.parameters[AUTHN_GET_CLIENT_PIN.NEW_PIN_ENC.value]

    def get_pin_hash_enc(self)->bytes:
        """Get the encrypted PIN Hash

        Returns:
            bytes: Encrypted PIN hash
        """
        return self.parameters[AUTHN_GET_CLIENT_PIN.PIN_HASH_ENC.value]

class PublicKeyCredentialDescriptor:
    """PublicKey Credential Description, consisting of id, type and possibly
    transport type
    """
    def __init__(self, desc:dict):
        self.parameters = desc
        self.verify()

    def get_id(self)->bytes:
        """Gets the id

        Returns:
            bytes: credential id
        """
        return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.ID.value]

    def get_type(self)->str:
        """Credential type

        Returns:
            str: credential type
        """
        return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.TYPE.value]

    def get_transports(self):
        """Transports supported by the credential
        TODO Check format
        Returns:
            [type]: supported transports
        """

        return self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.TRANSPORTS.value]

    def verify(self):
        """Verifies the parameters against the standard to
        ensure presence and type are correct.

        Raises:
            DICEAuthenticatorException: thrown if verification fails

        """
        if not AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.TYPE.value in self.parameters:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,
                "PublicKeyCredentialDesc missing type")
        if not AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.ID.value in self.parameters:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,
                "PublicKeyCredentialDesc missing id")
        if not self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.TYPE.value] == \
            AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.TYPE_PUBLIC_KEY.value:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,
                "PublicKeyCredentialDesc type not recognised")
        if not isinstance(self.parameters[AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR.ID.value],bytes):
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,
                "PublicKeyCredentialDesc id not bytes")

class AuthenticatorGetAssertionParameters:
    """
    Get Assertion parameters consisting of the following:
    rpId
        String 	Required
        Relying party identifier. See [WebAuthN].
    clientDataHash
        Byte Array 	Required
        Hash of the serialized client data collected by the host. See [WebAuthN].
    allowList
        Sequence of PublicKeyCredentialDescriptors Optional
        A sequence of PublicKeyCredentialDescriptor structures, each
        denoting a credential, as specified in [WebAuthN]. If this
        parameter is present and has 1 or more entries, the
        authenticator MUST only generate an assertion using one of
        the denoted credentials.
    extensions
        CBOR map of extension identifier authenticator extension input values 	Optional
        Parameters to influence authenticator operation. These parameters might be
        authenticator specific.
    options
        Map of authenticator options Optional
        Parameters to influence authenticator operation, as specified in
        the table below.
    pinAuth
        Byte Array 	Optional
        First 16 bytes of HMAC-SHA-256 of clientDataHash using pinToken
        which platform got from the authenticator:
        HMAC-SHA-256(pinToken, clientDataHash).
    pinProtocol
        Unsigned Integer 	Optional
        PIN protocol version selected by client.
    """
    def __init__(self, cbor_data:bytes):
        self.parameters = fido2.cbor.decode(cbor_data)
        self.allow_list = []
        if AUTHN_GET_ASSERTION.ALLOW_LIST.value in self.parameters:

            for allowed in self.parameters[AUTHN_GET_ASSERTION.ALLOW_LIST.value]:
                self.allow_list.append(PublicKeyCredentialDescriptor(allowed))
        self.verify()
        auth.debug("Decoded GetAssertionParameters: %s", self.parameters)


    def verify(self):
        """Verifies the parameters against the standard to
        ensure presence and type are correct.

        Raises:
            DICEAuthenticatorException: thrown if verification fails

        """
        if not AUTHN_GET_ASSERTION.RP_ID.value in self.parameters:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,
                "rpId missing")

        if not AUTHN_GET_ASSERTION.HASH.value in self.parameters:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,
                "clientDataHash missing")

        if not isinstance(self.parameters[AUTHN_GET_ASSERTION.RP_ID.value],str):
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                "rpId not string")

        if not isinstance(self.parameters[AUTHN_GET_ASSERTION.HASH.value],bytes):
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                "clientDataHash not bytes")

        if AUTHN_GET_ASSERTION.ALLOW_LIST.value in self.parameters:
            if not isinstance(self.parameters[AUTHN_GET_ASSERTION.ALLOW_LIST.value],list):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                    "allowList not sequence")
        if AUTHN_GET_ASSERTION.PIN_AUTH.value in self.parameters:
            if not isinstance(self.parameters[AUTHN_GET_ASSERTION.PIN_AUTH.value], bytes):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                    "pinAuth not bytes")
        if AUTHN_GET_ASSERTION.PIN_PROTOCOL.value in self.parameters:
            if not isinstance(self.parameters[AUTHN_GET_ASSERTION.PIN_PROTOCOL.value],int):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                    "pinProtocol not int")
        #TODO verify options and extensions


    def get_hash(self)->bytes:
        """Gets client hash

        Returns:
            bytes: client hash as bytes
        """
        return self.parameters[AUTHN_GET_ASSERTION.HASH.value]

    def get_rp_id(self)->str:
        """Get the relying party ID, usually URL

        Returns:
            str: relying party id
        """
        return self.parameters[AUTHN_GET_ASSERTION.RP_ID.value]

    def get_require_resident_key(self)->bool:
        """Get whether a resident key is required

        Returns:
            bool: True if key must be resident key, False if not
        """
        return self.parameters[AUTHN_GET_ASSERTION.OPTIONS.value][AUTHN_MAKE_CREDENTIAL.OPTIONS_RK.value]
    def get_user_presence(self)->bool:
        """Get whether user presence check is required, this is
        assumed to always be True in CTAP

        Returns:
            bool: True
        """
        # Not present in the current version of CTAP.
        # Authenticators are assumed to always check user presence.
        return True
    def require_user_verification(self)->bool:
        """Get whether user verification is required

        Returns:
            bool: True if required, False if not
        """
        if AUTHN_GET_ASSERTION.OPTIONS.value in self.parameters:
            if AUTHN_GET_ASSERTION.OPTIONS.value in \
                self.parameters[AUTHN_GET_ASSERTION.OPTIONS.value]:
                return self.parameters[AUTHN_GET_ASSERTION.OPTIONS.value][AUTHN_GET_ASSERTION.OPTIONS_UV.value]
            return False
        return False
    def get_allow_list(self)->[PublicKeyCredentialDescriptor]:
        """Get a list of allowed PublicKey Credential Descriptors

        Returns:
            [PublicKeyCredentialDescriptor]: list of allowed descriptors
        """
        return self.allow_list

    def get_extensions(self):
        """Get extensions

        TODO check return type
        Returns:
            [type]: [description]
        """
        return self.parameters[AUTHN_GET_ASSERTION.EXTENSIONS.value]

    def get_pin_auth(self)->bytes:
        """Get pin auth as bytes or None if not set

        Returns:
            bytes: PIN auth bytes or None
        """
        if not AUTHN_GET_ASSERTION.PIN_AUTH.value in self.parameters:
            return None
        return self.parameters[AUTHN_GET_ASSERTION.PIN_AUTH.value]

    def get_pin_protocol(self)->int:
        """Get required PIN protocol

        Returns:
            int: pin protocol
        """
        if not AUTHN_GET_ASSERTION.PIN_PROTOCOL.value in self.parameters:
            return -1
        return self.parameters[AUTHN_GET_ASSERTION.PIN_PROTOCOL.value]
class AuthenticatorMakeCredentialParameters:
    """
    Make Credential parameters consisting of:

    clientDataHash
        Byte Array 	Required
        Hash of the ClientData contextual binding specified by host. See [WebAuthN].
    rp
        PublicKeyCredentialRpEntity 	Required
        This PublicKeyCredentialRpEntity data structure describes
        a Relying Party with which the new public key credential
        will be associated. It contains the Relying party identifier,
        (optionally) a human-friendly RP name, and (optionally) a URL
        referencing a RP icon image. The RP name is to be used by the
        authenticator when displaying the credential to the user for
        selection and usage authorization.
    user
        PublicKeyCredentialUserEntity 	Required
        This PublicKeyCredentialUserEntity data structure describes the
        user account to which the new public key credential will be
        associated at the RP. It contains an RP-specific user account
        identifier, (optionally) a user name, (optionally) a user display
        name, and (optionally) a URL referencing a user icon image (of a
        user avatar, for example). The authenticator associates the
        created public key credential with the account identifier, and
        MAY also associate any or all of the user name, user display
        name, and image data (pointed to by the URL, if any).
    pubKeyCredParams 	CBOR Array 	Required
        A sequence of CBOR maps consisting of pairs of PublicKeyCredentialType
        (a string) and cryptographic algorithm (a positive or negative integer),
        where algorithm identifiers are values that SHOULD be registered in
        the IANA COSE Algorithms registry [IANA-COSE-ALGS-REG]. This
        sequence is ordered from most preferred (by the RP) to least
        preferred.
    excludeList
        Sequence of PublicKeyCredentialDescriptors Optional
        A sequence of PublicKeyCredentialDescriptor structures, as
        specified in [WebAuthN]. The authenticator returns an error
        if the authenticator already contains one of the credentials
        enumerated in this sequence. This allows RPs to limit the
        creation of multiple credentials for the same account on a
        single authenticator.
    extensions
        CBOR map of extension identifier → authenticator
        extension input values 	Optional
        Parameters to influence authenticator operation, as specified
        in [WebAuthN]. These parameters might be authenticator specific.
    options
        Map of authenticator options 	Optional
        Parameters to influence authenticator operation, as specified
        in in the table below.
    pinAuth
        Byte Array 	Optional
        First 16 bytes of HMAC-SHA-256 of clientDataHash using pinToken
        which platform got from the authenticator:
        HMAC-SHA-256(pinToken, clientDataHash).
    pinProtocol
        Unsigned Integer 	Optional
        PIN protocol version chosen by the client
    """
    def __init__(self, cbor_data:bytes):
        self.parameters = fido2.cbor.decode(cbor_data)
        auth.debug("Decoded MakeCredentialParameters: %s", self.parameters)
        self.verify()
        self.user_entity = PublicKeyCredentialUserEntity(
            self.parameters[AUTHN_MAKE_CREDENTIAL.USER.value])
        self.rp_entity = PublicKeyCredentialRpEntity(
            self.parameters[AUTHN_MAKE_CREDENTIAL.RP.value])
        self.exclude_list = []
        if AUTHN_MAKE_CREDENTIAL.EXCLUDE_LIST.value in self.parameters:
            for exclude in self.parameters[AUTHN_MAKE_CREDENTIAL.EXCLUDE_LIST.value]:
                self.exclude_list.append(PublicKeyCredentialDescriptor(exclude))

    def verify(self):
        """Verifies the parameters against the standard to
        ensure presence and type are correct.

        Raises:
            DICEAuthenticatorException: thrown if verification fails

        """
        if not AUTHN_MAKE_CREDENTIAL.RP.value in self.parameters:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,
                "rpId missing")

        if not AUTHN_MAKE_CREDENTIAL.HASH.value in self.parameters:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,
                "clientDataHash missing")

        if not AUTHN_MAKE_CREDENTIAL.USER.value in self.parameters:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,
                "user missing")

        if not AUTHN_MAKE_CREDENTIAL.PUBKEY_CRED_PARAMS.value in self.parameters:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_MISSING_PARAMETER,
                "publicKeyCredentials missing")

        if not isinstance(self.parameters[AUTHN_MAKE_CREDENTIAL.PUBKEY_CRED_PARAMS.value],list):
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                "publicKeyCredentials not list")

        for cred in self.parameters[AUTHN_MAKE_CREDENTIAL.PUBKEY_CRED_PARAMS.value]:
            if not isinstance(cred,dict):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                    "publicKeyCredential not dictionary")
            if not "type" in cred:
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,
                    "publicKeyCredential type missing")
            if not "alg" in cred:
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_INVALID_CBOR,
                    "publicKeyCredential alg missing")


        if not isinstance(self.parameters[AUTHN_MAKE_CREDENTIAL.RP.value],dict):
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                "rp not dictionary")
        if not isinstance(self.parameters[AUTHN_MAKE_CREDENTIAL.USER.value],dict):
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                "user not dictionary")

        if not isinstance(self.parameters[AUTHN_MAKE_CREDENTIAL.HASH.value],bytes):
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                "clientDataHash not bytes")

        if AUTHN_MAKE_CREDENTIAL.PIN_AUTH.value in self.parameters:
            if not isinstance(self.parameters[AUTHN_MAKE_CREDENTIAL.PIN_AUTH.value],bytes):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                    "pinAuth not bytes")
        if AUTHN_MAKE_CREDENTIAL.PIN_PROTOCOL.value in self.parameters:
            if not isinstance(self.parameters[AUTHN_MAKE_CREDENTIAL.PIN_PROTOCOL.value], int):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                    "pinProtocol not int")

        if AUTHN_MAKE_CREDENTIAL.OPTIONS.value in self.parameters:

            if AUTHN_MAKE_CREDENTIAL.OPTIONS_RK.value in self.parameters[AUTHN_MAKE_CREDENTIAL.OPTIONS.value] and not isinstance(self.parameters[AUTHN_MAKE_CREDENTIAL.OPTIONS.value][AUTHN_MAKE_CREDENTIAL.OPTIONS_RK.value], bool):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                    "option rk not boolean")
            if AUTHN_MAKE_CREDENTIAL.OPTIONS_UV.value in self.parameters[AUTHN_MAKE_CREDENTIAL.OPTIONS.value] and not isinstance(self.parameters[AUTHN_MAKE_CREDENTIAL.OPTIONS.value][AUTHN_MAKE_CREDENTIAL.OPTIONS_UV.value], bool):
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
                    "option uv not boolean")

    def get_hash(self)->bytes:
        """Get the client hash

        Returns:
            bytes: client hash as bytes
        """
        return self.parameters[AUTHN_MAKE_CREDENTIAL.HASH.value]
    def get_rp_entity(self)->PublicKeyCredentialRpEntity:
        """Get the relying party

        Returns:
            PublicKeyCredentialRpEntity: relying party entity
        """
        return self.rp_entity

    def get_user_entity(self)->PublicKeyCredentialUserEntity:
        """Get the user entity

        Returns:
            PublicKeyCredentialUserEntity: user entity
        """
        return self.user_entity
    def get_require_resident_key(self)->bool:
        """Get whether a resident key is required

        Returns:
            bool: True if required, False if not
        """
        if AUTHN_MAKE_CREDENTIAL.OPTIONS.value in self.parameters:
            if AUTHN_MAKE_CREDENTIAL.OPTIONS_RK.value in \
                self.parameters[AUTHN_MAKE_CREDENTIAL.OPTIONS.value]:
                return self.parameters[AUTHN_MAKE_CREDENTIAL.OPTIONS.value][AUTHN_MAKE_CREDENTIAL.OPTIONS_RK.value]
            return False
        return False
    def get_user_presence(self)->bool:
        """Get whether a user presence check is required, this is assumed
        to always be True in CTAP

        Returns:
            bool: True
        """
        return True
        #Not present in the current version of CTAP. Authenticators
        # are assumed to always check user presence.
    def require_user_verification(self)->bool:
        """Get whether user verification is required

        Returns:
            bool: True if required, False if not
        """
        if AUTHN_MAKE_CREDENTIAL.OPTIONS.value in self.parameters:
            if AUTHN_MAKE_CREDENTIAL.OPTIONS_UV.value in \
                self.parameters[AUTHN_MAKE_CREDENTIAL.OPTIONS.value]:
                return self.parameters[AUTHN_MAKE_CREDENTIAL.OPTIONS.value][AUTHN_MAKE_CREDENTIAL.OPTIONS_UV.value]
            return False
        return False
    def get_cred_types_and_pubkey_algs(self)->list:
        """Get the list of acceptable type and public key algorithms accepted
        in preference order

        Returns:
            list: list of dictionary object containing type and algorithm
        """
        return self.parameters[AUTHN_MAKE_CREDENTIAL.PUBKEY_CRED_PARAMS.value]
    def get_exclude_credential_descriptor_list(self)->[PublicKeyCredentialDescriptor]:
        """List of credential descriptors that should be excluded

        Returns:
            [PublicKeyCredentialDescriptor]: exclusion list
        """
        return self.exclude_list


    def get_extensions(self):
        """Get extensions
        TODO check type
        Returns:
            [type]: [description]
        """
        return self.parameters[AUTHN_MAKE_CREDENTIAL.EXTENSIONS.value]

    def get_pin_auth(self)->bytes:
        """Get PIN auth bytes

        Returns:
            bytes: PIN auth
        """
        if not AUTHN_MAKE_CREDENTIAL.PIN_AUTH.value in self.parameters:
            return None
        return self.parameters[AUTHN_MAKE_CREDENTIAL.PIN_AUTH.value]

    def get_pin_protocol(self)->int:
        """Get the supported PIN protocol

        Returns:
            int: PIN protocol
        """
        if not AUTHN_MAKE_CREDENTIAL.PIN_PROTOCOL.value in self.parameters:
            return -1
        return self.parameters[AUTHN_MAKE_CREDENTIAL.PIN_PROTOCOL.value]

class DICEAuthenticatorException(Exception):
    """Exception raised when accessing the storage medium

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, err_code:ctap.constants.CTAP_STATUS_CODE,message="Authenticator Exception"):
        self.message = message
        self.err_code = err_code
        super().__init__(self.message)

    def get_error_code(self)->ctap.constants.CTAP_STATUS_CODE:
        """Get the error code that has been set in this exception

        Returns:
            ctap.constants.CTAP_STATUS_CODE: error code
        """
        return self.err_code
