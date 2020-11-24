from enum import Enum, unique
BROADCAST_ID = b'\xff\xff\xff\xff'
MESSAGE_SIZE = 64
HEADER_SIZE = 7 
MAX_PAYLOAD = MESSAGE_SIZE - HEADER_SIZE
MAX_CONTINUATION_PAYLOAD = MESSAGE_SIZE - 5

@unique
class CTAPHID_ERROR(Enum):
    ERR_INVALID_CMD = b'\x01' #The command in the request is invalid
    ERR_INVALID_PAR = b'\x02' #The parameter(s) in the request is invalid
    ERR_INVALID_LEN = b'\x03' #The length field (BCNT) is invalid for the request
    ERR_INVALID_SEQ = b'\x04' #The sequence does not match expected value
    ERR_MSG_TIMEOUT = b'\x05' #The message has timed out
    ERR_CHANNEL_BUSY = b'\x06' #The device is busy for the requesting channel
    ERR_LOCK_REQUIRED = b'\x0A' #Command requires channel lock
    ERR_INVALID_CHANNEL = b'\x0B' #Reserved (Removed)
    ERR_OTHER = b'\x7F' #Unspecified error 


class CTAPHID_KEEPALIVE_STATUS(Enum):
    STATUS_PROCESSING = b'\x01' #The authenticator is still processing the current request.
    STATUS_UPNEEDED = b'\x02' #The authenticator is waiting for user presence. 
    
@unique
class CMD_TYPE(Enum):
    INITIALIZATION = 1
    CONTINUATION = 0

@unique
class CTAP_CMD(Enum):
    CTAPHID_MSG = b'\x03'
    CTAPHID_CBOR = b'\x10'
    CTAPHID_INIT = b'\x06'
    CTAPHID_PING = b'\x01'
    CTAPHID_CANCEL = b'\x11'
    CTAPHID_ERROR = b'\x3F'
    CTAPHID_KEEPALIVE = b'\x3B'

#Optional Commands (Currently not implemented)
    CTAPHID_WINK = b'\x08'
    CTAPHID_LOCK = b'\x04'

@unique
class CTAP_STATUS_CODE(Enum):
    CTAP2_OK = b'\x00'
    CTAP2_ERR_CBOR_UNEXPECTED_TYPE = b'\x11'#Invalid/unexpected CBOR error.
    CTAP2_ERR_INVALID_CBOR = b'\x12'# 	Error when parsing CBOR.
    CTAP2_ERR_MISSING_PARAMETER  = b'\x14'#	Missing non-optional parameter.
    CTAP2_ERR_LIMIT_EXCEEDED = b'\x15'# 	Limit for number of items exceeded.
    CTAP2_ERR_UNSUPPORTED_EXTENSION  = b'\x16'#	Unsupported extension.
    CTAP2_ERR_CREDENTIAL_EXCLUDED  = b'\x19'#	Valid credential found in the exclude list.
    CTAP2_ERR_PROCESSING  = b'\x21'#	Processing (Lengthy operation is in progress).
    CTAP2_ERR_INVALID_CREDENTIAL  = b'\x22'#	Credential not valid for the authenticator.
    CTAP2_ERR_USER_ACTION_PENDING  = b'\x23'#	Authentication is waiting for user interaction.
    CTAP2_ERR_OPERATION_PENDING = b'\x24'# 	Processing, lengthy operation is in progress.
    CTAP2_ERR_NO_OPERATIONS  = b'\x25'#	No request is pending.
    CTAP2_ERR_UNSUPPORTED_ALGORITHM  = b'\x26'#	Authenticator does not support requested algorithm.
    CTAP2_ERR_OPERATION_DENIED  = b'\x27'#	Not authorized for requested operation.
    CTAP2_ERR_KEY_STORE_FULL = b'\x28'# 	Internal key storage is full.
    CTAP2_ERR_NO_OPERATION_PENDING = b'\x2A'# 	No outstanding operations.
    CTAP2_ERR_UNSUPPORTED_OPTION  = b'\x2B'#	Unsupported option.
    CTAP2_ERR_INVALID_OPTION  = b'\x2C'#	Not a valid option for current operation.
    CTAP2_ERR_KEEPALIVE_CANCEL = b'\x2D'# 	Pending keep alive was cancelled.
    CTAP2_ERR_NO_CREDENTIALS = b'\x2E'# 	No valid credentials provided.
    CTAP2_ERR_USER_ACTION_TIMEOUT  = b'\x2F'#	Timeout waiting for user interaction.
    CTAP2_ERR_NOT_ALLOWED  = b'\x30'#	Continuation command, such as, authenticatorGetNextAssertion not allowed.
    CTAP2_ERR_PIN_INVALID = b'\x31'# 	PIN Invalid.
    CTAP2_ERR_PIN_BLOCKED = b'\x32'# 	PIN Blocked.
    CTAP2_ERR_PIN_AUTH_INVALID  = b'\x33'#	PIN authentication,pinUvAuthParam, verification failed.
    CTAP2_ERR_PIN_AUTH_BLOCKED = b'\x34'# 	PIN authentication,pinUvAuthParam, blocked. Requires power recycle to reset.
    CTAP2_ERR_PIN_NOT_SET  = b'\x35'#	No PIN has been set.
    CTAP2_ERR_PIN_REQUIRED  = b'\x36'#	PIN is required for the selected operation.
    CTAP2_ERR_PIN_POLICY_VIOLATION  = b'\x37'#	PIN policy violation. Currently only enforces minimum length.
    CTAP2_ERR_PIN_TOKEN_EXPIRED  = b'\x38'#	pinUvAuthToken expired on authenticator.
    CTAP2_ERR_REQUEST_TOO_LARGE  = b'\x39'#	Authenticator cannot handle this request due to memory constraints.
    CTAP2_ERR_ACTION_TIMEOUT = b'\x3A'# 	The current operation has timed out.
    CTAP2_ERR_UP_REQUIRED = b'\x3B'# 	User presence is required for the requested operation.
    CTAP2_ERR_UV_BLOCKED  = b'\x3C'#	Built in UV is blocked.
    CTAP1_ERR_OTHER  = b'\x7F'#	Other unspecified error.
    CTAP2_ERR_SPEC_LAST  = b'\xDF'#	CTAP 2 spec last error.
    CTAP2_ERR_EXTENSION_FIRST  = b'\xE0'#	Extension specific error.
    CTAP2_ERR_EXTENSION_LAST  = b'\xEF'#	Extension specific error.
    CTAP2_ERR_VENDOR_FIRST = b'\xF0'# 	Vendor specific error.
    CTAP2_ERR_VENDOR_LAST  = b'\xFF'#	Vendor specific error. 




@unique
class AUTHN_GETINFO_PARAMETER(Enum):
    pass



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
class AUTHN_GETINFO_VERSION(AUTHN_GETINFO_PARAMETER):
    CTAP2 = "FIDO_2_0"
    CTAP1 = "U2F_V2"


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

