from enum import Enum, unique
BROADCAST_ID = b'\xff\xff\xff\xff'
MESSAGE_SIZE = 64
HEADER_SIZE = 7 
MAX_PAYLOAD = MESSAGE_SIZE - HEADER_SIZE

@unique
class CTAPHID_ERROR(Enum):
    ERR_INVALID_CMD = b'\x01' #The command in the request is invalid
    ERR_INVALID_PAR = b'\x02' #The parameter(s) in the request is invalid
    ERR_INVALID_LEN = b'\x03' #The length field (BCNT) is invalid for the request
    ERR_INVALID_SEQ = b'\x04' #The sequence does not match expected value
    ERR_MSG_TIMEOUT = b'\x05' #The message has timed out
    ERR_CHANNEL_BUSY = b'\x06' #The device is busy for the requesting channel
    ERR_LOCK_REQUIRED = b'\x0A' #Command requires channel lock
    NA = b'\x0B' #Reserved (Removed)
    ERR_OTHER = b'\x7F' #Unspecified error 

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