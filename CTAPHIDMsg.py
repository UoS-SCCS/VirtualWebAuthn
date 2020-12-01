from HIDPacket import HIDInitializationPacket
from HIDPacket import HIDContinuationPacket
from AuthenticatorVersion import AuthenticatorVersion
from HIDPacket import HIDPacket
import json
from abc import ABC, abstractmethod
import CTAPHIDConstants
import logging
log = logging.getLogger('debug')
ctap = logging.getLogger('debug.ctap')
usbhid = logging.getLogger('debug.usbhid')
class CTAPHIDCMD(ABC):
    
    def __init__(self, CID:bytes, CMD:CTAPHIDConstants.CTAP_CMD, BCNT, payload:bytes):
        self._CID = CID
        self._CMD = CMD
        self._BCNT = BCNT
        if self._BCNT  > CTAPHIDConstants.MAX_PAYLOAD:
            self._payload = payload
        else:
            self._payload = payload[:self._BCNT]
        ctap.debug("Created CTAPHID CMD: %s", self)
        self.remaining_bytes = self._BCNT - len(self._payload)

    def __str__(self):
        out = {}
        out["CID"]=self._CID.hex()
        out["CMD"]=self._CMD.name
        out["BCNT"]=self._BCNT
        out["payload"] = self._payload.hex()
        return json.dumps(out)
    
    def is_complete(self):
        if self.remaining_bytes==0:
            return True
        else:
            return False
    
    def set_channel_id(self, CID:bytes):
        self._CID = CID
    def get_length(self):
        return self._BCNT
    
    def get_CMD(self):
        return self._CMD
    
    def get_CID(self):
        return self._CID
    def get_payload(self):
        return self._payload

    def get_HID_packets(self):
        if self._BCNT>CTAPHIDConstants.MAX_PAYLOAD:
            usbhid.debug("Payload greater than single packet size, creating packets")
            packets = []
            packet = HIDInitializationPacket(self._CID,self._CMD,self._BCNT,self._payload[:CTAPHIDConstants.MAX_PAYLOAD])
            packets.append(packet)
            payload_index = CTAPHIDConstants.MAX_PAYLOAD
            for seq in range(128):
                end = min(self._BCNT-payload_index,CTAPHIDConstants.MAX_CONTINUATION_PAYLOAD)
                packets.append(HIDContinuationPacket(self._CID,seq,self._payload[payload_index:payload_index+end]))
                payload_index = payload_index+end
                if payload_index == self._BCNT:
                    break 
            usbhid.debug("Created %s HID Packets", len(packets))
            return packets
        else:
            usbhid.debug("Payload fits in a single HID Packet")
            packet = HIDInitializationPacket(self._CID,self._CMD,self._BCNT,self._payload)
            return [packet]

    def verify(self):
        pass

    def append_continuation_packet(self,packet:HIDPacket):
        usbhid.debug("Appending continuation packet: %s", packet)
        if packet.CMDTYPE != CTAPHIDConstants.CMD_TYPE.CONTINUATION:
            raise Exception("Cannot append a non-continuation packet to a message")
        if self.remaining_bytes > CTAPHIDConstants.MAX_CONTINUATION_PAYLOAD:
            self._payload += packet.get_payload()
            self.remaining_bytes = self.remaining_bytes - CTAPHIDConstants.MAX_CONTINUATION_PAYLOAD
        else:
            self._payload += packet.get_payload()[:self.remaining_bytes]
            self.remaining_bytes = 0 
    
    @staticmethod
    def create_message(packet: HIDPacket):
        """
        docstring
        """
        if packet.get_CMD() == CTAPHIDConstants.CTAP_CMD.CTAPHID_INIT:
            return CTAPHIDInitRequest(packet)
        elif packet.get_CMD() == CTAPHIDConstants.CTAP_CMD.CTAPHID_MSG:
            return CTAPHIDMsgRequest(packet)
        elif packet.get_CMD() == CTAPHIDConstants.CTAP_CMD.CTAPHID_CBOR:
            return CTAPHIDCBORRequest(packet)
        elif packet.get_CMD() == CTAPHIDConstants.CTAP_CMD.CTAPHID_WINK:
            return CTAPHIDWinkRequest(packet)
        elif packet.get_CMD() == CTAPHIDConstants.CTAP_CMD.CTAPHID_CANCEL:
            return CTAPHIDCancelRequest(packet)
        elif packet.get_CMD() == CTAPHIDConstants.CTAP_CMD.CTAPHID_PING:
            return CTAPHIDPingRequest(packet)


"""
Request
CMD 	CTAPHID_MSG
BCNT 	1..(n + 1)
DATA 	U2F command byte
DATA + 1 	n bytes of data
"""
class CTAPHIDMsgRequest(CTAPHIDCMD):
    def __init__(self, packet: HIDInitializationPacket):
        super().__init__(packet.get_CID(), packet.get_CMD(),packet.get_length(),packet.get_payload())
        self._U2F_CMD = self._payload[0]
        self.verify()

    def get_cmd_data(self):
        return self._payload[1:]    


"""
Response at success
CMD 	CTAPHID_MSG
BCNT 	1..(n + 1)
DATA 	U2F status code
DATA + 1 	n bytes of data
"""
class CTAPHIDMsgResponse(CTAPHIDCMD):

    def __init__(self,CID, U2F_Status,payload_data:bytes):     
        payload = bytearray(len(payload_data)+1)
        payload[0] = U2F_Status
        payload[1:]=payload_data
        ctap.debug("Create initial MSG response %s",payload.hex())
        super().__init__(CID,CTAPHIDConstants.CTAP_CMD.CTAPHID_MSG,len(payload),payload)


"""
Request
CMD 	CTAPHID_CANCEL
BCNT 	0 
"""
class CTAPHIDCancelRequest(CTAPHIDCMD):
    def __init__(self, packet: HIDInitializationPacket):
        super().__init__(packet.get_CID(), packet.get_CMD(),packet.get_length(),packet.get_payload())
        self.verify()



"""
Response at success
CMD 	CTAPHID_CANCEL
BCNT 	0 
"""
class CTAPHIDCancelResponse(CTAPHIDCMD):

    def __init__(self,CID):     
        ctap.debug("Create initial Cancel response")
        super().__init__(CID,CTAPHIDConstants.CTAP_CMD.CTAPHID_CANCEL,0,bytes(0))

"""
Response at success
CMD 	CTAPHID_KEEPALIVE
BCNT 	1
DATA 	Status code

The following status codes are defined
STATUS_PROCESSING 	1 	The authenticator is still processing the current request.
STATUS_UPNEEDED 	2 	The authenticator is waiting for user presence. 
"""
class CTAPHIDKeepAliveResponse(CTAPHIDCMD):

    def __init__(self,CID,status_code:CTAPHIDConstants.CTAPHID_KEEPALIVE_STATUS):     
        ctap.debug("Create Keep-alive response")
        super().__init__(CID,CTAPHIDConstants.CTAP_CMD.CTAPHID_KEEPALIVE,1,status_code.value)

"""
Response at success
CMD 	CTAPHID_ERROR
BCNT 	1
DATA 	Error code 
"""
class CTAPHIDErrorResponse(CTAPHIDCMD):

    def __init__(self,CID,error_code:CTAPHIDConstants.CTAPHID_ERROR):     
        ctap.debug("Create initial Error response")
        super().__init__(CID,CTAPHIDConstants.CTAP_CMD.CTAPHID_ERROR,1,error_code.value)

"""
Request
CMD 	CTAPHID_WINK
BCNT 	0
DATA 	N/A 
"""
class CTAPHIDWinkRequest(CTAPHIDCMD):
    def __init__(self, packet: HIDInitializationPacket):
        super().__init__(packet.get_CID(), packet.get_CMD(),packet.get_length(),packet.get_payload())
        self.verify()



"""
Response at success
CMD 	CTAPHID_WINK
BCNT 	0
DATA 	N/A 
"""
class CTAPHIDWinkResponse(CTAPHIDCMD):

    def __init__(self,CID,payload_data:bytes):     
        ctap.debug("Create initial WINK response %s",payload_data)
        super().__init__(CID,CTAPHIDConstants.CTAP_CMD.CTAPHID_WINK,len(payload_data),payload_data)




"""
Request
CMD 	CTAPHID_PING
BCNT 	0..n
DATA 	n bytes 
"""
class CTAPHIDPingRequest(CTAPHIDCMD):
    def __init__(self, packet: HIDInitializationPacket):
        super().__init__(packet.get_CID(), packet.get_CMD(),packet.get_length(),packet.get_payload())
        self.verify()



"""
Response at success
CMD 	CTAPHID_PING
BCNT 	n
DATA 	N bytes 
"""
class CTAPHIDPingResponse(CTAPHIDCMD):

    def __init__(self,CID,payload_data:bytes):     
        ctap.debug("Create initial PING response %s",payload_data)
        super().__init__(CID,CTAPHIDConstants.CTAP_CMD.CTAPHID_PING,len(payload_data),payload_data)



"""
Request
CMD 	CTAPHID_CBOR
BCNT 	1..(n + 1)
DATA 	CTAP command byte
DATA + 1 	n bytes of CBOR encoded data 
"""
class CTAPHIDCBORRequest(CTAPHIDCMD):
    def __init__(self, packet: HIDInitializationPacket):
        super().__init__(packet.get_CID(), packet.get_CMD(),packet.get_length(),packet.get_payload())
        self._CTAP_CMD = self._payload[0]
        self.verify()

    def get_cmd_data(self):
        return self._payload[1:]    


"""
Response at success
CMD 	CTAPHID_MSG
BCNT 	1..(n + 1)
DATA 	CTAP status code
DATA + 1 	n bytes of CBOR encoded data 
"""
class CTAPHIDCBORResponse(CTAPHIDCMD):

    def __init__(self,CID, CTAP_Status:CTAPHIDConstants.CTAP_STATUS_CODE,payload_data:bytes):     
        payload = bytearray(len(payload_data)+1)
        payload[0] = CTAP_Status.value[0]
        payload[1:]=payload_data
        ctap.debug("Create initial CBOR response %s",payload)
        super().__init__(CID,CTAPHIDConstants.CTAP_CMD.CTAPHID_CBOR,len(payload),payload)


class CTAPHIDInitRequest(CTAPHIDCMD):
    def __init__(self, packet: HIDInitializationPacket):
        super().__init__(packet.get_CID(), packet.get_CMD(),packet.get_length(),packet.get_payload())
        self.verify()
    
    def verify(self):
        if(self.get_length()!= 8):
            raise Exception("Invalid init message length")

"""
    CMD 	CTAPHID_INIT
    BCNT 	17 (see note below)
    DATA 	8-byte nonce
    DATA+8 	4-byte channel ID
    DATA+12 	CTAPHID protocol version identifier
    DATA+13 	Major device version number
    DATA+14 	Minor device version number
    DATA+15 	Build device version number
    DATA+16 	Capabilities flags 
    """
class CTAPHIDInitResponse(CTAPHIDCMD):

    CAPABILITY_WINK =b'\x01' #If set to 1, authenticator implements CTAPHID_WINK function
    CAPABILITY_CBOR =b'\x04' #If set to 1, authenticator implements CTAPHID_CBOR function
    CAPABILITY_NMSG =b'\x08' #If set to 1, authenticator DOES NOT implement CTAPHID_MSG function 

    def __init__(self, version:AuthenticatorVersion):     
        payload = bytearray(17) #17 bytes of data
        payload[12] = version.ctaphid_protocol_version
        payload[13] = version.major_version
        payload[14] = version.minor_version
        payload[15] = version.build_version
        payload[16] = CTAPHIDInitResponse.CAPABILITY_CBOR[0] | CTAPHIDInitResponse.CAPABILITY_WINK[0]
        ctap.debug("Creating initial response: %s",payload.hex())
        super().__init__(CTAPHIDConstants.BROADCAST_ID,CTAPHIDConstants.CTAP_CMD.CTAPHID_INIT,17,payload)   

    def set_nonce(self, nonce:bytes):
        self._payload[0:8]=nonce

    def set_channel_id(self, channel_id:bytes):        
        self._payload[8:12] = channel_id

    
    def set_protocol_version(self, version:int):
        self._payload[12] = version.to_bytes(1,"big")
    
    """
    Flag is the XOR of the CAPABILITY_ flags defined in the class
    """
    def set_capability_flag(self, flag):
        self._payload[18] = flag

    
