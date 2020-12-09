from abc import ABC, abstractmethod
import logging
import json

from hid.packets import HIDInitializationPacket,HIDContinuationPacket,HIDPacket
from authenticator.datatypes import AuthenticatorVersion
from ctap.exceptions import CTAPHIDException

import ctap.constants

log = logging.getLogger('debug')
ctaplog = logging.getLogger('debug.ctap')
usbhid = logging.getLogger('debug.usbhid')

class CTAPHIDCMD(ABC):
    
    def __init__(self, CID:bytes, CMD:ctap.constants.CTAP_CMD, BCNT, payload:bytes):
        self._CID = CID
        self._CMD = CMD
        self._BCNT = BCNT
        if self._BCNT  > ctap.constants.MAX_PAYLOAD:
            self._payload = payload
        else:
            self._payload = payload[:self._BCNT]
        ctaplog.debug("Created CTAPHID CMD: %s", self)
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
    
    def set_channel_id(self, channel_id:bytes):
        self._CID = channel_id
    def get_length(self):
        return self._BCNT
    
    def get_CMD(self):
        return self._CMD
    
    def get_CID(self):
        return self._CID
    def get_payload(self):
        return self._payload

    def get_HID_packets(self):
        if self._BCNT>ctap.constants.MAX_PAYLOAD:
            usbhid.debug("Payload greater than single packet size, creating packets")
            packets = []
            packet = HIDInitializationPacket(self._CID,self._CMD,self._BCNT,self._payload[:ctap.constants.MAX_PAYLOAD])
            packets.append(packet)
            payload_index = ctap.constants.MAX_PAYLOAD
            for seq in range(128):
                end = min(self._BCNT-payload_index,ctap.constants.MAX_CONTINUATION_PAYLOAD)
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

    @abstractmethod
    def verify(self):
        pass

    def append_continuation_packet(self,packet:HIDPacket):
        usbhid.debug("Appending continuation packet: %s", packet)
        if packet.CMDTYPE != ctap.constants.CMD_TYPE.CONTINUATION:
            raise Exception("Cannot append a non-continuation packet to a message")
        if self.remaining_bytes > ctap.constants.MAX_CONTINUATION_PAYLOAD:
            self._payload += packet.get_payload()
            self.remaining_bytes = self.remaining_bytes - ctap.constants.MAX_CONTINUATION_PAYLOAD
        else:
            self._payload += packet.get_payload()[:self.remaining_bytes]
            self.remaining_bytes = 0 
    
    @staticmethod
    def create_message(packet: HIDPacket):
        """
        docstring
        """
        if packet.get_CMD() == ctap.constants.CTAP_CMD.CTAPHID_INIT:
            return CTAPHIDInitRequest(packet)
        elif packet.get_CMD() == ctap.constants.CTAP_CMD.CTAPHID_MSG:
            return CTAPHIDMsgRequest(packet)
        elif packet.get_CMD() == ctap.constants.CTAP_CMD.CTAPHID_CBOR:
            return CTAPHIDCBORRequest(packet)
        elif packet.get_CMD() == ctap.constants.CTAP_CMD.CTAPHID_WINK:
            return CTAPHIDWinkRequest(packet)
        elif packet.get_CMD() == ctap.constants.CTAP_CMD.CTAPHID_CANCEL:
            return CTAPHIDCancelRequest(packet)
        elif packet.get_CMD() == ctap.constants.CTAP_CMD.CTAPHID_PING:
            return CTAPHIDPingRequest(packet)
        else:
            raise CTAPHIDException(ctap.constants.CTAPHID_ERROR.ERR_INVALID_CMD,"Unknown Command")

class CTAPHIDMsgRequest(CTAPHIDCMD):
    """CTAP2 MSG Request

    Receives parameters as per the standard:

    """
    def __init__(self, packet: HIDInitializationPacket):
        super().__init__(packet.get_CID(), packet.get_CMD(),packet.get_length(),packet.get_payload())
        self._U2F_CMD = self._payload[0]
        

    def get_cmd_data(self):
        return self._payload[1:]    

    def verify(self):
        print("ERROR WE SHOULDN'T RECEIVE THIS MESSAGE")

class CTAPHIDMsgResponse(CTAPHIDCMD):
    """CTAP MSG Response consists of the following:

        Response at success
            CMD 	CTAPHID_MSG
            BCNT 	1..(n + 1)
            DATA 	U2F status code
            DATA + 1 	n bytes of data
    """
    def __init__(self,CID, U2F_Status,payload_data:bytes):     
        payload = bytearray(len(payload_data)+1)
        payload[0] = U2F_Status
        payload[1:]=payload_data
        ctaplog.debug("Create initial MSG response %s",payload.hex())
        super().__init__(CID,ctap.constants.CTAP_CMD.CTAPHID_MSG,len(payload),payload)

    def verify(self):
        """
        We don't verify the construction of responses
        """



class CTAPHIDCancelRequest(CTAPHIDCMD):
    """CTAP HID Cancel Request. Consists of the following:

        Request
            CMD 	CTAPHID_CANCEL
            BCNT 	0 
    """
    def __init__(self, packet: HIDInitializationPacket):
        super().__init__(packet.get_CID(), packet.get_CMD(),packet.get_length(),packet.get_payload())
        
    def verify(self):
        if len(self._payload)>0:
            raise CTAPHIDException(ctap.constants.CTAPHID_ERROR.ERR_INVALID_LEN)


class CTAPHIDCancelResponse(CTAPHIDCMD):
    """CTAP Cancel Response consisting of:

        Response at success
            CMD 	CTAPHID_CANCEL
            BCNT 	0 

    """
    def __init__(self,CID):     
        ctaplog.debug("Create initial Cancel response")
        super().__init__(CID,ctap.constants.CTAP_CMD.CTAPHID_CANCEL,0,bytes(0))

    def verify(self):
        """
        We don't verify the construction of responses
        """

class CTAPHIDKeepAliveResponse(CTAPHIDCMD):
    """CTAP KeepAlive Response consists of:
    
        Response at success
            CMD 	CTAPHID_KEEPALIVE
            BCNT 	1
            DATA 	Status code

            The following status codes are defined
            STATUS_PROCESSING 	1 	The authenticator is still processing the current request.
            STATUS_UPNEEDED 	2 	The authenticator is waiting for user presence. 
    """
    def __init__(self,CID,status_code:ctap.constants.CTAPHID_KEEPALIVE_STATUS):     
        ctaplog.debug("Create Keep-alive response")
        super().__init__(CID,ctap.constants.CTAP_CMD.CTAPHID_KEEPALIVE,1,status_code.value)

    
    def verify(self):
        """
        We don't verify the construction of responses
        """

class CTAPHIDErrorResponse(CTAPHIDCMD):
    """CTAP Error Response consists of:

        Response at success
            CMD 	CTAPHID_ERROR
            BCNT 	1
            DATA 	Error code 
    """
    def __init__(self,CID,error_code:ctap.constants.CTAPHID_ERROR):     
        ctaplog.debug("Create initial Error response")
        super().__init__(CID,ctap.constants.CTAP_CMD.CTAPHID_ERROR,1,error_code.value)

    def verify(self):
        pass

class CTAPHIDWinkRequest(CTAPHIDCMD):
    """CTAP Wink Request consists of:

        Request
            CMD 	CTAPHID_WINK
            BCNT 	0
            DATA 	N/A 

    """
    def __init__(self, packet: HIDInitializationPacket):
        super().__init__(packet.get_CID(), packet.get_CMD(),packet.get_length(),packet.get_payload())
        self.verify()

    def verify(self):
        if len(self._payload)>0:
            raise CTAPHIDException(ctap.constants.CTAPHID_ERROR.ERR_INVALID_LEN)

class CTAPHIDWinkResponse(CTAPHIDCMD):
    """CTAP Wink Response consists of:
        Response at success
            CMD 	CTAPHID_WINK
            BCNT 	0
            DATA 	N/A 

    """
    def __init__(self,CID,payload_data:bytes):     
        ctaplog.debug("Create initial WINK response %s",payload_data)
        super().__init__(CID,ctap.constants.CTAP_CMD.CTAPHID_WINK,len(payload_data),payload_data)

    def verify(self):
        """
        We don't verify the construction of responses
        """


class CTAPHIDPingRequest(CTAPHIDCMD):
    """CTAP Ping Reqeust consists of:

        Request
            CMD 	CTAPHID_PING
            BCNT 	0..n
            DATA 	n bytes 
    """
    def __init__(self, packet: HIDInitializationPacket):
        super().__init__(packet.get_CID(), packet.get_CMD(),packet.get_length(),packet.get_payload())
        

    def verify(self):
        if not len(self._payload) == self._BCNT:
            raise CTAPHIDException(ctap.constants.CTAPHID_ERROR.ERR_INVALID_LEN)

class CTAPHIDPingResponse(CTAPHIDCMD):
    """CTAP Ping Response consists of:

        Response at success
            CMD 	CTAPHID_PING
            BCNT 	n
            DATA 	N bytes 
    """
    def __init__(self,CID,payload_data:bytes):     
        ctaplog.debug("Create initial PING response %s",payload_data)
        super().__init__(CID,ctap.constants.CTAP_CMD.CTAPHID_PING,len(payload_data),payload_data)

    def verify(self):
        """
        We don't verify the construction of responses
        """



class CTAPHIDCBORRequest(CTAPHIDCMD):
    """CTAP CBOR Request consists of:

        Request
            CMD 	CTAPHID_CBOR
            BCNT 	1..(n + 1)
            DATA 	CTAP command byte
            DATA + 1 	n bytes of CBOR encoded data 
    """
    def __init__(self, packet: HIDInitializationPacket):
        super().__init__(packet.get_CID(), packet.get_CMD(),packet.get_length(),packet.get_payload())
        self._CTAP_CMD = self._payload[0]

    def get_cmd_data(self):
        return self._payload[1:]    

    def verify(self):
        if self._BCNT != len(self._payload):
            raise CTAPHIDException(ctap.constants.CTAPHID_ERROR.ERR_INVALID_LEN)
        try:
            ctap.constants.AUTHN_CMD(self._payload[0].to_bytes(1,"big"))
        except ValueError:
            if not (self._CTAP_CMD >= int.from_bytes(ctap.constants.AUTHN_CMD.AUTHN_VendorFirst.value,"big") and self._CTAP_CMD <= int.from_bytes(ctap.constants.AUTHN_CMD.AUTHN_VendorLast.value,"big")):
                raise CTAPHIDException(ctap.constants.CTAPHID_ERROR.ERR_INVALID_PAR)
        
        

class CTAPHIDCBORResponse(CTAPHIDCMD):
    """CTAP CBOR Response consists of:

        Response at success
            CMD 	CTAPHID_MSG
            BCNT 	1..(n + 1)
            DATA 	CTAP status code
            DATA + 1 	n bytes of CBOR encoded data 
    """
    def __init__(self,CID, CTAP_Status:ctap.constants.CTAP_STATUS_CODE,payload_data:bytes=bytes(0)):     
        payload = bytearray(len(payload_data)+1)
        payload[0] = CTAP_Status.value[0]
        payload[1:]=payload_data
        ctaplog.debug("Create initial CBOR response %s",payload)
        super().__init__(CID,ctap.constants.CTAP_CMD.CTAPHID_CBOR,len(payload),payload)

    def verify(self):
        """
        We don't verify the construction of responses
        """

class CTAPHIDInitRequest(CTAPHIDCMD):
    def __init__(self, packet: HIDInitializationPacket):
        super().__init__(packet.get_CID(), packet.get_CMD(),packet.get_length(),packet.get_payload())
        self.verify()
    
    def verify(self):
        if(self.get_length()!= 8):
            raise Exception("Invalid init message length")


class CTAPHIDInitResponse(CTAPHIDCMD):
    """CTAP Init Response consists of:

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
        ctaplog.debug("Creating initial response: %s",payload.hex())
        super().__init__(ctap.constants.BROADCAST_ID,ctap.constants.CTAP_CMD.CTAPHID_INIT,17,payload)   

    def set_nonce(self, nonce:bytes):
        self._payload[0:8]=nonce

    def set_channel_id(self, channel_id:bytes):        
        self._payload[8:12] = channel_id

    
    def set_protocol_version(self, version:int):
        self._payload[12] = version.to_bytes(1,"big")
    
    def set_capability_flag(self, flag):
        """Sets the capability flag

        Flag is the XOR of the CAPABILITY_ flags defined in the class
        Args:
            flag (int): flag to set
        """
        self._payload[18] = flag

    
    def verify(self):
        """
        We don't verify the construction of responses
        """
