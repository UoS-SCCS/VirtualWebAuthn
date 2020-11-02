from HIDPacket import HIDInitializationPacket


from HIDPacket import HIDPacket

from abc import ABC, abstractmethod
import CTAPHIDConstants
import logging
class CTAPHIDCMD(ABC):
    
    def __init__(self, CID:bytes, CMD:CTAPHIDConstants.CTAP_CMD, BCNT, payload:bytes):
        self._CID = CID
        self._CMD = CMD
        self._BCNT = BCNT
        if self._BCNT  > CTAPHIDConstants.MAX_PAYLOAD:
            self._payload = payload
        else:
            self._payload = payload[:self._BCNT]
        logging.debug("Created CTAPHIDCMD: %s, %s, %s, %s, %s",CID,CMD,BCNT,self._payload,len(self._payload))
        self.remaining_bytes = self._BCNT - len(self._payload)

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
            #sequence
            pass
        else:
            packet = HIDInitializationPacket(self._CID,self._CMD,self._BCNT,self._payload)
            return [packet]

    def verify(self):
        pass

    def append_continuation_packet(self,packet:HIDPacket):
        if packet.CMDTYPE != CTAPHIDConstants.CMD_TYPE.CONTINUATION:
            raise Exception("Cannot append a non-continuation packet to a message")
        if self.remaining_bytes > CTAPHIDConstants.MAX_PAYLOAD:
            self._payload += packet.data
            self.remaining_bytes = self.remaining_bytes - CTAPHIDConstants.MAX_PAYLOAD
        else:
            self._payload += packet.data[:self.remaining_bytes]
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
        logging.debug("Create initial MSG response %s",payload)
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
        logging.debug("Create initial Cancel response")
        super().__init__(CID,CTAPHIDConstants.CTAP_CMD.CTAPHID_CANCEL,0,bytes(0))

"""
Response at success
CMD 	CTAPHID_ERROR
BCNT 	1
DATA 	Error code 
"""
class CTAPHIDErrorResponse(CTAPHIDCMD):

    def __init__(self,CID,error_code:CTAPHIDConstants.CTAPHID_ERROR):     
        logging.debug("Create initial Error response")
        super().__init__(CID,CTAPHIDConstants.CTAP_CMD.CTAPHID_ERROR,1,error_code)


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
        logging.debug("Create initial PING response %s",payload_data)
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

    def __init__(self,CID, CTAP_Status,payload_data:bytes):     
        payload = bytearray(len(payload_data)+1)
        payload[0] = CTAP_Status
        payload[1:]=payload_data
        logging.debug("Create initial CBOR response %s",payload)
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

    def __init__(self):     
        payload = bytearray(17) #17 bytes of data
        payload[12] = 2
        payload[13] = 0
        payload[14] = 1
        payload[15] = 1
        payload[16] = CTAPHIDInitResponse.CAPABILITY_CBOR[0]
        logging.debug("Create initial Init response %s",payload)
        super().__init__(CTAPHIDConstants.BROADCAST_ID,CTAPHIDConstants.CTAP_CMD.CTAPHID_INIT,17,payload)   

    def set_nonce(self, nonce:bytes):
        logging.debug("Setting nonce %s, %s",nonce,self._payload)
        self._payload[0:8]=nonce
        logging.debug("Setting nonce %s, %s",nonce,self._payload)

    def set_channel_id(self, channel_id:bytes):
        logging.debug("Set Channel ID: %s, %s",channel_id,len(channel_id))
        self._payload[8:12] = channel_id

    
    def set_protocol_version(self, version):
        self._payload[12] = version
    
    """
    Flag is the XOR of the CAPABILITY_ flags defined in the class
    """
    def set_capability_flag(self, flag):
        self._payload[18] = flag

    
