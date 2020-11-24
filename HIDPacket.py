import CTAPHIDConstants
from abc import ABC, abstractmethod
import logging
import json

log = logging.getLogger('debug')

usbhid = logging.getLogger('debug.usbhid')

class HIDPacket:
    _BROADCAST_ID = b'\xff\xff\xff\xff'
    
    def __init__(self, data):
        self._data = data

    def get_bytes(self):
        
        if len(self._data) < 64:
            return self._data + bytes(64-len(self._data))
        else:
            return self._data

    @abstractmethod
    def get_payload(self)->bytes:
        pass

    @classmethod
    def from_bytes(cls, packet:bytes):
        if (packet[4] & (1 << 7)):
            return HIDInitializationPacket.from_bytes(packet)
        else:
            return HIDContinuationPacket.from_bytes(packet)
    @abstractmethod
    def debug_str(self):
        pass

"""
Offset 	Length 	Mnemonic 	Description
0 	4 	CID 	Channel identifier
4 	1 	CMD 	Command identifier (bit 7 always set)
5 	1 	BCNTH 	High part of payload length
6 	1 	BCNTL 	Low part of payload length
7 	(s - 7) 	DATA 	Payload data (s is equal to the fixed packet size)
"""
class HIDInitializationPacket(HIDPacket):
    
    CMDTYPE = CTAPHIDConstants.CMD_TYPE.INITIALIZATION
    
    def __init__(self, CID:bytes, CMD:CTAPHIDConstants.CTAP_CMD, length, payload):
        self._CID=CID
        self._CMD=CMD
        self._length=length
        self._payload=payload
        packet = bytearray(64)
        packet[0:4] = self._CID
        
        packet[4] = self._CMD.value[0] ^ (1 << 7)
        packet[5:7]=self._length.to_bytes(2,'big')
        packet[7:] = self._payload
        if self._length > (64 - 7):
            self._has_sequence = True
        else:
            self._has_sequence = False
        super().__init__(packet)

    def __str__(self):
        out = {}
        out["CID"]=self._CID.hex()
        out["CMD"]=self._CMD.name
        out["length"] = self._length
        out["payload"] = self._payload.hex()
        return json.dumps(out)

    def get_CMD(self):
        return self._CMD
    
    def get_length(self):
        return self._length
    
    def get_payload(self)->bytes:
        return self._payload

    def get_CID(self):
        return self._CID
    @classmethod
    def from_bytes(cls, packet:bytes):
        channel_id = packet[:4]
        cmd = CTAPHIDConstants.CTAP_CMD((packet[4] & ~(1 << 7)).to_bytes(1,"big"))
        message_length = int.from_bytes(packet[5:7], "big")
        data = packet[7:]
        return HIDInitializationPacket(channel_id, cmd, message_length, data)
   
    @abstractmethod
    def debug_str(self):
        pass


"""
Offset 	Length 	Mnemonic 	Description
0 	4 	CID 	Channel identifier
4 	1 	SEQ 	Packet sequence 0x00..0x7f (bit 7 always cleared)
5 	(s - 5) 	DATA 	Payload data (s is equal to the fixed packet size) 
"""
class HIDContinuationPacket(HIDPacket):
    
    CMDTYPE = CTAPHIDConstants.CMD_TYPE.CONTINUATION
    
    def __init__(self, CID:bytes, seq, payload:bytes):
        self._CID=CID
        self._seq=seq
        self._payload=payload
        packet = bytearray(64)
        packet[0:4] = self._CID
        packet[4] = self._seq & ~(1 << 7)
        packet[5:] = self._payload
        super().__init__(packet)

    def __str__(self):
        out = {}
        out["CID"]=self._CID.hex()
        out["SEQ"]=self._seq
        out["payload"] = self._payload.hex()
        return json.dumps(out)
    
    def get_payload(self)->bytes:
        return self._payload
    def get_sequence(self):
        return self._seq
    @classmethod
    def from_bytes(cls, packet:bytes):
        channel_id = packet[:4]
        seq = packet[4]
        data = packet[5:]
        return HIDContinuationPacket(channel_id, seq, data)
   
    @abstractmethod
    def debug_str(self):
        pass