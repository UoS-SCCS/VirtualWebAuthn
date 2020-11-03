from HIDPacket import HIDPacket
from USBHID import USBHID
from USBHID import USBHIDListener
from CTAPHID import CTAPHID
import sys
import logging
import os
class CTAP2Listener(USBHIDListener):
    def received_packet(self, packet):
        print(packet.debug_str())
    
    def response_sent(self, transaction):
        print("response sent")
        pass

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
#usbdevice = open("/dev/hidg0","rb+") 
usbdevice = os.open("/dev/hidg0", os.O_RDWR)
usbhid = USBHID(usbdevice)
ctaphid = CTAPHID(usbhid)
#ctap2 = CTAP2Listener()
usbhid.set_listener(ctaphid)
usbhid.start()

#broadcast_id = bytes([255,255,255,255])
#def process_message(msg):
#    hid_packet = HIDPacket(msg)
#    print(hid_packet.debug_str())
#    print("In process message")
    #if msg[:4] == broadcast_id:
     #   print("Received broadcast message")
     #   print(msg)
    #else:
    #    print("Channel " + msg[:4] + " message received")
    
while 1:
    for line in sys.stdin:
        
        if line.rstrip() == "quit":
            print("quit called")
            #This doesn't actually kill the thread because python handles threads in a bizarre way
            usbhid.shutdown()
            #usbdevice.flush()
            #usbdevice.seek(0)
            #usbdevice.close()
            print("file closed")
            sys.exit()
            
        else:
            print(len(line.rstrip()))

#Received broadcast message
#b'\xff\xff\xff\xff\x86\x00\x08\xaf\x93\xa6\xac8\xeb\xa1\xec\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'