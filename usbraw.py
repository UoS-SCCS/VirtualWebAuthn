from HIDPacket import HIDPacket
from USBHID import USBHID
from USBHID import USBHIDListener
from CTAPHID import CTAPHID
from JSONAuthenticatorStorage import JSONAuthenticatorStorage
from MyAuthenticator import MyAuthenticator
from AuthenticatorCryptoProvider import AuthenticatorCryptoProvider
from ES256CryptoProvider import ES256CryptoProvider
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
usbdevice = os.open("/dev/dicekey", os.O_RDWR)
usbhid = USBHID(usbdevice)

ctaphid = CTAPHID(usbhid)
authenticator_storage = JSONAuthenticatorStorage("my_authenticator.json")
AuthenticatorCryptoProvider.add_provider(ES256CryptoProvider())
providers = []
providers.append(ES256CryptoProvider().get_alg())
if not authenticator_storage.is_initialised():
    authenticator_storage.init_new()
authenticator = MyAuthenticator(authenticator_storage,providers)
ctaphid.set_authenticator(authenticator)
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