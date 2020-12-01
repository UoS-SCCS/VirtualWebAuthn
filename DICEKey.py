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
import shutil
import time


def result():
    print("Result")

def setup_logger(logger_name, log_file, level=logging.DEBUG):
    l = logging.getLogger(logger_name)
    
    formatter = logging.Formatter('%(asctime)s : %(levelname)s : %(message)s')
    fileHandler = logging.FileHandler(log_file, mode='w')
    if logger_name=="debug":
        formatter = logging.Formatter('%(asctime)s : %(levelname)s : %(message)s')
        fileHandler.setFormatter(formatter)
        streamHandler = logging.StreamHandler()
        streamHandler.setFormatter(formatter)
        l.addHandler(streamHandler)    
        l.propagate = False
    else:
        fileHandler.setFormatter(formatter)
        l.propagate = True
    l.setLevel(level)
    l.addHandler(fileHandler)


timestr = time.strftime("%Y%m%d-%H%M%S")    
if not os.path.exists("./logs/"):
    os.mkdir("./logs/")
else:
    source_dir = './logs/'
    target_dir = './logs/archive/'
    if not os.path.exists(target_dir):
        os.mkdir(target_dir)
    file_names = os.listdir(source_dir)
    for file_name in file_names:
        shutil.move(os.path.join(source_dir, file_name), target_dir)

setup_logger('debug', r'./logs/debug_'+timestr+'.log')
setup_logger('debug.usbhid', r'./logs/usbhid_'+timestr+'.log')
setup_logger('debug.ctap', r'./logs/ctap_'+timestr+'.log')
setup_logger('debug.auth', r'./logs/auth_'+timestr+'.log')


log = logging.getLogger('debug')

#logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
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
usbhid.set_listener(ctaphid)
usbhid.start()


while 1:
    for line in sys.stdin:
        
        if line.rstrip() == "quit":
            log.debug("Quit Called")
            #This doesn't actually kill the thread because python handles threads in a bizarre way
            usbhid.shutdown()
            #usbdevice.flush()
            #usbdevice.seek(0)
            #usbdevice.close()
            sys.exit()
        else:
            log.debug("Unknown command entered on CLI: %s",line.rstrip() )
            



    