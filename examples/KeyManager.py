from __future__ import print_function, absolute_import, unicode_literals

from fido2.hid import CtapHidDevice, CAPABILITY
from fido2.ctap2 import CTAP2, PinProtocolV1
from os import system, name 
import sys
import getpass


try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None


def enumerate_devices():
    for dev in CtapHidDevice.list_devices():
        yield dev
    if CtapPcscDevice:
        for dev in CtapPcscDevice.list_devices():
            yield dev
# define our clear function 
def clear(): 
  
    # for windows 
    if name == 'nt': 
        _ = system('cls') 
  
    # for mac and linux(here, os.name is 'posix') 
    else: 
        _ = system('clear') 
def show_menu():
    clear()
    print("DICE Key Manager")
    print("================")
    print("\t1. Set PIN")
    print("\t2. Change PIN")
    print("\t3. Get PIN Token")
    print("\t4. Get PIN Retries remaining")
    print("\t5. Wink")
    print("\t9. Reset")
    print("\t0. Quit")
def any_key():
    print("Press any key to continue")
    sys.stdin.readline().rstrip()
for dev in enumerate_devices():
    print("CONNECT: %s" % dev)
    print("CTAPHID protocol version: %d" % dev.version)

    if dev.capabilities & CAPABILITY.CBOR:
        ctap2 = CTAP2(dev)
        info = ctap2.get_info()
        print("DEVICE INFO: %s" % info)
        while 1:
            try:
                show_menu()
                cmd=input("Please enter an option and press return: ")
                
                clear()
                if cmd == "0":
                    print("Quit Called")
                    dev.close()
                    sys.exit()
                elif cmd == "1":
                    print("Set PIN")
                    print("=======")
                    cur_pin = getpass.getpass("Please enter PIN:")
                    client_pin = PinProtocolV1(ctap2)
                    client_pin.set_pin(cur_pin)
                    
                elif cmd == "2":
                    print("Change PIN")
                    print("==========")
                    cur_pin = getpass.getpass("Please enter current PIN:")
                    new_pin = getpass.getpass("Please enter new PIN:")
                    client_pin = PinProtocolV1(ctap2)
                    client_pin.change_pin(cur_pin,new_pin)
                    
                elif cmd == "3":
                    print("Get PIN Token")
                    print("=============")
                    cur_pin = getpass.getpass("Please enter PIN:")
                    client_pin = PinProtocolV1(ctap2)
                    print("PinToken: %s" % client_pin.get_pin_token(cur_pin))
                elif cmd == "4":
                    print("Get Retries Remaining")
                    print("=====================")
                    client_pin = PinProtocolV1(ctap2)
                    print("Retries remaining: %s" % client_pin.get_pin_retries())
                elif cmd == "5":
                    print("Wink")
                    print("====")
                    if dev.capabilities & CAPABILITY.WINK:
                        dev.wink()
                        print("WINK sent!")
                    else:
                        print("Device does not support WINK")
                elif cmd == "9":
                    print("Reset")
                    print("=====")
                    print("Enter Y to confirm")
                    if sys.stdin.readline().rstrip() == "Y":
                        ctap2.reset()
                    else:
                        print("Aborting reset")
                else:
                    print("Unknown command entered on CLI: %s" % cmd)
            except Exception as e:
                print("Error: %s" % e)
            any_key()
    else:
        print("Device does not support CBOR")
    
    dev.close()