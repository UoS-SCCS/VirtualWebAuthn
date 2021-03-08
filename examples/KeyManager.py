"""
 © Copyright 2020-2021 University of Surrey

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

"""
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