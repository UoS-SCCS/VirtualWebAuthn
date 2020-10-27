# Virtual WebAuthN
This repository contains work in progress for building a Virtual WebAuthN Token.

## Current Status
Proof of concept has been shown with the use of [Solo](https://github.com/solokeys/solo) and hints from [https://blog.hansenpartnership.com/webauthn-in-linux-with-a-tpm-via-the-hid-gadget/](https://blog.hansenpartnership.com/webauthn-in-linux-with-a-tpm-via-the-hid-gadget/)

I would recommed performing the following in a Virtual Machine, I've tested on Ubuntu 20.04. The kernel version needs to be fairly recent to include a patch that would cause errors when creating the virtual USB device. 

Steps to setup:
* Clone this repository
* Ensure that the kernel sources have been installed:
    ``` 
    sudo apt-get update
    sudo apt-get install linux-source
    ```
* Navigate to `udev_rules` and run `sudo ./set_udev_rules.sh` this will set the rules that permit access to the Virtual USB device without needing root access, which Chrome will not have.
* Run `sudo make install`
* This should create a virtual HID device that appears to be a CTAP key device. Note, I needed to reboot before I could get this to work correctly. If it has worked correctly you should see output similar to this:
    ```
    modprobe libcomposite
    insmod dummy_hcd.ko
    mkdir -p /sys/kernel/config/usb_gadget/fido2
    mkdir -p /sys/kernel/config/usb_gadget/fido2/configs/c.1
    mkdir -p /sys/kernel/config/usb_gadget/fido2/functions/hid.usb0
    echo 0 > /sys/kernel/config/usb_gadget/fido2/functions/hid.usb0/protocol
    echo 0 > /sys/kernel/config/usb_gadget/fido2/functions/hid.usb0/subclass
    echo 64 > /sys/kernel/config/usb_gadget/fido2/functions/hid.usb0/report_length
    echo -ne "\x06\xd0\xf1\x09\x01\xa1\x01\x09\x20\x15\x00\x26\xff\x00\x75\x08\x95\x40\x81\x02\x09\x21\x15\x00\x26\xff\x00\x75\x08\x95\x40\x91\x02\xc0" > /sys/kernel/config/usb_gadget/fido2/functions/hid.usb0/report_desc
    mkdir /sys/kernel/config/usb_gadget/fido2/strings/0x409
    mkdir /sys/kernel/config/usb_gadget/fido2/configs/c.1/strings/0x409
    echo "0xa2ca" > /sys/kernel/config/usb_gadget/fido2/idProduct
    echo "0x0483" > /sys/kernel/config/usb_gadget/fido2/idVendor
    echo "1234567890" > /sys/kernel/config/usb_gadget/fido2/strings/0x409/serialnumber
    echo "Solo" > /sys/kernel/config/usb_gadget/fido2/strings/0x409/manufacturer
    echo "Solo Software Authenticator" > /sys/kernel/config/usb_gadget/fido2/strings/0x409/product
    echo "Configuration 1" > /sys/kernel/config/usb_gadget/fido2/configs/c.1/strings/0x409/configuration
    echo 120 > /sys/kernel/config/usb_gadget/fido2/configs/c.1/MaxPower
    ln -s /sys/kernel/config/usb_gadget/fido2/functions/hid.usb0 /sys/kernel/config/usb_gadget/fido2/configs/c.1
    echo "dummy_udc.0" > /sys/kernel/config/usb_gadget/fido2/UDC
    ```
* If you check `dmesg` you should see the following:
    ```
    [   48.841857] dummy_hcd dummy_hcd.0: USB Host+Gadget Emulator, driver 02 May 2005
    [   48.841860] dummy_hcd dummy_hcd.0: Dummy host controller
    [   48.841862] dummy_hcd dummy_hcd.0: new USB bus registered, assigned bus number 1
    [   48.841904] usb usb1: New USB device found, idVendor=1d6b, idProduct=0002, bcdDevice= 5.04
    [   48.841905] usb usb1: New USB device strings: Mfr=3, Product=2, SerialNumber=1
    [   48.841906] usb usb1: Product: Dummy host controller
    [   48.841907] usb usb1: Manufacturer: Linux 5.4.0-52-generic dummy_hcd
    [   48.841908] usb usb1: SerialNumber: dummy_hcd.0
    [   48.842182] hub 1-0:1.0: USB hub found
    [   48.842201] hub 1-0:1.0: 1 port detected
    [   49.174446] usb 1-1: new high-speed USB device number 2 using dummy_hcd
    [   49.433561] usb 1-1: New USB device found, idVendor=0483, idProduct=a2ca, bcdDevice= 5.04
    [   49.433565] usb 1-1: New USB device strings: Mfr=1, Product=2, SerialNumber=3
    [   49.433567] usb 1-1: Product: Solo Software Authenticator
    [   49.433568] usb 1-1: Manufacturer: Solo
    [   49.433570] usb 1-1: SerialNumber: 1234567890
    [   49.441803] configfs-gadget gadget: high-speed config #1: c
    [   49.482037] hidraw: raw HID events driver (C) Jiri Kosina
    [   49.510015] usbcore: registered new interface driver usbhid
    [   49.510016] usbhid: USB HID core driver
    [   49.521664] hid-generic 0003:0483:A2CA.0001: hiddev0,hidraw0: USB HID v1.01 Device [Solo Solo Software Authenticator] on usb-dummy_hcd.0-1/input0
    ```
* At this point you should see two new devices prefixed with `hidraw` and `hidg`. For example, `hidraw0` and `hidg0`. I have had some problems with this happening, particularly after a soft restart, i.e. out of suspend. If in doubt reboot and repeat the steps above. 

### Test
* Clone [Solo](https://github.com/solokeys/solo)
    * `git clone --recurse-submodules https://github.com/solokeys/solo`
    * `cd solo`
    * `make all`
* Start Solo `sudo ./main -b hidg`
* You should see the following:
    ```
    [DEBUG] Using hidg backing
    state file does not exist, creating it
    [ERR] Current firmware version address: 0x5604f580f1ec
    [ERR] Current firmware version: 4.0.0.0 (04.00.00.00)
    [STOR] Generated PIN SALT: e3 48 f4 7b 47 e8 96 9d 96 63 32 90 a3 d3 d8 ce 80 ee 37 06 97 37 e4 f9 03 e9 33 2c 3b 83 9e 63 
    [STOR] pin not set.
    ```
* In Chrome navigate to a test WebAuthN website and attempt to register
    * https://webauthn.io/
    * https://www.passwordless.dev/passwordless#heroFoot

