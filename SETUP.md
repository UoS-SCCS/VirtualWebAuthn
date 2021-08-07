# Virtual WebAuthN
This repository contains work in progress for building a Virtual WebAuthN Token.

## Current Status
Proof of concept implementation, current status:
### Implemented
* CTAPHID commands
    * CTAPHID_MSG (partial)
    * CTAPHID_CBOR
    * CTAPHID_INIT
    * CTAPHID_PING
    * CTAPHID_CANCEL
    * CTAPHID_ERROR
    * CTAPHID_KEEPALIVE
    * CTAPHID_WINK
* Authenticator API
    * authenticatorMakeCredential
    * authenticatorGetAssertion
    * authenticatorGetNextAssertion
    * authenticatorGetInfo
    * authenticatorClientPIN
        * Authenticator Configuration Operations Upon Power Up
        * Getting Retries from Authenticator
        * Getting sharedSecret from Authenticator
        * Setting a New PIN
        * Changing existing PIN
        * Getting pinToken from the Authenticator
        * Using pinToken
            * Using pinToken in authenticatorMakeCredential
            * Using pinToken in authenticatorGetAssertion
            * Without pinToken in authenticatorGetAssertion (*Needs testing*)
    * authenticatorReset (0x07)

### TODO
* CTAPHID commands
    * CTAPHID_MSG - The USB handling of this is implemented in the framework but no message handling code has been written since it is for CTAP1/U2F which doesn't provide the functionality being explored in the current project. Such functionality could be added by extending the process\_msg\_request function in ctap.py and adding the necessary functions to the authenticator framework.
    * ~~CTAPHID_LOCK~~ implemented but not tested due to client not using it
* Additional Attestation Statement formats
* Additional Attestation Types
* Expand to handle different simultaneous TPM and non-TPM crypto providers for the same algorithm

## Setup
We would recommed performing the following in a Virtual Machine, it has been tested on Ubuntu 20.04. The kernel version needs to be fairly recent to include a patch that would cause errors when creating the virtual USB device.

### Virtual Machine Setup
* Download VirtualBox [https://www.virtualbox.org/](https://www.virtualbox.org/)
* Download an Ubuntu ISO: [https://ubuntu.com/download/desktop](https://ubuntu.com/download/desktop)
* Follow the tutorial at [https://fossbytes.com/how-to-install-ubuntu-20-04-lts-virtualbox-windows-mac-linux/](https://fossbytes.com/how-to-install-ubuntu-20-04-lts-virtualbox-windows-mac-linux/) Follow the basic setup, there is no need to change partition structures
* Check your VM boots
* Perform the steps below in your VirtualBox instance

### Prerequisites
* Install the following dependencies (note: this may not be a complete list, if you get errors create an issue):
    ```
    sudo apt-get install build-essential git chromium-browser python3 pip3 libssl-dev qt5-default
    ```
* In a terminal install some Python dependencies:
    ```
    pip3 install pyqt5 fido2
    ```

### Steps to setup:

* Clone this repository
* Ensure that the kernel sources have been installed:
    ```
    sudo apt-get update
    sudo apt-get install linux-source
    ```
* Navigate to `udev_rules` and run `sudo ./set_udev_rules.sh` this will set the rules that permit access to the Virtual USB device without needing root access, which Chrome will not have.
* Move directory `cd Create_USB_Gadget`
* Run `sudo make install`
* This should create a virtual HID device that appears to be a CTAP key device. Note, I needed to reboot before I could get this to work correctly. If it has worked correctly you should see output similar to this:
    ```
    tar -xvf /usr/src/linux-source-5.4.0.tar.bz2 linux-source-5.4.0/drivers/usb/gadget/udc/dummy_hcd.c
    linux-source-5.4.0/drivers/usb/gadget/udc/dummy_hcd.c
    cp linux-source-5.4.0/drivers/usb/gadget/udc/dummy_hcd.c dummy_hcd.c
    make -C /lib/modules/5.4.0-53-generic/build M=/home/dev/git/VirtualWebAuthN/Create_USB_Gadget modules
    make[1]: Entering directory '/usr/src/linux-headers-5.4.0-53-generic'
    CC [M]  /home/dev/git/VirtualWebAuthN/Create_USB_Gadget/dummy_hcd.o
    Building modules, stage 2.
    MODPOST 1 modules
    CC [M]  /home/dev/git/VirtualWebAuthN/Create_USB_Gadget/dummy_hcd.mod.o
    LD [M]  /home/dev/git/VirtualWebAuthN/Create_USB_Gadget/dummy_hcd.ko
    make[1]: Leaving directory '/usr/src/linux-headers-5.4.0-53-generic'
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
    echo "0x05df" > /sys/kernel/config/usb_gadget/fido2/idProduct
    echo "0x16c0" > /sys/kernel/config/usb_gadget/fido2/idVendor
    echo "6548556985" > /sys/kernel/config/usb_gadget/fido2/strings/0x409/serialnumber
    echo "DICEProject" > /sys/kernel/config/usb_gadget/fido2/strings/0x409/manufacturer
    echo "DICEKey Software Authenticator" > /sys/kernel/config/usb_gadget/fido2/strings/0x409/product
    echo "Configuration 1" > /sys/kernel/config/usb_gadget/fido2/configs/c.1/strings/0x409/configuration
    echo 120 > /sys/kernel/config/usb_gadget/fido2/configs/c.1/MaxPower
    ln -s /sys/kernel/config/usb_gadget/fido2/functions/hid.usb0 /sys/kernel/config/usb_gadget/fido2/configs/c.1
    echo "dummy_udc.0" > /sys/kernel/config/usb_gadget/fido2/UDC
    ```
* If you check `dmesg` you should see the following:
    ```
    [26093.700158] dummy_hcd dummy_hcd.0: USB Host+Gadget Emulator, driver 02 May 2005
    [26093.700161] dummy_hcd dummy_hcd.0: Dummy host controller
    [26093.700164] dummy_hcd dummy_hcd.0: new USB bus registered, assigned bus number 1
    [26093.700209] usb usb1: New USB device found, idVendor=1d6b, idProduct=0002, bcdDevice= 5.04
    [26093.700210] usb usb1: New USB device strings: Mfr=3, Product=2, SerialNumber=1
    [26093.700212] usb usb1: Product: Dummy host controller
    [26093.700213] usb usb1: Manufacturer: Linux 5.4.0-53-generic dummy_hcd
    [26093.700214] usb usb1: SerialNumber: dummy_hcd.0
    [26093.700356] hub 1-0:1.0: USB hub found
    [26093.700362] hub 1-0:1.0: 1 port detected
    [26094.036899] usb 1-1: new high-speed USB device number 2 using dummy_hcd
    [26094.260980] usb 1-1: New USB device found, idVendor=16c0, idProduct=05df, bcdDevice= 5.04
    [26094.260983] usb 1-1: New USB device strings: Mfr=1, Product=2, SerialNumber=3
    [26094.260985] usb 1-1: Product: DICEKey Software Authenticator
    [26094.260986] usb 1-1: Manufacturer: DICEProject
    [26094.260988] usb 1-1: SerialNumber: 6548556985
    [26094.268865] configfs-gadget gadget: high-speed config #1: c
    [26094.309302] hid-generic 0003:16C0:05DF.0002: hiddev0,hidraw0: USB HID v1.01 Device [DICEProject DICEKey Software Authenticator] on usb-dummy_hcd.0-1/input0

    ```
* At this point you should see three new devices, two prefixed with `hidraw` and `hidg` (For example, `hidraw0` and `hidg0`), and one called `dicekey`. If you have any problems in not seening these devices try rebooting the machine first and trying again.

#### Setup TPM
* Follow the instructions in [Installing_IBM_software](Installing_IBM_software.md) to create and start the IBM Simulator
* Once complete you should be able to run the simulator using `sudo /opt/ibmtpm/src/tpm_server`
    * use `sudo /opt/ibmtpm/src/tpm_server --rm` to reset the software TPM
* In this respository navigate to `./tpm/src` and then:
   1. Create a Build directory at the top level
   2. cd Build
   3. cmake ..
   4. make

* Once complete you should have a `./tpm/lib/libwatpm.so` file

### Running DiceKey
* Inside `./src` run `python3 dice_key.py`
* You'll be asked for a password and once started should see an icon of a die (dice) in the top right hand corner.
* Try creating a credential at [webauthni.io](https://webauthni.io)
* Note: you will need to have set the environment variables in the terminal where you launch python from if it is different to the one you
used previously. Use the following to set them up.

    ```
    export LD_LIBRARY_PATH=/opt/ibmtss/utils
    export PATH=$PATH:/opt/ibmtss/utils
    export TPM_INTERFACE_TYPE=socsim
    ```
### Key Manager
* Inside of the `examples` folder is a KeyManager.py that currently allows setting and changing of the PIN, issuing a WINK command, and getting a PIN Token and PIN retries.
* You will need to set a PIN using the KeyManager to force Chrome to start requesting a PIN.

### Test with Solo Keys - not required any longer
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

