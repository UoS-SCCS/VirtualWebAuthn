"""Defines the base DICEAuthenticator with abstract methods
    that should be implemented by concrete subclasses that wish
    to provide Authenticator implementations.

Classes:
    DICEAuthenticator
"""
from abc import ABC, abstractmethod
import os
from uuid import UUID
import time
import shutil
import logging
from fido2 import cbor

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac

from hid.ctap import CTAPHID
from hid.usb import USBHID

import ctap.constants
from ctap.constants import (AUTHN_GET_CLIENT_PIN_SUBCMD,AUTHN_CMD)
from ctap.keep_alive import CTAPHIDKeepAlive
from ctap.credential_source import PublicKeyCredentialSource

from authenticator.datatypes import (AuthenticatorVersion, AuthenticatorGetAssertionParameters,
    AuthenticatorMakeCredentialParameters,AuthenticatorGetClientPINParameters,
    DICEAuthenticatorException)
from authenticator.cbor import (GetInfoResp, MakeCredentialResp,GetAssertionResp,GetClientPINResp,
    ResetResp,GetNextAssertionResp)
from authenticator.ui import DICEAuthenticatorListener, DICEAuthenticatorUI, ConsoleAuthenticatorUI

from crypto.crypto_provider import AuthenticatorCryptoProvider
from crypto.es256_crypto_provider import ES256CryptoProvider

log = logging.getLogger('debug')
auth = logging.getLogger('debug.auth')


class DICEAuthenticator(DICEAuthenticatorListener,ABC):
    """Base class for all Authenticators. This provides core functionality
    like message processing and interfacing with USB HID. It processes the
    incoming message then calls the appropriate abstractmethod to process
    the actual method.

    Implementations of an Authenticator should subclass this class and
    implement the abstractmethods to provide authenticator functionality.
    """
    AUTHENTICATOR_AAGUID = UUID("695e437f-c0cd-4fe8-b545-d39084f5c805")
    PIN_TOKEN_LENGTH = 64
    def __init__(self, pin_token_length=PIN_TOKEN_LENGTH,
            ui:DICEAuthenticatorUI=ConsoleAuthenticatorUI()):
        self._create_debug_logs()
        self._last_get_assertion_cid = None
        self._last_get_assertion_params =  None
        self._last_get_assertion_time = None
        self._last_get_assertion_idx = None
        self._storage = None
        self._usbdevice = None
        self._usbhid = None
        self._ctaphid = None
        self._authenticator_key_agreement_key=None
        self._pin_crypto_provider= ES256CryptoProvider()
        self._generate_authenticator_key_agreement_key()
        self._generate_pin_token(pin_token_length)
        self._ui = ui
        if not self._ui is None:
            self._ui.create()
            self._ui.add_listener(self)


    def shutdown(self):
        """Shutdown call to close and finish the USBHID connection
        """
        self._usbhid.shutdown()

    def _start(self,device:str="/dev/dicekey"):
        """Start the authenticator by opening a USBHID device to the
        specified device or the default /dev/dicekey.

        The device should be a USB gadget that implements the CTAP USBHID
        spec
        Args:
            device (str, optional): path to device. Defaults to "/dev/dicekey".
        """
        self._usbdevice = os.open(device, os.O_RDWR)
        self._usbhid = USBHID(self._usbdevice)
        self._ctaphid = CTAPHID(self._usbhid)
        self._ctaphid.set_authenticator(self)
        self._usbhid.set_listener(self._ctaphid)
        self._usbhid.start()
        if not self._ui is None:
            self._ui.start()

    def _create_debug_logs(self):
        """Create and cycle the debug logs
        """
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

        self._setup_logger('debug', r'./logs/debug_'+timestr+'.log')
        self._setup_logger('debug.usbhid', r'./logs/usbhid_'+timestr+'.log')
        self._setup_logger('debug.ctap', r'./logs/ctap_'+timestr+'.log')
        self._setup_logger('debug.auth', r'./logs/auth_'+timestr+'.log')

    def _setup_logger(self, logger_name:str, log_file:str, level:int=logging.DEBUG):
        """Setup a logger with the appropriate name and file

        Args:
            logger_name (str): logger name
            log_file (str): path to log file
            level (int, optional): log level. Defaults to logging.DEBUG.
        """
        new_log = logging.getLogger(logger_name)

        formatter = logging.Formatter('%(asctime)s : %(levelname)s : %(message)s')
        file_handler = logging.FileHandler(log_file, mode='w')
        if logger_name=="debug":
            formatter = logging.Formatter('%(asctime)s : %(levelname)s : %(message)s')
            file_handler.setFormatter(formatter)
            stream_handler = logging.StreamHandler()
            stream_handler.setFormatter(formatter)
            new_log.addHandler(stream_handler)
            new_log.propagate = False
        else:
            file_handler.setFormatter(formatter)
            new_log.propagate = True
        new_log.setLevel(level)
        new_log.addHandler(file_handler)

    def _generate_pin_token(self,pin_token_length:int):
        """Generate a new random bin token of specified length using
        os.urandom and set _pin_token to that value

        Args:
            pin_token_length (int): length of PIN token to generate in bytes
        """
        auth.debug("Generating new pinToken")
        self._pin_token = os.urandom(pin_token_length)
    def _generate_authenticator_key_agreement_key(self):
        """Generates a new authenticator key agreement key and sets it to
        authenticator_key_agreement_key
        """
        auth.debug("Generating new authenticatorKeyAgreementKey")
        self._authenticator_key_agreement_key = \
            self._get_pin_crypto_provider().create_new_key_pair()

    def get_aaguid(self)->UUID:
        """Get the Authenticator AA GUID

        Returns:
            UUID: AAGUID
        """
        return DICEAuthenticator.AUTHENTICATOR_AAGUID

    def process_cbor(self, cbor_data:bytes, keep_alive: CTAPHIDKeepAlive, cid:bytes=None)->bytes:
        """Process an incoming CBOR request

        This is the core of the authenticator since most of the WebAuthN messages are
        sent via CBOR. This method will create the appropriate parameter object and
        then call the abstract method for the concrete authenticator to process.

        The keep_alive object is from the underlying USBHID and allows the authenticator
        to trigger regular keep-alive messages to be sent whilst it is processing the
        request. By default these messages are not sent, they must be activated by calling
        the start method on the passed keep_alive object.
        Args:
            cbor_data (bytes): received CBOR bytes
            keep_alive (CTAPHIDKeepAlive): keep_alive object that can
            cid (bytes, optional): channel id. Defaults to None.

        Returns:
            bytes: CBOR encoded response to be wrapped and sent back to the client
        """
        if not bytes is None:
            self.check_get_last_assertion_cid(cid)

        cmd = cbor_data[:1]
        auth.debug("Received %s CBOR: %s", AUTHN_CMD(cmd).name, cbor_data.hex())
        if cmd == AUTHN_CMD.AUTHN_MakeCredential.value:
            params = AuthenticatorMakeCredentialParameters(cbor_data[1:])
            return self.authenticator_make_credential(params, keep_alive).get_encoded()
        if cmd == AUTHN_CMD.AUTHN_GetAssertion.value:
            params = AuthenticatorGetAssertionParameters(cbor_data[1:])
            get_assertion_resp = self.authenticator_get_assertion(params, keep_alive)
            if get_assertion_resp.get_count() > 1:
                self.set_get_assertion_params_start_timer(cid,params,1)
            else:
                self.clear_get_last_assertion()
            return get_assertion_resp.get_encoded()
        if cmd == AUTHN_CMD.AUTHN_GetInfo.value:
            return self.authenticator_get_info(keep_alive).get_encoded()
        if cmd == AUTHN_CMD.AUTHN_ClientPIN.value:
            params = AuthenticatorGetClientPINParameters(cbor_data[1:])
            return self.authenticator_get_client_pin(params, keep_alive).get_encoded()
        if cmd == AUTHN_CMD.AUTHN_Reset.value:
            return self.authenticator_reset(keep_alive).get_encoded()
        if cmd == AUTHN_CMD.AUTHN_GetNextAssertion.value:
            last = self.get_last_assertion_params(cid)
            get_next_resp = self.authenticator_get_next_assertion(last["params"],
                last["idx"], keep_alive)
            self.set_get_assertion_params_idx_reset_timer(last["idx"]+1)
            return get_next_resp.get_encoded()
        if cmd == AUTHN_CMD.AUTHN_BioEnrollment.value:
            pass
        if cmd == AUTHN_CMD.AUTHN_CredentialManagement.value:
            pass
        if cmd == AUTHN_CMD.AUTHN_PlatformConfig.value:
            pass
        if cmd == AUTHN_CMD.AUTHN_CredentialManagement.value:
            pass
        if cmd == AUTHN_CMD.AUTHN_VendorFirst.value:
            pass
        if cmd == AUTHN_CMD.AUTHN_VendorLast.value:
            pass



    def set_get_assertion_params_start_timer(self, cid:bytes,
            params:AuthenticatorGetAssertionParameters, idx:int):
        """Sets the start time the get assertion was called. This is required to
        determine if any future GetNextAssertion calls are within the timeout

        Args:
            cid (bytes): channel id
            params (AuthenticatorGetAssertionParameters): get assertion parameters
            idx (int): the current index of the credential being sent back
        """
        auth.debug("Setting getAssertion %s for Channel: %s with Index: %s", params, cid, idx)
        self._last_get_assertion_cid = cid
        self._last_get_assertion_params =  params
        self._last_get_assertion_time = int(time.time())
        self._last_get_assertion_idx = idx

    def set_get_assertion_params_idx_reset_timer(self, idx:int):
        """Resets the timer for the current GetAssertion, triggered when a
        GetNextAssertion is called

        Args:
            idx (int): index of the credential currently being sent back
        """
        auth.debug("Incrementing getAssertion Index: %s", idx)
        self._last_get_assertion_idx = idx
        self._last_get_assertion_time = int(time.time())

    def clear_get_last_assertion(self):
        """Clears the last GetAssertion after a timeout or different request
        """
        auth.debug("Clearing get assertion")
        self._last_get_assertion_cid = None
        self._last_get_assertion_params =  None
        self._last_get_assertion_time = None
        self._last_get_assertion_idx = None

    def get_last_assertion_cid(self)->bytes:
        """Get the channel ID of the currently set GetAssertion

        Returns:
            bytes: channel id of currently set GetAssertion
        """
        return self._last_get_assertion_cid

    def check_get_last_assertion_cid(self, cid:bytes)->bool:
        """Check that the set GetAssertion matches the received
        GetNextAssertion, if not reset.

        Args:
            cid (bytes): [description]

        Returns:
            bool: True if channels match, False if not and reset
        """
        auth.debug("Checking last assertion Channel: %s with incoming: %s",
            self.get_last_assertion_cid(), cid)
        if not self.get_last_assertion_cid() is None and self._last_get_assertion_cid != bytes:
            auth.debug("Channels don't match, clearing last assertion")
            self.clear_get_last_assertion()
            return False
        auth.debug("Channels match, last assertion not cleared")
        return True

    def get_last_assertion_params(self, cid:bytes)->dict:
        """Get the set last assertion parameters associated with
        the specified channel ID.

        Args:
            cid (bytes): [description]

        Raises:
            DICEAuthenticatorException: thrown if no last assertion is set,
            the last assertion has timed out, or the channel IDs don't match

        Returns:
            dict: Dictionary consisting of the last assertion params ["params"]
                and the currently stored credential index ["idx"]
        """
        if self._last_get_assertion_time is None:
            auth.debug("No last assertions found")
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED,"No last assertions found")
        if int(time.time())-self._last_get_assertion_time >30:
            auth.debug("Last assertion has timed out")
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED,
                "Last assertion has timed out")
        if not self.check_get_last_assertion_cid(cid):
            auth.debug("Last assertion mismatched channel ID")
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED,"Mismatched channel ID")
        ret = {}
        ret["params"]=self._last_get_assertion_params
        ret["idx"]=self._last_get_assertion_idx
        auth.debug("Returning stored last assertion: %s",ret)
        return ret


    def authenticator_get_client_pin(self, params:AuthenticatorGetClientPINParameters,
        keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        """Implements the initial processing of the GetClient PIN request.

        This method itself just processes the initial message and calls the
        appropriate method for the subcommand. An authenticator needs to implement
        those subcommand abstract methods to provide the necessary funcionality.

        Args:
            params (AuthenticatorGetClientPINParameters): GetClientPIN parameters
            keep_alive (CTAPHIDKeepAlive): keep-alive object

        Raises:
            DICEAuthenticatorException: thrown if subcommand is unknown

        Returns:
            GetClientPINResp: Complete GetClientPIN response
        """
        subcmd = params.get_sub_command()
        if subcmd == AUTHN_GET_CLIENT_PIN_SUBCMD.GET_RETRIES.value:
            return self.authenticator_get_client_pin_get_retries(params,keep_alive)
        elif subcmd == AUTHN_GET_CLIENT_PIN_SUBCMD.GET_KEY_AGREEMENT.value:
            return self.authenticator_get_client_pin_get_key_agreement(params,keep_alive)
        elif subcmd == AUTHN_GET_CLIENT_PIN_SUBCMD.SET_PIN.value:
            return self.authenticator_get_client_pin_set_pin(params,keep_alive)
        elif subcmd == AUTHN_GET_CLIENT_PIN_SUBCMD.CHANGE_PIN.value:
            return self.authenticator_get_client_pin_change_pin(params,keep_alive)
        elif subcmd == AUTHN_GET_CLIENT_PIN_SUBCMD.GET_PIN_TOKEN.value:
            return self.authenticator_get_client_pin_get_pin_token(params,keep_alive)
        else:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER,"Invalid sub command")

    def _get_credential_data(self,credential_source:PublicKeyCredentialSource)->bytes:
        """Get credential data method, construct a credential data object containing
        the following:
        	                    Length (in bytes) 	Description
            aaguid 	            16 	                The AAGUID of the authenticator.
            credentialIdLength  2 	                Byte length L of Credential ID,
                                                    16-bit unsigned big-endian integer.
            credentialId 	    L 	                Credential ID
            credentialPublicKey variable 	        The credential public key encoded
                                                    in COSE_Key format, as defined in
                                                    Section 7 of [RFC8152], using the
                                                    CTAP2 canonical CBOR encoding form.
                                                    The COSE_Key-encoded credential public
                                                    key MUST contain the "alg" parameter and
                                                    MUST NOT contain any other OPTIONAL
                                                    parameters. The "alg" parameter MUST
                                                    contain a COSEAlgorithmIdentifier value.
                                                    The encoded credential public key MUST
                                                    also contain any additional REQUIRED
                                                    parameters stipulated by the relevant
                                                    key type specification, i.e., REQUIRED
                                                    for the key type "kty" and algorithm
                                                    "alg" (see Section 8 of [RFC8152]).


        Args:
            credential_source (PublicKeyCredentialSource): Credential source to use to construct
                the credential data from

        Returns:
            bytes: Correctly constructed credential data bytes
        """
        credential_data = self.get_aaguid().bytes
        credential_data += len(credential_source.get_id()).to_bytes(2,"big")
        credential_data += credential_source.get_id()
        credential_data += cbor.encode(credential_source.get_cose_public_key())
        return credential_data

    def _get_authenticator_data_minus_creds(self, credential_source:PublicKeyCredentialSource,
            up:bool, uv:bool=False,extensions:bytes=None)->bytes:
        """Gets the authenticator data without the credentials. Consists of the following

        Name 	    Length (in bytes) 	Description
        rpIdHash 	32 	                SHA-256 hash of the RP ID the credential is scoped to.
        flags 	    1 	                Flags (bit 0 is the least significant bit):
                                        Bit 0: User Present (UP) result.
                                            1 means the user is present.
                                            0 means the user is not present.
                                        Bit 1: Reserved for future use (RFU1).
                                        Bit 2: User Verified (UV) result.
                                            1 means the user is verified.
                                            0 means the user is not verified.
                                        Bits 3-5: Reserved for future use (RFU2).
                                        Bit 6: Attested credential data included (AT).
                                            Indicates whether the authenticator added attested
                                            credential data.
                                        Bit 7: Extension data included (ED).
                                            Indicates if the authenticator data has extensions.
        signCount   4 	                Signature counter, 32-bit unsigned big-endian integer.
        extensions 	variable (if present)
                                        Extension-defined authenticator data. This is a CBOR
                                        [RFC7049] map with extension identifiers as keys, and
                                        authenticator extension outputs as values. See §9
                                        WebAuthn Extensions for details.

        Args:
            credential_source (PublicKeyCredentialSource): credential source to use to
                generate data
            up (bool): User presence check, True if performed
            uv (bool, optional): User verification check, True if performed. Defaults to False.
            extensions (bytes, optional): appropriate extensions. Defaults to None.

        Returns:
            bytes: containing concatenated authenticator data
        """
        digest = hashes.Hash(hashes.SHA256(),default_backend())
        digest.update(credential_source.get_rp_entity().get_id().encode('UTF-8'))
        data = digest.finalize()
        flags = 0

        if up:
            flags = flags ^ (1 << 0)
        if uv:
            flags = flags ^ (1 << 2)

        data += flags.to_bytes(1,"big")
        #data[32] = data[32] ^ (0 << 7) set extension flag
        data += credential_source.get_signature_counter_bytes()
        return data

    def _get_authenticator_data(self, credential_source:PublicKeyCredentialSource, up:bool,
            uv:bool=False,extensions:bytes=None)->bytes:
        """Get the authenticator data including the credential data as well. Consists of


        Name 	    Length (in bytes) 	Description
        rpIdHash 	32 	                SHA-256 hash of the RP ID the credential is scoped to.
        flags       1                   Flags (bit 0 is the least significant bit):
                                        Bit 0: User Present (UP) result.
                                            1 means the user is present.
                                            0 means the user is not present.
                                        Bit 1: Reserved for future use (RFU1).
                                        Bit 2: User Verified (UV) result.
                                            1 means the user is verified.
                                            0 means the user is not verified.
                                        Bits 3-5: Reserved for future use (RFU2).
                                        Bit 6: Attested credential data included (AT).
                                            Indicates whether the authenticator added attested
                                            credential data.
                                        Bit 7: Extension data included (ED).
                                            Indicates if the authenticator data has extensions.
        signCount   4                   Signature counter, 32-bit unsigned big-endian integer.
        attestedCredentialData  variable (if present)
                                        attested credential data (if present). See §6.4.1 Attested
                                        Credential Data for details. Its length depends on the
                                        length of the credential ID and credential public key
                                        being attested.
        extensions  variable (if present)
                                        Extension-defined authenticator data. This is a CBOR
                                        [RFC7049] map with extension identifiers as keys, and
                                        authenticator extension outputs as values. See §9
                                        WebAuthn Extensions for details.

        Args:
            credential_source (PublicKeyCredentialSource): credential source to create the data from
            up (bool): True if user presence performed
            uv (bool, optional): True if User Verification performed. Defaults to False.
            extensions (bytes, optional): extensions. Defaults to None.

        Returns:
            bytes Concatenated authenticator data
        """

        digest = hashes.Hash(hashes.SHA256(),default_backend())
        digest.update(credential_source.get_rp_entity().get_id().encode('UTF-8'))
        data = digest.finalize()
        flags = 0

        if up:
            flags = flags ^ (1 << 0)
        if uv:
            flags = flags ^ (1 << 2)
        flags = flags ^ (1 << 6)
        data += flags.to_bytes(1,"big")
        #data[32] = data[32] ^ (0 << 7) set extension flag
        data += credential_source.get_signature_counter_bytes()
        data += self._get_credential_data(credential_source)
        return data

    def _get_pin_crypto_provider(self)->AuthenticatorCryptoProvider:
        """Gets the crypto provider for PIN crypto operations, this will
        be ES256 according to the standard

        Returns:
            AuthenticatorCryptoProvider: Crypto Provider to use for PIN crypto
        """
        return self._pin_crypto_provider

    def _generate_shared_secret(self,key_agreement:dict)->bytes:
        """Generate a shared secret for the PIN authorisation.

        This generates the shared secret by performing a partial ECDH

        Args:
            key_agreement (dict): key agreement dictionary containing a public key

        Returns:
            bytes: generated share secret
        """
        platform_key_agreement_key = \
            self._get_pin_crypto_provider().public_key_from_cose(key_agreement)
        return self._authenticator_key_agreement_key.get_private_key().exchange(
            platform_key_agreement_key.get_public_key())

    def _calculate_pin_auth(self, *args)->bytes:
        """Calculate the PIN authorisation and return it

        Args:
            first parameter is the HMAC key
            remaining parameters are added to the HMAC

        Returns:
            bytes: HMAC of parameters from 1 onwards
        """
        hmac_hash = hmac.HMAC(args[0], hashes.SHA256(),default_backend())
        argitr = iter(args)
        next(argitr)
        for val in argitr:
            hmac_hash.update(val)
        return hmac_hash.finalize()

    def _decrypt_value(self, shared_secret:bytes, ciphertext:bytes)->bytes:
        """Decrypts a value used AES CBC and used by the PIN
        authorisation

        Args:
            shared_secret (bytes): secret key (shared secret)
            ciphertext (bytes): cipher text to decrypt

        Returns:
            bytes: decrypted cipher text
        """
        cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(bytes(16)),default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def _encrypt_value(self, shared_secret:bytes, plaintext:bytes)->bytes:
        """Encrypt a plaintext with using AES CBC and the shared secret

        Args:
            shared_secret (bytes): secret key (shared secret)
            plaintext (bytes): plaintext to encrypt

        Returns:
            bytes: encrypted cipher text
        """
        cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(bytes(16)),default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()
    def _extract_pin(self, pin_bytes:bytes)->str:
        """Extracts the PIN from the bytes, looking for a null termination

        Args:
            pin_bytes (bytes): bytes containing the PIN

        Returns:
            str: extracted PIN as UTF8
        """
        for i in range(len(pin_bytes)):
            if pin_bytes[i]== b'\x00'[0]:
                return pin_bytes[:i].decode('utf-8')

    def _sha256(self, value)->bytes:
        """Calculates the SHA256 of the specified value, encoding
        appropriately first

        Args:
            value (str or bytes): value to hash, if string will encode to bytes

        Returns:
            bytes: hash of value
        """
        digest = hashes.Hash(hashes.SHA256(),default_backend())

        if isinstance(value,str):
            digest.update(value.encode())
        else:
            digest.update(value)
        return digest.finalize()

    def _check_pin(self, pin_auth:bytes, pin_protocol:int, client_hash:bytes,
            error_on_no_auth=True)->bool:
        """Checks whether the PIN is valid

        Args:
            pin_auth (bytes): PIN auth bytes
            pin_protocol (int): PIN protocol to use
            client_hash (bytes): client hash
            error_on_no_auth (bool, optional): if True throws an exception if PIN
                auth is missing. Defaults to True.

        Raises:
            DICEAuthenticatorException: thrown when either no PIN is set, or the verification
                fails. Will also throw if PIN Auth is missing and error_on_no_auth set to True


        Returns:
            bool: True if valid, False if not, or possibly an Exception if not
        """

        if not pin_auth is None and pin_protocol == 1:
            if self._storage.get_pin() is None:
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_INVALID,"PIN Invalid")
            #verify PIN
            if pin_auth[:16] == self._calculate_pin_auth(self._pin_token,client_hash)[:16]:
                auth.debug("PIN Verified")
                return True
            else:
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_INVALID,"PIN Invalid")
        elif not pin_auth is None and pin_protocol != 1:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_INVALID,"Unsupport PIN Protocol")
        elif not self._storage.get_pin() is None and (not pin_auth is None or pin_protocol != 1):
            if error_on_no_auth:
                raise DICEAuthenticatorException(
                    ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_REQUIRED,"PIN Required")
            return False
        elif pin_auth is None and pin_protocol ==-1:
            return False

    #==============================================================================================
    #               ABSTRACT METHODS TO IMPLEMENT
    #
    #==============================================================================================
    @abstractmethod
    def process_wink(self, payload:bytes, keep_alive: CTAPHIDKeepAlive)->bytes:
        """Process the wink request which basically requires flashing or
        some visual indicator of the target authenticator

        Args:
            payload (bytes): payload bytes
            keep_alive (CTAPHIDKeepAlive): keep-alive object

        Returns:
            bytes: CBOR encoded response to be wrapped and sent back to the client
        """
    @abstractmethod
    def authenticator_get_info(self, keep_alive:CTAPHIDKeepAlive) -> GetInfoResp:
        """Abstract method to process the GetInfo request. Should return
        a completed GetInfoResp

        Args:
            keep_alive (CTAPHIDKeepAlive): keep-alive object

        Returns:
            GetInfoResp: Complete GetInfo Response
        """

    @abstractmethod
    def authenticator_make_credential(self, params:AuthenticatorMakeCredentialParameters,
        keep_alive:CTAPHIDKeepAlive) -> MakeCredentialResp:
        """Abstract method to process the MakeCredential request. Should
        return a completed MakeCredentialResp

        Args:
            params (AuthenticatorMakeCredentialParameters): Make credential parameters
            keep_alive (CTAPHIDKeepAlive): keep-alive object

        Returns:
            MakeCredentialResp: Complete MakeCredential response
        """

    @abstractmethod
    def authenticator_get_assertion(self, params:AuthenticatorGetAssertionParameters,
        keep_alive:CTAPHIDKeepAlive) -> GetAssertionResp:
        """Abstract method to process the GetAssertion request. Should return
        a completed GetAssertionResp

        Args:
            params (AuthenticatorGetAssertionParameters): GetAssertion parameters
            keep_alive (CTAPHIDKeepAlive): keep-alive object

        Returns:
            GetAssertionResp: Complete GetAssertion response
        """
    @abstractmethod
    def authenticator_get_client_pin_get_retries(self,
        params:AuthenticatorGetClientPINParameters,keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        """Abstract method to get the number of retries remaining for the ClientPIN

        Args:
            params (AuthenticatorGetClientPINParameters): Client PIN parameters
            keep_alive (CTAPHIDKeepAlive): keep-alive object

        Returns:
            GetClientPINResp: completed Client PIN response
        """

    @abstractmethod
    def authenticator_get_client_pin_get_key_agreement(self,
            params:AuthenticatorGetClientPINParameters,
            keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        """Abstract method to process the request for the PIN key agreement

        Args:
            params (AuthenticatorGetClientPINParameters): Get Client PIN parameters
            keep_alive (CTAPHIDKeepAlive): keep-alive object

        Returns:
            GetClientPINResp: Completed Get Client PIN Response
        """

    @abstractmethod
    def authenticator_get_client_pin_set_pin(self,params:AuthenticatorGetClientPINParameters,
            keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        """Abstract method to process the PIN set request

        Args:
            params (AuthenticatorGetClientPINParameters): Client PIN parameters including new PIN
            keep_alive (CTAPHIDKeepAlive): keep-alive object

        Returns:
            GetClientPINResp: Completed Get Client PIN Response
        """

    @abstractmethod
    def authenticator_get_client_pin_change_pin(self,params:AuthenticatorGetClientPINParameters,
            keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        """Abstract method to process a PIN change request

        Args:
            params (AuthenticatorGetClientPINParameters): Client PIN parameters include new PIN
            keep_alive (CTAPHIDKeepAlive): keep-alive object

        Returns:
            GetClientPINResp: Completed Get Client PIN response
        """

    @abstractmethod
    def authenticator_get_client_pin_get_pin_token(self,params:AuthenticatorGetClientPINParameters,
            keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        """Abstact method to process the request for the PIN Token

        Args:
            params (AuthenticatorGetClientPINParameters): Client PIN parameters
            keep_alive (CTAPHIDKeepAlive): keep-alive object

        Returns:
            GetClientPINResp: Completed Get Client PIN response including PIN Token
        """

    @abstractmethod
    def authenticator_get_next_assertion(self, params:AuthenticatorGetAssertionParameters, idx:int,
            keep_alive:CTAPHIDKeepAlive) -> GetNextAssertionResp:
        """Abstract method to process GetNextAssertion request

        Args:
            params (AuthenticatorGetAssertionParameters): GetAssertion parameters
            idx (int): credential index
            keep_alive (CTAPHIDKeepAlive): keep-alive object

        Returns:
            GetNextAssertionResp: Completed Get Next Assertion response
        """

    @abstractmethod
    def authenticator_reset(self, keep_alive:CTAPHIDKeepAlive) -> ResetResp:
        """Abstract method to process a reset request

        Args:
            keep_alive (CTAPHIDKeepAlive): keep-alive object

        Returns:
            ResetResp: Completed reset response
        """

    @abstractmethod
    def get_version(self)->AuthenticatorVersion:
        """Get the authenticator version object

        Returns:
            AuthenticatorVersion: version information
        """