from abc import ABC, abstractmethod
import json
import os
import time

import shutil
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from enum import Enum, unique
from uuid import UUID
from fido2 import cbor

from hid.ctap import CTAPHIDTransaction, HIDPacket, CTAPHID
from hid.usb import USBHID
from hid.listeners import USBHIDListener
import ctap.constants
from ctap.constants import (AUTHN_GET_CLIENT_PIN,AUTHN_GET_ASSERTION, AUTHN_MAKE_CREDENTIAL,
    AUTHN_GETINFO,AUTHN_GETINFO_OPTION,AUTHN_GETINFO_PARAMETER,AUTHN_GETINFO_PIN_UV_PROTOCOL,
    AUTHN_GETINFO_TRANSPORT,AUTHN_CMD,AUTHN_GETINFO_VERSION,AUTHN_GET_CLIENT_PIN_SUBCMD,
    AUTHN_GET_CLIENT_PIN_RESP,AUTHN_PUBLIC_KEY_CREDENTIAL_DESCRIPTOR,
    AUTHN_PUBLIC_KEY_CREDENTIAL_USER_ENTITY,AUTHN_PUBLIC_KEY_CREDENTIAL_RP_ENTITY)
from authenticator.datatypes import (AuthenticatorVersion, AuthenticatorGetAssertionParameters,
    AuthenticatorMakeCredentialParameters,AuthenticatorGetClientPINParameters, DICEAuthenticatorException)
from ctap.keep_alive import CTAPHIDKeepAlive
from crypto.crypto_provider import AuthenticatorCryptoProvider,CRYPTO_PROVIDERS
from crypto.es256_crypto_provider import ES256CryptoProvider

from authenticator.ui import DICEAuthenticatorListener, DICEAuthenticatorUI, ConsoleAuthenticatorUI

from ctap.credential_source import PublicKeyCredentialSource

from authenticator.cbor import GetInfoResp, MakeCredentialResp,GetAssertionResp,GetClientPINResp,ResetResp,GetNextAssertionResp


log = logging.getLogger('debug')
auth = logging.getLogger('debug.auth')





    





class DICEAuthenticator(DICEAuthenticatorListener):
    AUTHENTICATOR_AAGUID = UUID("695e437f-c0cd-4fe8-b545-d39084f5c805")
    PIN_TOKEN_LENGTH = 64
    def __init__(self, pin_token_length=PIN_TOKEN_LENGTH, ui:DICEAuthenticatorUI=ConsoleAuthenticatorUI()):
        self._create_debug_logs()
        self._last_get_assertion_cid = None
        self._last_get_assertion_params =  None
        self._last_get_assertion_time = None
        self._last_get_assertion_idx = None
        self._storage = None
        self._pin_crypto_provider= ES256CryptoProvider()
        #self._ctap_hid = ctap_hid
        self._generate_authenticatorKeyAgreementKey()
        self._generate_pinToken(pin_token_length)
        self._ui = ui
        if not self._ui is None:
            self._ui.add_listener(self)
        
    def shutdown(self):
        self._usbhid.shutdown()

    def _start(self,device:str="/dev/dicekey"):
        self._usbdevice = os.open(device, os.O_RDWR)
        self._usbhid = USBHID(self._usbdevice)
        #import CTAPHID
        self._ctaphid = CTAPHID(self._usbhid)
        self._ctaphid.set_authenticator(self)
        self._usbhid.set_listener(self._ctaphid)
        self._usbhid.start()
        if not self._ui is None:
            self._ui.start()



    def _create_debug_logs(self):
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
    
    def _setup_logger(self, logger_name, log_file, level=logging.DEBUG):
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

    def _generate_pinToken(self,pin_token_length:int):
        auth.debug("Generating new pinToken")
        self._pin_token = os.urandom(pin_token_length)
    def _generate_authenticatorKeyAgreementKey(self):
        auth.debug("Generating new authenticatorKeyAgreementKey")
        self._authenticatorKeyAgreementKey = self._get_pin_crypto_provider().create_new_key_pair()

    def get_AAGUID(self):
        return DICEAuthenticator.AUTHENTICATOR_AAGUID

    def process_cbor(self, cbor_data:bytes, keep_alive: CTAPHIDKeepAlive, CID:bytes=None):
        if not bytes is None:
            self.check_get_last_assertion_cid(CID)

        cmd = cbor_data[:1]
        auth.debug("Received %s CBOR: %s", AUTHN_CMD(cmd).name, cbor_data.hex())
        if cmd == AUTHN_CMD.AUTHN_MakeCredential.value:
            params = AuthenticatorMakeCredentialParameters(cbor_data[1:])
            return self.authenticatorMakeCredential(params, keep_alive).get_encoded()
        elif cmd == AUTHN_CMD.AUTHN_GetAssertion.value:
            params = AuthenticatorGetAssertionParameters(cbor_data[1:])
            get_assertion_resp = self.authenticatorGetAssertion(params, keep_alive)
            if get_assertion_resp.get_count() > 1:
                self.set_get_assertion_params_start_timer(CID,params,1)
            else:
                self.clear_get_last_assertion()
            return get_assertion_resp.get_encoded()
        elif cmd == AUTHN_CMD.AUTHN_GetInfo.value:
            return self.authenticatorGetInfo(keep_alive).get_encoded()
        elif cmd == AUTHN_CMD.AUTHN_ClientPIN.value:
            params = AuthenticatorGetClientPINParameters(cbor_data[1:])
            return self.authenticatorGetClientPIN(params, keep_alive).get_encoded()
        elif cmd == AUTHN_CMD.AUTHN_Reset.value:
            return self.authenticatorReset(keep_alive).get_encoded()
        elif cmd == AUTHN_CMD.AUTHN_GetNextAssertion.value:
            last = self.get_last_assertion_params(CID)
            get_next_resp = self.authenticatorGetNextAssertion(last["params"], last["idx"], keep_alive)
            self.set_get_assertion_params_idx_reset_timer(last["idx"]+1)
            return get_next_resp.get_encoded()
        elif cmd == AUTHN_CMD.AUTHN_BioEnrollment.value:
            pass
        elif cmd == AUTHN_CMD.AUTHN_CredentialManagement.value:
            pass
        elif cmd == AUTHN_CMD.AUTHN_PlatformConfig.value:
            pass
        elif cmd == AUTHN_CMD.AUTHN_CredentialManagement.value:
            pass
        elif cmd == AUTHN_CMD.AUTHN_VendorFirst.value:
            pass
        elif cmd == AUTHN_CMD.AUTHN_VendorLast.value:
            pass

    @abstractmethod
    def process_wink(self, payload:bytes, keep_alive: CTAPHIDKeepAlive)->bytes:
        pass

    def set_get_assertion_params_start_timer(self, CID:bytes,params:AuthenticatorGetAssertionParameters, idx:int):
        auth.debug("Setting getAssertion %s for Channel: %s with Index: %s", params, CID, idx)
        self._last_get_assertion_cid = CID
        self._last_get_assertion_params =  params
        self._last_get_assertion_time = int(time.time())
        self._last_get_assertion_idx = idx
    
    def set_get_assertion_params_idx_reset_timer(self, idx:int):
        auth.debug("Incrementing getAssertion Index: %s", idx)
        self._last_get_assertion_idx = idx
        self._last_get_assertion_time = int(time.time())

    def clear_get_last_assertion(self):
        auth.debug("Clearing get assertion")
        self._last_get_assertion_cid = None
        self._last_get_assertion_params =  None
        self._last_get_assertion_time = None
        self._last_get_assertion_idx = None
    
    def get_last_assertion_cid(self):
        return self._last_get_assertion_cid

    def check_get_last_assertion_cid(self, CID:bytes)->bool:
        auth.debug("Checking last assertion Channel: %s with incoming: %s", self.get_last_assertion_cid(), CID)
        if not self.get_last_assertion_cid() is None and self._last_get_assertion_cid != bytes:
            auth.debug("Channels don't match, clearing last assertion")
            self.clear_get_last_assertion()
            return False
        auth.debug("Channels match, last assertion not cleared")
        return True
    
    def get_last_assertion_params(self, CID:bytes):
        if self._last_get_assertion_time is None:
            auth.debug("No last assertions found")
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED,"No last assertions found")
        if int(time.time())-self._last_get_assertion_time >30:
            auth.debug("Last assertion has timed out")
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED,"Last assertion has timed out")
        if not self.check_get_last_assertion_cid(CID):
            auth.debug("Last assertion mismatched channel ID")
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED,"Mismatched channel ID")
        ret = {}
        ret["params"]=self._last_get_assertion_params
        ret["idx"]=self._last_get_assertion_idx
        auth.debug("Returning stored last assertion: %s",ret)
        return ret

    @abstractmethod
    def authenticatorGetInfo(self, keep_alive:CTAPHIDKeepAlive) -> GetInfoResp:
        pass

    @abstractmethod
    def authenticatorMakeCredential(self, params:AuthenticatorMakeCredentialParameters,keep_alive:CTAPHIDKeepAlive) -> MakeCredentialResp:
        pass

    @abstractmethod
    def authenticatorGetAssertion(self, params:AuthenticatorGetAssertionParameters,keep_alive:CTAPHIDKeepAlive) -> GetAssertionResp:
        pass

    def authenticatorGetClientPIN(self, params:AuthenticatorGetClientPINParameters,keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        subcmd = params.get_sub_command()
        if subcmd == AUTHN_GET_CLIENT_PIN_SUBCMD.GET_RETRIES.value:
            return self.authenticatorGetClientPIN_getRetries(params,keep_alive)
        elif subcmd == AUTHN_GET_CLIENT_PIN_SUBCMD.GET_KEY_AGREEMENT.value:
            return self.authenticatorGetClientPIN_getKeyAgreement(params,keep_alive)
        elif subcmd == AUTHN_GET_CLIENT_PIN_SUBCMD.SET_PIN.value:
            return self.authenticatorGetClientPIN_setPIN(params,keep_alive)
        elif subcmd == AUTHN_GET_CLIENT_PIN_SUBCMD.CHANGE_PIN.value:
            return self.authenticatorGetClientPIN_changePIN(params,keep_alive)
        elif subcmd == AUTHN_GET_CLIENT_PIN_SUBCMD.GET_PIN_TOKEN.value:
            return self.authenticatorGetClientPIN_getPINToken(params,keep_alive)
        else:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP1_ERR_INVALID_PARAMETER,"Invalid sub command")

    @abstractmethod
    def authenticatorGetClientPIN_getRetries(self, params:AuthenticatorGetClientPINParameters,keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        pass

    @abstractmethod
    def authenticatorGetClientPIN_getKeyAgreement(self, params:AuthenticatorGetClientPINParameters,keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        pass

    @abstractmethod
    def authenticatorGetClientPIN_setPIN(self, params:AuthenticatorGetClientPINParameters,keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        pass
    @abstractmethod
    def authenticatorGetClientPIN_changePIN(self, params:AuthenticatorGetClientPINParameters,keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        pass
    
    @abstractmethod
    def authenticatorGetClientPIN_getPINToken(self, params:AuthenticatorGetClientPINParameters,keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        pass

    @abstractmethod
    def authenticatorGetNextAssertion(self, params:AuthenticatorGetAssertionParameters, idx:int, keep_alive:CTAPHIDKeepAlive) -> GetNextAssertionResp:
        pass

    @abstractmethod
    def authenticatorReset(self, keep_alive:CTAPHIDKeepAlive) -> ResetResp:
        pass 
 
    @abstractmethod
    def get_version(self)->AuthenticatorVersion:
        pass
    def _get_credential_data(self,credential_source:PublicKeyCredentialSource):
        """	                    Length (in bytes) 	Description
            aaguid 	            16 	                The AAGUID of the authenticator.
            credentialIdLength 	2 	                Byte length L of Credential ID, 16-bit unsigned big-endian integer.
            credentialId 	    L 	                Credential ID
            credentialPublicKey variable 	        The credential public key encoded in COSE_Key format, as defined in Section 7 of [RFC8152], using the CTAP2 canonical CBOR encoding form. The COSE_Key-encoded credential public key MUST contain the "alg" parameter and MUST NOT contain any other OPTIONAL parameters. The "alg" parameter MUST contain a COSEAlgorithmIdentifier value. The encoded credential public key MUST also contain any additional REQUIRED parameters stipulated by the relevant key type specification, i.e., REQUIRED for the key type "kty" and algorithm "alg" (see Section 8 of [RFC8152]). 
        """
        credential_data = self.get_AAGUID().bytes
        credential_data += len(credential_source.get_id()).to_bytes(2,"big")
        credential_data += credential_source.get_id()
        credential_data += cbor.encode(credential_source.get_cose_public_key())
        return credential_data
    
    def _get_authenticator_data_minus_creds(self, credential_source:PublicKeyCredentialSource, up:bool, uv:bool=False,extensions:bytes=None):
        """
        Name 	Length (in bytes) 	Description
        rpIdHash 	32 	SHA-256 hash of the RP ID the credential is scoped to.
        flags 	1 	Flags (bit 0 is the least significant bit):
                        Bit 0: User Present (UP) result.
                            1 means the user is present.
                            0 means the user is not present.
                        Bit 1: Reserved for future use (RFU1).
                        Bit 2: User Verified (UV) result.
                            1 means the user is verified.
                            0 means the user is not verified.
                        Bits 3-5: Reserved for future use (RFU2).
                        Bit 6: Attested credential data included (AT).
                            Indicates whether the authenticator added attested credential data.
                        Bit 7: Extension data included (ED).
                            Indicates if the authenticator data has extensions.
        signCount 	4 	Signature counter, 32-bit unsigned big-endian integer.
        extensions 	variable (if present) 	Extension-defined authenticator data. This is a CBOR [RFC7049] map with extension identifiers as keys, and authenticator extension outputs as values. See §9 WebAuthn Extensions for details. 
        """
        digest = hashes.Hash(hashes.SHA256(),default_backend())
        digest.update(credential_source.get_rp_id().encode('UTF-8'))
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

    def _get_authenticator_data(self, credential_source:PublicKeyCredentialSource, up:bool, uv:bool=False,extensions:bytes=None):
        """
        Name 	Length (in bytes) 	Description
        rpIdHash 	32 	SHA-256 hash of the RP ID the credential is scoped to.
        flags 	1 	Flags (bit 0 is the least significant bit):
                        Bit 0: User Present (UP) result.
                            1 means the user is present.
                            0 means the user is not present.
                        Bit 1: Reserved for future use (RFU1).
                        Bit 2: User Verified (UV) result.
                            1 means the user is verified.
                            0 means the user is not verified.
                        Bits 3-5: Reserved for future use (RFU2).
                        Bit 6: Attested credential data included (AT).
                            Indicates whether the authenticator added attested credential data.
                        Bit 7: Extension data included (ED).
                            Indicates if the authenticator data has extensions.
        signCount 	4 	Signature counter, 32-bit unsigned big-endian integer.
        attestedCredentialData 	variable (if present) 	attested credential data (if present). See §6.4.1 Attested Credential Data for details. Its length depends on the length of the credential ID and credential public key being attested.
        extensions 	variable (if present) 	Extension-defined authenticator data. This is a CBOR [RFC7049] map with extension identifiers as keys, and authenticator extension outputs as values. See §9 WebAuthn Extensions for details. 
        """
        digest = hashes.Hash(hashes.SHA256(),default_backend())
        digest.update(credential_source.get_rp_id().encode('UTF-8'))
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
        return self._pin_crypto_provider
    
    def _generate_shared_secret(self,key_agreement:{})->bytes:
        platformKeyAgreementKey = self._get_pin_crypto_provider().public_key_from_cose(key_agreement)
        return self._authenticatorKeyAgreementKey.get_private_key().exchange(platformKeyAgreementKey.get_public_key())
    
    def _calculate_pin_auth(self, *args)->bytes:
        h = hmac.HMAC(args[0], hashes.SHA256(),default_backend())
        argitr = iter(args)
        next(argitr)
        for val in argitr:
            h.update(val)
        return h.finalize()
    
    def _decrypt_value(self, shared_secret, ciphertext)->bytes:
        cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(bytes(16)),default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext)
    
    def _encrypt_value(self, shared_secret, plaintext)->bytes:
        cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(bytes(16)),default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()
    def _extract_pin(self, pin_bytes:bytes)->str:
        for i in range(len(pin_bytes)):
            if pin_bytes[i]== b'\x00'[0]:
                return pin_bytes[:i].decode('utf-8')
    
    def _sha256(self, value)->bytes:   
        digest = hashes.Hash(hashes.SHA256(),default_backend())
        
        if type(value) is str:
            digest.update(value.encode())
        else:
            digest.update(value)
        return digest.finalize()

    def _check_pin(self, pin_auth:bytes, pin_protocol:int, client_hash:bytes, error_on_no_auth=True)->bool:
        
        if not pin_auth is None and pin_protocol == 1:
            if self._storage.get_pin() is None:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_INVALID,"PIN Invalid")
            #verify PIN
            if pin_auth[:16] == self._calculate_pin_auth(self._pin_token,client_hash)[:16]:
                auth.debug("PIN Verified")
                return True
            else:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_INVALID,"PIN Invalid")
        elif not pin_auth is None and pin_protocol != 1:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_INVALID,"Unsupport PIN Protocol")
        elif not self._storage.get_pin() is None and (not pin_auth is None or pin_protocol != 1):
            if error_on_no_auth:
                raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_REQUIRED,"PIN Required")
            else:
                return False
        elif pin_auth is None and pin_protocol ==-1:
            return False

   