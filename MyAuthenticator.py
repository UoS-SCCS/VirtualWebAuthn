from DICEAuthenticator import DICEAuthenticator
from DICEAuthenticator import GetInfoResp
from DICEAuthenticator import ResetResp
from DICEAuthenticator import AUTHN_GETINFO_OPTION
from DICEAuthenticator import AUTHN_GETINFO_TRANSPORT
from DICEAuthenticator import PUBLIC_KEY_ALG
from DICEAuthenticator import PublicKeyCredentialParameters
from DICEAuthenticator import AUTHN_GETINFO_VERSION
from DICEAuthenticator import AuthenticatorMakeCredentialParameters
from DICEAuthenticator import AuthenticatorGetAssertionParameters
from DICEAuthenticator import AuthenticatorGetClientPINParameters
from DICEAuthenticator import GetClientPINResp
from DICEAuthenticator import MakeCredentialResp
from DICEAuthenticator import GetAssertionResp
from DICEAuthenticator import DICEAuthenticatorException
import CTAPHIDConstants
from binascii import b2a_hex

from DICEAuthenticatorStorage import DICEAuthenticatorStorage
from AuthenticatorCryptoProvider import AuthenticatorCryptoProvider
from PublicKeyCredentialSource import PublicKeyCredentialSource
from AuthenticatorCryptoProvider import CRYPTO_PROVIDERS
from CTAPHIDKeepAlive import CTAPHIDKeepAlive
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from AttestationObject import AttestationObject
import logging
from binascii import hexlify, a2b_hex, b2a_hex
from uuid import UUID
from fido2.cose import CoseKey, ES256, RS256, UnsupportedKey
from fido2 import cbor
#for x509 cert
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import os
from cryptography.hazmat.primitives import serialization
from CredentialWrapper import CredentialWrapper
from DICEAuthenticatorUI import DICEAuthenticatorListener
from AuthenticatorVersion import AuthenticatorVersion
log = logging.getLogger('debug')
ctap = logging.getLogger('debug.ctap')
auth = logging.getLogger('debug.auth')
class MyAuthenticator(DICEAuthenticator,DICEAuthenticatorListener):
    VERSION = AuthenticatorVersion(2,1,0,0)
    MY_AUTHENTICATOR_AAGUID = UUID("c9181f2f-eb16-452a-afb5-847e621b92aa")
    
    def __init__(self, storage:DICEAuthenticatorStorage, crypto_providers:[int], credential_wrapper:CredentialWrapper):
        #allow list of crypto providers, may be a subset of all available providers
        super().__init__()
        self._storage = storage
        self._providers = crypto_providers
        self._credential_wrapper = credential_wrapper
        #self._providers_idx = {}
        #for provider in crypto_providers:
        #    self._providers_idx[provider.get_alg()] = provider
        self.get_info_resp = GetInfoResp()
        self.get_info_resp.set_auguid(MyAuthenticator.MY_AUTHENTICATOR_AAGUID)
        if not self._storage.get_pin() is None:
            self.get_info_resp.set_option(AUTHN_GETINFO_OPTION.CLIENT_PIN,True)
        else:
            self.get_info_resp.set_option(AUTHN_GETINFO_OPTION.CLIENT_PIN,False)
        self.get_info_resp.set_option(AUTHN_GETINFO_OPTION.RESIDENT_KEY,True)
        self.get_info_resp.set_option(AUTHN_GETINFO_OPTION.USER_PRESENCE,True)
        #self.get_info_resp.set_option(AUTHN_GETINFO_OPTION.CONFIG,True)
        self.get_info_resp.add_version(AUTHN_GETINFO_VERSION.CTAP2)
        #self.get_info_resp.add_version(AUTHN_GETINFO_VERSION.CTAP1)
        self.get_info_resp.add_transport(AUTHN_GETINFO_TRANSPORT.USB)
        self.get_info_resp.add_algorithm(PublicKeyCredentialParameters(PUBLIC_KEY_ALG.ES256))
        #self.get_info_resp.add_algorithm(PublicKeyCredentialParameters(PUBLIC_KEY_ALG.RS256))
        #Generate PIN Key Agreement at Startup
        if not self._storage.has_wrapping_key():
            self._storage.set_wrapping_key(self._credential_wrapper.generate_key())


    
    def quit(self):
        print("Quit called")

    def get_AAGUID(self):
        return MyAuthenticator.MY_AUTHENTICATOR_AAGUID

    def get_version(self)->AuthenticatorVersion:
        return MyAuthenticator.VERSION

    def authenticatorGetInfo(self, keep_alive:CTAPHIDKeepAlive) -> GetInfoResp:
        auth.debug("GetInfo called: %s", self.get_info_resp)
        return self.get_info_resp

    def authenticatorMakeCredential(self, params:AuthenticatorMakeCredentialParameters, keep_alive:CTAPHIDKeepAlive, as_rk = True) -> MakeCredentialResp:
        #TODO perform necessary checks
        #TODO add non-residential key approach
        #keep_alive.start()
        auth.debug("Make Credential called, is resident: %s, with params: %s", as_rk, params)
        provider = None
        for cred_type in params.get_cred_types_and_pubkey_algs():
            if cred_type["alg"] in self._providers:
                provider=CRYPTO_PROVIDERS[cred_type["alg"]]
                #provider = self._providers_idx[cred_type["alg"]]
                auth.debug("Found matching public key algorithm: %s", PUBLIC_KEY_ALG(provider.get_alg()).name)
                break

        if provider is None:
            auth.error("No matching public key provider found")
            raise Exception("No matching provider found")
        
        uv = self._check_pin(params.get_pin_auth(),params.get_pin_protocol(),params.get_hash())

        credential_source=PublicKeyCredentialSource()
        keypair = provider.create_new_key_pair()
        #TODO need to store entire user handle
        credential_source.init_new(provider.get_alg(),keypair,params.get_rp_entity()['id'],params.get_user_entity()['id'])

        if as_rk:
            self._storage.add_credential_source(params.get_rp_entity()['id'],params.get_user_entity()['id'],credential_source)
        else:
            auth.debug("Non-resident key, wrapping credential source")
            credential_source.set_id(self._credential_wrapper.wrap(self._storage.get_wrapping_key(),credential_source))


        authenticator_data = self._get_authenticator_data(credential_source,True,uv)
        
        attestObject = AttestationObject.create_packed_self_attestation_object(credential_source,authenticator_data,params.get_hash())
        auth.debug("Created attestation object: %s", attestObject)
        return MakeCredentialResp(attestObject)
        
    
    def authenticatorGetAssertion(self, params:AuthenticatorGetAssertionParameters,keep_alive:CTAPHIDKeepAlive) -> GetAssertionResp:
        #TODO perform necessary checks
        #TODO add non-residential key approach

        #First find all resident creds (could be zero)
        creds = self._storage.get_credential_source_by_rp(params.get_rp_id(),params.get_allow_list())
        
        #Now check for any non-resident creds
        for allow_cred in params.get_allow_list():
            if len(allow_cred["id"])>16:
                auth.debug("Wrapped key provided, will unwrap credential source")
                #we have a wrapped credential
                creds.append(self._credential_wrapper.unwrap(self._storage.get_wrapping_key(),allow_cred["id"]))
            
                
        numberOfCredentials = len(creds)
        #TODO Implement Pin Options
        #TODO Implement User verification and presence check
        if numberOfCredentials < 1:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS)

        credential_source = creds[0]
        uv = self._check_pin(params.get_pin_auth(),params.get_pin_protocol(),params.get_hash(),False)
        authenticator_data = self._get_authenticator_data_minus_creds(credential_source,True,uv)
        
        response = {}
        
        
        response[2]=authenticator_data
        response[3]=credential_source.get_private_key().sign(authenticator_data + params.get_hash())
        credential_source.increment_signature_counter()
        response[4]=credential_source.get_user_handle()
        response[5]=numberOfCredentials
        #We put this last so the returned value can be updated - not sure this actually has any impact
        response[1]=credential_source.get_public_key_credential_descriptor()
        """
        credential 	0x01 	definite length map (CBOR major type 5).
        authData 	0x02 	byte string (CBOR major type 2).
        signature 	0x03 	byte string (CBOR major type 2).
        publicKeyCredentialUserEntity 	0x04 	definite length map (CBOR major type 5).
        numberOfCredentials 	0x05 	unsigned integer(CBOR major type 0). 
        """
        
        return GetAssertionResp(response,numberOfCredentials)
    
    def authenticatorGetNextAssertion(self, params:AuthenticatorGetAssertionParameters,idx:int, keep_alive:CTAPHIDKeepAlive) -> GetAssertionResp:
        #TODO perform necessary checks
        #TODO add non-residential key approach
        creds = self._storage.get_credential_source_by_rp(params.get_rp_id(),params.get_allow_list())
         #Now check for any non-resident creds
        for allow_cred in params.get_allow_list():
            if len(allow_cred["id"])>16:
                auth.debug("Wrapped key provided, will unwrap credential source")
                #we have a wrapped credential
                creds.append(self._credential_wrapper.unwrap(self._storage.get_wrapping_key(),allow_cred["id"]))
            
        numberOfCredentials = len(creds)
        if numberOfCredentials < 1:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS)
        if idx >= numberOfCredentials:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED)
        
        credential_source = creds[idx]
        authenticator_data = self._get_authenticator_data_minus_creds(credential_source,True)
        
        response = {}
        
        
        response[2]=authenticator_data
        response[3]=credential_source.get_private_key().sign(authenticator_data + params.get_hash())
        credential_source.increment_signature_counter()
        response[4]=credential_source.get_user_handle()
        response[5]=numberOfCredentials
        #We put this last so the returned value can be updated - not sure this actually has any impact
        response[1]=credential_source.get_public_key_credential_descriptor()
        """
        credential 	0x01 	definite length map (CBOR major type 5).
        authData 	0x02 	byte string (CBOR major type 2).
        signature 	0x03 	byte string (CBOR major type 2).
        publicKeyCredentialUserEntity 	0x04 	definite length map (CBOR major type 5).
        numberOfCredentials 	0x05 	unsigned integer(CBOR major type 0). 
        """
        
        return GetAssertionResp(response,numberOfCredentials)

    def authenticatorReset(self, keep_alive:CTAPHIDKeepAlive) -> ResetResp:
        if self._storage.reset():
            return ResetResp()
        else:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP1_ERR_OTHER)
    
    def authenticatorGetClientPIN_getRetries(self, params:AuthenticatorGetClientPINParameters,keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        return GetClientPINResp(retries=self._storage.get_pin_retries())
    
    def authenticatorGetClientPIN_getKeyAgreement(self, params:AuthenticatorGetClientPINParameters,keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        return GetClientPINResp(key_agreement=self._authenticatorKeyAgreementKey.get_public_key().get_as_cose())
    
    def authenticatorGetClientPIN_setPIN(self, params:AuthenticatorGetClientPINParameters,keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        #TODO verify contents of params
        if not self._storage.get_pin() is None:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_AUTH_INVALID,"PIN has already been set")
        
        #TODO generalise and remove hard coding to cose parameters
        shared_secret = self._generate_shared_secret(params.get_key_agreement())
        check = self._calculate_pin_auth(shared_secret,params.get_new_pin_enc())
        if not check[0:16] == params.get_pin_auth()[0:16]:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_AUTH_INVALID,"Auth PIN did not match")
        
        decrypted_pin = self._decrypt_value(shared_secret,params.get_new_pin_enc())
        pin = self._extract_pin(decrypted_pin)
        
        if len(pin)<4:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_POLICY_VIOLATION, "PIN too short")
        self._storage.set_pin(self._sha256(pin)[:16])
        return GetClientPINResp()
    
    def authenticatorGetClientPIN_changePIN(self, params:AuthenticatorGetClientPINParameters,keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        if self._storage.get_pin() is None:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_AUTH_INVALID,"No PIN Set")
        
        #TODO generalise and remove hard coding to cose parameters
        shared_secret = self._generate_shared_secret(params.get_key_agreement())
        check = self._calculate_pin_auth(shared_secret,params.get_new_pin_enc(),params.get_pin_hash_enc())
        if not check[0:16] == params.get_pin_auth()[0:16]:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_AUTH_INVALID,"Auth PIN did not match")
    
        self._storage.decrement_pin_retries()
        decrypted_pin_hash = self._decrypt_value(shared_secret,params.get_pin_hash_enc())
        stored_pin = self._storage.get_pin()

        if not stored_pin[:16] == decrypted_pin_hash[:16]:
            #TODO handle run out of tries and successive lock
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_INVALID, "PIN invalid")

        decrypted_pin = self._decrypt_value(shared_secret,params.get_new_pin_enc())
        pin = self._extract_pin(decrypted_pin)
        
        if len(pin)<4:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_POLICY_VIOLATION, "PIN too short")
        
        self._storage.set_pin(self._sha256(pin)[:16])
        self._storage.set_pin_retries(8)
        return GetClientPINResp()
    
    def authenticatorGetClientPIN_getPINToken(self, params:AuthenticatorGetClientPINParameters,keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        if self._storage.get_pin() is None:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_AUTH_INVALID,"No PIN Set")
        
        #TODO generalise and remove hard coding to cose parameters
        shared_secret = self._generate_shared_secret(params.get_key_agreement())
        
        self._storage.decrement_pin_retries()
        decrypted_pin_hash = self._decrypt_value(shared_secret,params.get_pin_hash_enc())
        stored_pin = self._storage.get_pin()

        if not stored_pin[:16] == decrypted_pin_hash[:16]:
            #TODO handle run out of tries and successive lock
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_INVALID, "PIN invalid")

        self._storage.set_pin_retries(8)
        
        return GetClientPINResp(pin_token=self._encrypt_value(shared_secret,self._pin_token))

    def process_wink(self, payload:bytes, keep_alive: CTAPHIDKeepAlive)->bytes:
        auth.debug("Process wink")
        return bytes(0)