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

from DICEAuthenticator import MakeCredentialResp
from DICEAuthenticator import GetAssertionResp
from DICEAuthenticator import DICEAuthenticatorException
import CTAPHIDConstants

from DICEAuthenticatorStorage import DICEAuthenticatorStorage
from AuthenticatorCryptoProvider import AuthenticatorCryptoProvider
from PublicKeyCredentialSource import PublicKeyCredentialSource
from AuthenticatorCryptoProvider import CRYPTO_PROVIDERS
from CTAPHIDKeepAlive import CTAPHIDKeepAlive
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
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
from cryptography.hazmat.primitives import serialization

log = logging.getLogger('debug')
auth = logging.getLogger('auth')
class MyAuthenticator(DICEAuthenticator):
    MY_AUTHENTICATOR_AAGUID = UUID("c9181f2f-eb16-452a-afb5-847e621b92aa")
    def __init__(self, storage:DICEAuthenticatorStorage, crypto_providers:[int]):
        #allow list of crypto providers, may be a subset of all available providers
        super().__init__()
        self._storage = storage
        self._providers = crypto_providers
        #self._providers_idx = {}
        #for provider in crypto_providers:
        #    self._providers_idx[provider.get_alg()] = provider
        self.get_info_resp = GetInfoResp()
        self.get_info_resp.set_auguid(MyAuthenticator.MY_AUTHENTICATOR_AAGUID)
        #self.get_info_resp.set_option(AUTHN_GETINFO_OPTION.CLIENT_PIN,True)
        #self.get_info_resp.set_option(AUTHN_GETINFO_OPTION.RESIDENT_KEY,True)
        #self.get_info_resp.set_option(AUTHN_GETINFO_OPTION.USER_PRESENCE,True)
        #self.get_info_resp.set_option(AUTHN_GETINFO_OPTION.CONFIG,True)
        self.get_info_resp.add_version(AUTHN_GETINFO_VERSION.CTAP2)
        #self.get_info_resp.add_transport(AUTHN_GETINFO_TRANSPORT.USB)
        #self.get_info_resp.add_algorithm(PublicKeyCredentialParameters(PUBLIC_KEY_ALG.ES256))
        #self.get_info_resp.add_algorithm(PublicKeyCredentialParameters(PUBLIC_KEY_ALG.RS256))

    def get_AAGUID(self):
        return MyAuthenticator.MY_AUTHENTICATOR_AAGUID

    def authenticatorGetInfo(self, keep_alive:CTAPHIDKeepAlive) -> GetInfoResp:
        auth.debug("GetInfo called: %s", self.get_info_resp)
        return self.get_info_resp

    def authenticatorMakeCredential(self, params:AuthenticatorMakeCredentialParameters, keep_alive:CTAPHIDKeepAlive) -> MakeCredentialResp:
        #TODO perform necessary checks
        #TODO add non-residential key approach
        #keep_alive.start()
        auth.debug("Make Credential Called with params: %s", params)
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
        
        credential_source=PublicKeyCredentialSource()
        keypair = provider.create_new_key_pair()
        #TODO need to store entire user handle
        credential_source.init_new(provider.get_alg(),keypair,params.get_rp_entity()['id'],params.get_user_entity()['id'])
        self._storage.add_credential_source(params.get_rp_entity()['id'],params.get_user_entity()['id'],credential_source)
        authenticator_data = self._get_authenticator_data(credential_source,True)
        
        attestObject = AttestationObject.create_packed_self_attestation_object(credential_source,authenticator_data,params.get_hash())
        auth.debug("Created attestation object: %s", attestObject)
        return MakeCredentialResp(attestObject)
        
    
    def authenticatorGetAssertion(self, params:AuthenticatorGetAssertionParameters,keep_alive:CTAPHIDKeepAlive) -> GetAssertionResp:
        #TODO perform necessary checks
        #TODO add non-residential key approach
        creds = self._storage.get_credential_source_by_rp(params.get_rp_id(),params.get_allow_list())
        numberOfCredentials = len(creds)
        #TODO Implement Pin Options
        #TODO Implement User verification and presence check
        if numberOfCredentials < 1:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS)

        credential_source = creds[0]
        authenticator_data = self._get_authenticator_data_minus_creds(credential_source,True)
        
        response = {}
        
        response[1]=credential_source.get_public_key_credential_descriptor()
        response[2]=authenticator_data
        response[3]=credential_source.get_private_key().sign(authenticator_data + params.get_hash())
        credential_source.increment_signature_counter()
        response[4]=credential_source.get_user_handle()
        response[5]=numberOfCredentials
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
        numberOfCredentials = len(creds)
        if numberOfCredentials < 1:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS)
        if idx >= numberOfCredentials:
            raise DICEAuthenticatorException(CTAPHIDConstants.CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED)
        
        credential_source = creds[idx]
        authenticator_data = self._get_authenticator_data_minus_creds(credential_source,True)
        
        response = {}
        
        response[1]=credential_source.get_public_key_credential_descriptor()
        response[2]=authenticator_data
        response[3]=credential_source.get_private_key().sign(authenticator_data + params.get_hash())
        credential_source.increment_signature_counter()
        response[4]=credential_source.get_user_handle()
        response[5]=numberOfCredentials
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