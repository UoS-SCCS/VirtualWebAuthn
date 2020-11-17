from DICEAuthenticator import DICEAuthenticator
from DICEAuthenticator import GetInfoResp
from DICEAuthenticator import AUTHN_GETINFO_OPTION
from DICEAuthenticator import AUTHN_GETINFO_TRANSPORT
from DICEAuthenticator import PUBLIC_KEY_ALG
from DICEAuthenticator import PublicKeyCredentialParameters
from DICEAuthenticator import AUTHN_GETINFO_VERSION
from DICEAuthenticator import AuthenticatorMakeCredentialParameters
from DICEAuthenticator import AuthenticatorGetAssertionParameters

from DICEAuthenticator import MakeCredentialResp
from DICEAuthenticator import GetAssertionResp

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


class MyAuthenticator(DICEAuthenticator):
    MY_AUTHENTICATOR_AAGUID = UUID("c9181f2f-eb16-452a-afb5-847e621b92aa")
    def __init__(self, storage:DICEAuthenticatorStorage, crypto_providers:[int]):
        #allow list of crypto providers, may be a subset of all available providers
        super()
        self._init()
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

    def _init(self):
        pass

    def authenticatorGetInfo(self, keep_alive:CTAPHIDKeepAlive) -> GetInfoResp:
        print("this was called")
        return self.get_info_resp

    def authenticatorMakeCredential(self, params:AuthenticatorMakeCredentialParameters, keep_alive:CTAPHIDKeepAlive) -> MakeCredentialResp:
        #TODO perform necessary checks
        #TODO add non-residential key approach
        #keep_alive.start()
        provider = None
        for cred_type in params.get_cred_types_and_pubkey_algs():
            if cred_type["alg"] in self._providers:
                provider=CRYPTO_PROVIDERS[cred_type["alg"]]
                #provider = self._providers_idx[cred_type["alg"]]
                logging.debug("Found matching algorithm: %s", provider.get_alg())
                break

        if provider is None:
            raise Exception("No matching provider found")
        
        print("Will create keypair")
        credential_source=PublicKeyCredentialSource()
        keypair = provider.create_new_key_pair()
        #TODO need to store entire user handle
        credential_source.init_new(provider.get_alg(),keypair,params.get_rp_entity()['id'],params.get_user_entity()['id'])
        self._storage.add_credential_source(params.get_rp_entity()['id'],params.get_user_entity()['id'],credential_source)
        #output=self._storage.get_credential_source(params.get_rp_entity()['id'],params.get_user_entity()['id'])
        #credential_data = self._get_credential_data(credential_source)
        authenticator_data = self._get_authenticator_data(credential_source,True)
        
        attestObject = AttestationObject.create_packed_self_attestation_object(credential_source,authenticator_data,params.get_hash())
        return MakeCredentialResp(attestObject)
        #params.get_user_entity()["id"]
    
    def authenticatorGetAssertion(self, params:AuthenticatorGetAssertionParameters,keep_alive:CTAPHIDKeepAlive) -> GetAssertionResp:
         #TODO perform necessary checks
        #TODO add non-residential key approach
        creds = self._storage.get_credential_source_by_rp(params.get_rp_id())
        if not params.get_allow_list() is None:
            print("need to filter creds by allow list")
            print("AllowList:%s", params.get_allow_list()[0]["id"].hex())
            #TODO implement allow list
        numberOfCredentials = len(creds)
        #TODO Implement Pin Options
        #TODO Implement User verification and presence check
        if numberOfCredentials < 1:
            #TODO Return error
            pass
        cred_list = []
        for cred in creds:
            cred_list.append(creds[cred])
            print("Creds:%s",creds[cred].get_id().hex())
        credential_source = cred_list[0]
        authenticator_data = self._get_authenticator_data_minus_creds(credential_source,True)
        #attestObject = AttestationObject.create_packed_self_attestation_object(credential_source,authenticator_data,params.get_hash())

        response = {}
        
        response[1]=credential_source.get_public_key_credential_descriptor()
        response[2]=authenticator_data
        response[3]=credential_source.get_private_key().sign(authenticator_data + params.get_hash())
        response[4]=credential_source.get_user_handle()
        #response[4]["name"]="stag_test_2"
        #response[4]["displayName"]="stag_test_2"
        response[5]=numberOfCredentials
        """
        credential 	0x01 	definite length map (CBOR major type 5).
        authData 	0x02 	byte string (CBOR major type 2).
        signature 	0x03 	byte string (CBOR major type 2).
        publicKeyCredentialUserEntity 	0x04 	definite length map (CBOR major type 5).
        numberOfCredentials 	0x05 	unsigned integer(CBOR major type 0). 
        """
        print("CBOR******************")
        print(cbor.encode(response).hex())

        return GetAssertionResp(response)
        
    
    def _get_credential_data(self,credential_source:PublicKeyCredentialSource):
        """	                    Length (in bytes) 	Description
            aaguid 	            16 	                The AAGUID of the authenticator.
            credentialIdLength 	2 	                Byte length L of Credential ID, 16-bit unsigned big-endian integer.
            credentialId 	    L 	                Credential ID
            credentialPublicKey variable 	        The credential public key encoded in COSE_Key format, as defined in Section 7 of [RFC8152], using the CTAP2 canonical CBOR encoding form. The COSE_Key-encoded credential public key MUST contain the "alg" parameter and MUST NOT contain any other OPTIONAL parameters. The "alg" parameter MUST contain a COSEAlgorithmIdentifier value. The encoded credential public key MUST also contain any additional REQUIRED parameters stipulated by the relevant key type specification, i.e., REQUIRED for the key type "kty" and algorithm "alg" (see Section 8 of [RFC8152]). 
        """
        credential_data = MyAuthenticator.MY_AUTHENTICATOR_AAGUID.bytes
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