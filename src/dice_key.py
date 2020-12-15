"""Example implementation of a DICE Authenticator

Classes:
    DICEKey
"""
import logging

#for x509 cert
from uuid import UUID

from crypto.crypto_provider import AuthenticatorCryptoProvider,CRYPTO_PROVIDERS
from crypto.tpm_es256_crypto_provider import TPMES256CryptoProvider
from crypto.aes_credential_wrapper import AESCredentialWrapper
from crypto.algs import PUBLIC_KEY_ALG
from authenticator.ui import DICEAuthenticatorListener
from authenticator.diceauthenticator import DICEAuthenticator
from authenticator.datatypes import (DICEAuthenticatorException,AuthenticatorGetClientPINParameters,
    AuthenticatorGetAssertionParameters,AuthenticatorMakeCredentialParameters,
    PublicKeyCredentialParameters,AuthenticatorVersion)
from authenticator.cbor import (GetAssertionResp,MakeCredentialResp,GetClientPINResp,
    GetInfoResp,ResetResp,AUTHN_GETINFO_OPTION,AUTHN_GETINFO_TRANSPORT,AUTHN_GETINFO_VERSION)
from authenticator.json_storage import JSONAuthenticatorStorage, EncryptedJSONAuthenticatorStorage

import ctap.constants
from ctap.credential_source import PublicKeyCredentialSource
from ctap.keep_alive import CTAPHIDKeepAlive
from ctap.attestation import AttestationObject

from authenticator.ui import QTAuthenticatorUI

log = logging.getLogger('debug')
auth = logging.getLogger('debug.auth')

class DICEKey(DICEAuthenticator,DICEAuthenticatorListener):
    """Concrete implementation of a CTAP2 authenticator

    """
    VERSION = AuthenticatorVersion(2,1,0,0)
    DICEKEY_AUTHENTICATOR_AAGUID = UUID("c9181f2f-eb16-452a-afb5-847e621b92aa")
    KEEP_ALIVE_TIME_MS=180000
    def __init__(self):
        #allow list of crypto providers, may be a subset of all available providers
        #super().__init__(ui=QTAuthenticatorUI())
        super().__init__(ui=QTAuthenticatorUI())
        #prepare authenticator


        AuthenticatorCryptoProvider.add_provider(TPMES256CryptoProvider())
        self._providers = []
        self._providers.append(TPMES256CryptoProvider().get_alg())

        self._credential_wrapper = AESCredentialWrapper()
        #This can be user configurable
        self.default_to_rk=True


        #self._providers_idx = {}
        #for provider in crypto_providers:
        #    self._providers_idx[provider.get_alg()] = provider
        self.get_info_resp = GetInfoResp(DICEAuthenticator.AUTHENTICATOR_AAGUID.bytes)
        self.get_info_resp.set_auguid(DICEKey.DICEKEY_AUTHENTICATOR_AAGUID)

        self.get_info_resp.set_option(AUTHN_GETINFO_OPTION.RESIDENT_KEY,True)
        self.get_info_resp.set_option(AUTHN_GETINFO_OPTION.USER_PRESENCE,True)
        #self.get_info_resp.set_option(AUTHN_GETINFO_OPTION.CONFIG,True)
        self.get_info_resp.add_version(AUTHN_GETINFO_VERSION.CTAP2)
        #self.get_info_resp.add_version(AUTHN_GETINFO_VERSION.CTAP1)
        self.get_info_resp.add_transport(AUTHN_GETINFO_TRANSPORT.USB)
        self.get_info_resp.add_algorithm(PublicKeyCredentialParameters(PUBLIC_KEY_ALG.ES256))
        #self.get_info_resp.add_algorithm(PublicKeyCredentialParameters(PUBLIC_KEY_ALG.RS256))


    def post_ui_load(self):
        #will be called on a new thread
        log.debug("In post UI load method, asking for password")
        pwd = self._ui.get_user_password("Please enter your password:")
        log.debug("Initialising Encrypted Storage")
        self._storage = EncryptedJSONAuthenticatorStorage("./data/auth_store.enc",pwd)
        if not self._storage.is_initialised():
            self._storage.init_new()
        #Generate PIN Key Agreement at Startup
        if not self._storage.has_wrapping_key():
            self._storage.set_wrapping_key(self._credential_wrapper.generate_key())

        if not self._storage.get_pin() is None:
            self.get_info_resp.set_option(AUTHN_GETINFO_OPTION.CLIENT_PIN,True)
        else:
            self.get_info_resp.set_option(AUTHN_GETINFO_OPTION.CLIENT_PIN,False)


    def shutdown(self):
        """Shut down the authenticator
        """
        auth.log("DICEKey shutdown called")
        super().shutdown()


    def get_aaguid(self)->UUID:
        """Get the Authenticator AA GUID

        Returns:
            UUID: AAGUID
        """
        return DICEKey.DICEKEY_AUTHENTICATOR_AAGUID

    def get_version(self)->AuthenticatorVersion:
        return DICEKey.VERSION

    def authenticator_get_info(self, keep_alive:CTAPHIDKeepAlive) -> GetInfoResp:
        auth.debug("GetInfo called: %s", self.get_info_resp)
        return self.get_info_resp

    def authenticator_make_credential(self, params:AuthenticatorMakeCredentialParameters,
            keep_alive:CTAPHIDKeepAlive) -> MakeCredentialResp:
        #TODO perform necessary checks
        keep_alive.start(DICEKey.KEEP_ALIVE_TIME_MS)
        #keep_alive.start()
        user_presence = self._ui.check_user_presence(params.get_rp_entity().get_name() + " requests access to your Authenticator.")

        if not user_presence:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_OPERATION_DENIED, "User Presence Denied")

        auth.debug("Make Credential called, req resident: %s, with params: %s",
            params.get_require_resident_key(), params)
        provider = None
        for cred_type in params.get_cred_types_and_pubkey_algs():
            if cred_type["alg"] in self._providers:
                provider=CRYPTO_PROVIDERS[cred_type["alg"]]
                #provider = self._providers_idx[cred_type["alg"]]
                auth.debug("Found matching public key algorithm: %s",
                    PUBLIC_KEY_ALG(provider.get_alg()).name)
                break

        if provider is None:
            auth.error("No matching public key provider found")
            raise Exception("No matching provider found")

        uv = self._check_pin(params.get_pin_auth(),params.get_pin_protocol(),params.get_hash())

        credential_source=PublicKeyCredentialSource()
        keypair = provider.create_new_key_pair()
        credential_source.init_new(provider.get_alg(),keypair,params.get_rp_entity(),
            params.get_user_entity())

        #If requested to be an RK store as RK, or if default is RK set to
        if params.get_require_resident_key() or self.default_to_rk:
            self._storage.add_credential_source(params.get_rp_entity().get_id(),
                params.get_user_entity(),credential_source)
        else:
            auth.debug("Non-resident key, wrapping credential source")
            credential_source.set_id(self._credential_wrapper.wrap(
                    self._storage.get_wrapping_key(),credential_source))


        authenticator_data = self._get_authenticator_data(credential_source,user_presence,uv)

        attest_object = AttestationObject.create_packed_self_attestation_object(
            credential_source,authenticator_data,params.get_hash())
        auth.debug("Created attestation object: %s", attest_object)
        keep_alive.stop()
        return MakeCredentialResp(attest_object)


    def authenticator_get_assertion(self, params:AuthenticatorGetAssertionParameters,
            keep_alive:CTAPHIDKeepAlive) -> GetAssertionResp:

        keep_alive.start(DICEKey.KEEP_ALIVE_TIME_MS)
        #First find all resident creds (could be zero)
        creds = self._storage.get_credential_source_by_rp(params.get_rp_id(),
            params.get_allow_list())

        #Now check for any non-resident creds
        for allow_cred in params.get_allow_list():
            if len(allow_cred.get_id())>ctap.constants.CREDENTIAL_ID_SIZE:
                auth.debug("Wrapped key provided, will unwrap credential source")
                #we have a wrapped credential
                creds.append(self._credential_wrapper.unwrap(
                    self._storage.get_wrapping_key(),allow_cred.get_id()))


        number_of_credentials = len(creds)

        #TODO Implement User verification
        if number_of_credentials < 1:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS)

        credential_source = creds[0]
        uv = self._check_pin(params.get_pin_auth(),params.get_pin_protocol(),
            params.get_hash(),False)

        user_presence = self._ui.check_user_presence(params.get_rp_id() + " requests access to your Authenticator.")

        if not user_presence:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_OPERATION_DENIED, "User Presence Denied")

        authenticator_data = self._get_authenticator_data_minus_creds(credential_source,True,uv)

        # Contains the following data
        #   credential  0x01    definite length map (CBOR major type 5).
        #   authData 	0x02 	byte string (CBOR major type 2).
        #   signature 	0x03 	byte string (CBOR major type 2).
        #   publicKeyCredentialUserEntity 	0x04 	definite length map (CBOR major type 5).
        #   numberOfCredentials 	0x05 	unsigned integer(CBOR major type 0).
        response = {}
        response[2]=authenticator_data
        response[3]=credential_source.get_private_key().sign(authenticator_data + params.get_hash())
        credential_source.increment_signature_counter()
        response[4]=credential_source.get_user_entity()
        response[5]=number_of_credentials
        #We put this last so the returned value can be
        # updated - not sure this actually has any impact
        response[1]=credential_source.get_public_key_credential_descriptor()
        keep_alive.stop()
        return GetAssertionResp(response,number_of_credentials)

    def authenticator_get_next_assertion(self, params:AuthenticatorGetAssertionParameters,idx:int,
            keep_alive:CTAPHIDKeepAlive) -> GetAssertionResp:
        creds = self._storage.get_credential_source_by_rp(params.get_rp_entity().get_id(),
            params.get_allow_list())
        #Now check for any non-resident creds
        for allow_cred in params.get_allow_list():
            if len(allow_cred.get_id())>ctap.constants.CREDENTIAL_ID_SIZE:
                auth.debug("Wrapped key provided, will unwrap credential source")
                #we have a wrapped credential
                creds.append(self._credential_wrapper.unwrap(
                    self._storage.get_wrapping_key(),allow_cred.get_id()))

        number_of_credentials = len(creds)
        if number_of_credentials < 1:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_NO_CREDENTIALS)
        if idx >= number_of_credentials:
            raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_NOT_ALLOWED)

        credential_source = creds[idx]
        authenticator_data = self._get_authenticator_data_minus_creds(credential_source,True)

        # Consists of
        # credential 	0x01 	definite length map (CBOR major type 5).
        # authData 	0x02 	byte string (CBOR major type 2).
        # signature 	0x03 	byte string (CBOR major type 2).
        # publicKeyCredentialUserEntity 	0x04 	definite length map (CBOR major type 5).
        # numberOfCredentials 	0x05 	unsigned integer(CBOR major type 0).


        response = {}
        response[2]=authenticator_data
        response[3]=credential_source.get_private_key().sign(authenticator_data + params.get_hash())
        credential_source.increment_signature_counter()
        response[4]=credential_source.get_user_entity()
        response[5]=number_of_credentials
        #We put this last so the returned value can be
        # updated - not sure this actually has any impact
        response[1]=credential_source.get_public_key_credential_descriptor()

        return GetAssertionResp(response,number_of_credentials)

    def authenticator_reset(self, keep_alive:CTAPHIDKeepAlive) -> ResetResp:
        if self._storage.reset():
            return ResetResp()
        raise DICEAuthenticatorException(ctap.constants.CTAP_STATUS_CODE.CTAP1_ERR_OTHER)

    def authenticator_get_client_pin_get_retries(self, params:AuthenticatorGetClientPINParameters,
            keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        return GetClientPINResp(retries=self._storage.get_pin_retries())

    def authenticator_get_client_pin_get_key_agreement(self,
            params:AuthenticatorGetClientPINParameters,
            keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        return GetClientPINResp(
            key_agreement=self._authenticator_key_agreement_key.get_public_key().get_as_cose())

    def authenticator_get_client_pin_set_pin(self, params:AuthenticatorGetClientPINParameters,
            keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        #TODO verify contents of params
        if not self._storage.get_pin() is None:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_AUTH_INVALID,
                "PIN has already been set")

        #TODO generalise and remove hard coding to cose parameters
        shared_secret = self._generate_shared_secret(params.get_key_agreement())
        check = self._calculate_pin_auth(shared_secret,params.get_new_pin_enc())
        if not check[0:16] == params.get_pin_auth()[0:16]:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_AUTH_INVALID,"Auth PIN did not match")

        decrypted_pin = self._decrypt_value(shared_secret,params.get_new_pin_enc())
        pin = self._extract_pin(decrypted_pin)

        if len(pin)<4:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_POLICY_VIOLATION, "PIN too short")
        self._storage.set_pin(self._sha256(pin)[:16])
        return GetClientPINResp()

    def authenticator_get_client_pin_change_pin(self, params:AuthenticatorGetClientPINParameters,
            keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        if self._storage.get_pin() is None:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_AUTH_INVALID,"No PIN Set")

        #TODO generalise and remove hard coding to cose parameters
        shared_secret = self._generate_shared_secret(params.get_key_agreement())
        check = self._calculate_pin_auth(shared_secret,params.get_new_pin_enc(),
            params.get_pin_hash_enc())
        if not check[0:16] == params.get_pin_auth()[0:16]:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_AUTH_INVALID,"Auth PIN did not match")

        self._storage.decrement_pin_retries()
        decrypted_pin_hash = self._decrypt_value(shared_secret,params.get_pin_hash_enc())
        stored_pin = self._storage.get_pin()

        if not stored_pin[:16] == decrypted_pin_hash[:16]:
            #TODO handle run out of tries and successive lock
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_INVALID, "PIN invalid")

        decrypted_pin = self._decrypt_value(shared_secret,params.get_new_pin_enc())
        pin = self._extract_pin(decrypted_pin)

        if len(pin)<4:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_POLICY_VIOLATION, "PIN too short")

        self._storage.set_pin(self._sha256(pin)[:16])
        self._storage.set_pin_retries(8)
        return GetClientPINResp()

    def authenticator_get_client_pin_get_pin_token(self, params:AuthenticatorGetClientPINParameters,
            keep_alive:CTAPHIDKeepAlive) -> GetClientPINResp:
        if self._storage.get_pin() is None:
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_AUTH_INVALID,"No PIN Set")

        #TODO generalise and remove hard coding to cose parameters
        shared_secret = self._generate_shared_secret(params.get_key_agreement())

        self._storage.decrement_pin_retries()
        decrypted_pin_hash = self._decrypt_value(shared_secret,params.get_pin_hash_enc())
        stored_pin = self._storage.get_pin()

        if not stored_pin[:16] == decrypted_pin_hash[:16]:
            #TODO handle run out of tries and successive lock
            raise DICEAuthenticatorException(
                ctap.constants.CTAP_STATUS_CODE.CTAP2_ERR_PIN_INVALID, "PIN invalid")

        self._storage.set_pin_retries(8)

        return GetClientPINResp(pin_token=self._encrypt_value(shared_secret,self._pin_token))

    def process_wink(self, payload:bytes, keep_alive: CTAPHIDKeepAlive)->bytes:
        auth.debug("Process wink")
        return bytes(0)

    def start(self):
        """Starts the authenticator
        """
        self._start()

    #==========================
    #
    #       UI Methods
    #==========================
    def menu_clicked(self, menu_item:str):
        pass



def main():
    """Main function to run the DICEKey code
    """
    key = DICEKey()
    key.start()


if __name__ == "__main__":
    main()

