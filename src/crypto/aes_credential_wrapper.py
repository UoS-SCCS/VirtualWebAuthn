"""Concrete implementation of Credential Wrapper providing
a wrapper that uses AES to wrap the credential source

Classes:
    AESCredentialWrapper
"""
import os
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.backends import default_backend
from ctap.credential_source import PublicKeyCredentialSource
from crypto.credential_wrapper import CredentialWrapper

class AESCredentialWrapper(CredentialWrapper):
    """An implementation of an AES based Credential Wrapper

    This can be used to encrypt and decrypt a PublicKeyCredentialSource

    """
    def __init__(self):
        super().__init__()
        self.name = "AES"

    def wrap(self, key:bytes, credential:PublicKeyCredentialSource)->bytes:
        """wraps a PublicKeyCredentialSource in an encrypted block.
        This is used for a non-resident key.

        Args:
            key (bytes): AES Key
            credential (PublicKeyCredentialSource): credential to wrap

        Returns:
            bytes: Encrypted credential
        """
        return keywrap.aes_key_wrap_with_padding(key,credential.get_bytes(True),default_backend())

    def unwrap(self, key:bytes, wrapped_credential:bytes)->PublicKeyCredentialSource:
        """unwraps by decrypting a wrapped credential

        Args:
            key (bytes): AES key
            wrapped_credential (bytes): Encrypted credential to decrypt

        Returns:
            PublicKeyCredentialSource: Decrypted PublicKeyCredentialSource
        """
        unwrapped = keywrap.aes_key_unwrap_with_padding(key,wrapped_credential,default_backend())
        cred = PublicKeyCredentialSource()
        cred.from_bytes(unwrapped,True)
        cred.set_id(wrapped_credential)
        return cred

    def generate_key(self)->bytes:
        """Generates a new wrapping key by selecting 32 bytes at random

        Returns:
            bytes: 32 bytes at random to use as an AES key
        """
        return os.urandom(32)
