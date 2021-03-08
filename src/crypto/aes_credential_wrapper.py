"""Concrete implementation of Credential Wrapper providing
a wrapper that uses AES to wrap the credential source

Classes:

 * :class:`AESCredentialWrapper`

"""
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
