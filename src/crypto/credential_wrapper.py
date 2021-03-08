"""Abstract Credential Wrapper provides functionality for
encrypting (wrapping) and decrypting (unwrapping) PublicKeyCredentialSources
as used by WebAuthN to store credential sources on the Relying Party server
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
from abc import ABC, abstractmethod
from ctap.credential_source import PublicKeyCredentialSource
class CredentialWrapper(ABC):
    """Abstract Credential Wrapper defining functions needed to
    wrap and unwrap credential sources

    """
    def __init__(self):
        self.name = "Base"

    @abstractmethod
    def wrap(self, key:bytes, credential:PublicKeyCredentialSource)->bytes:
        """Wrap a public key credential source by encrypting it with the specified key

        Args:
            key (bytes): AES key bytes to use in encryption
            credential (PublicKeyCredentialSource): credential to be encrypted

        Returns:
            bytes: encrypted credential
        """
    @abstractmethod
    def unwrap(self, key:bytes, wrapped_credential:bytes)->PublicKeyCredentialSource:
        """Unwrap a wrapped public key credential source by decrypting it with the
        specified key

        Args:
            key (bytes): AES key bytes to use in decryption
            wrapped_credential (bytes): encrypted credential to unwrap

        Returns:
            PublicKeyCredentialSource: decrypted and instantiated credential source
        """

    @abstractmethod
    def generate_key(self)->bytes:
        """Generates a new wrapping key

        Returns:
            bytes: bytes containing wrapping key
        """
