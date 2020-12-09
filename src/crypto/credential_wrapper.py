"""Abstract Credential Wrapper provides functionality for
encrypting (wrapping) and decrypting (unwrapping) PublicKeyCredentialSources
as used by WebAuthN to store credential sources on the Relying Party server
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
