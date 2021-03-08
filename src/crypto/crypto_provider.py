"""Authenticator Crypto Provider

Abstract classes that provide framework for Crypto Providers

Classes:

 * :class:`AuthenticatorCryptoPublicKey`
 * :class:`AuthenticatorCryptoPrivateKey`
 * :class:`AuthenticatorCryptoKeyPair`
 * :class:`AuthenticatorCryptoProvider`

Variables:
    CRYPTO_PROVIDERS - Global map of COSE algorithms to Crypto
        Provider instances
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


class AuthenticatorCryptoPublicKey(ABC):
    """Abstract Public Key to be used by the Authenticator

    This should be subclassed to provide appropriate functionality for
    implemented crypto algorithms. This is not intended to be instantiated
    itself.
    """
    def __init__(self, public_key):
        """Creates a new instance of the wrapper around a specific public key instance

        Note the type of the public key is left deliberately unspecified since it would be
        the type associate with the underlying crypto provider

        Args:
            public_key ([type]): the underlying public key to be wrapped, format is left unspecified
        """
        self._pk = public_key

    def get_public_key(self):
        """Gets the underlying public key

        Returns:
            [type]: Underlying public key
        """
        return self._pk

    @abstractmethod
    def get_encoded(self)->bytes:
        """Returns the underlying public key as bytes using whatever encoding is appropriate

        Returns:
            bytes: containing the public key
        """

    @abstractmethod
    def get_as_cose(self):
        """Returns the public key in a COSE compatible encoding
        """

    @staticmethod
    @abstractmethod
    def from_cose(cose_data:{})->'AuthenticatorCryptoPublicKey':
        """Loads a public key from its COSE encoding

        Returns:
            AuthenticatorCryptoPublicKey: crypto public key instance
        """

class AuthenticatorCryptoPrivateKey(ABC):
    """Abstract class representing the Private Key.

    Wraps the underlying crypto private key
    """
    def __init__(self, private_key):
        """Creates a new instance of abtract private key

        Args:
            private_key ([type]): underlying private key to be wrapped
        """
        self._sk = private_key

    def get_private_key(self):
        """Gets the underlying private key object

        Returns:
            [type]: private key in the underlying obkect
        """
        return self._sk

    @abstractmethod
    def sign(self,msg:bytes)->bytes:
        """Signs the msg with the private key

        The message with be hashed appropriately for the key size
        as such, it is not necessary to hash the message first.

        Args:
            msg (bytes): message bytes to be hashed and signed

        Returns:
            bytes: signature of hashed message
        """

    @abstractmethod
    def get_encoded(self)->bytes:
        """Gets the private key in a byte encoded form

        Returns:
            bytes: private key encoded as bytes
        """

class AuthenticatorCryptoKeyPair(ABC):
    """Abstract class containing a key pair of AuthenticatorPublicKey
    and AuthenticatorPrivateKey.

    This is used a convenience method
    """
    def __init__(self, public_key:AuthenticatorCryptoPublicKey,
                private_key:AuthenticatorCryptoPrivateKey):
        """Create a new instance of the key pair with references to
        abstract private and public keys

        Args:
            public_key (AuthenticatorCryptoPublicKey): public key portion
            private_key (AuthenticatorCryptoPrivateKey): private key portion
        """
        self._pk = public_key
        self._sk = private_key

    def get_public_key(self)->AuthenticatorCryptoPublicKey:
        """Return the public key

        Returns:
            AuthenticatorCryptoPublicKey: public key
        """
        return self._pk

    def get_private_key(self)->AuthenticatorCryptoPrivateKey:
        """Returns the private key

        Returns:
            AuthenticatorCryptoPrivateKey: private key
        """
        return self._sk

    @abstractmethod
    def get_encoded(self)->bytes:
        """Gets the key pair in a byte encoded form

        Note this may only encode the private key if the public key can be derived
        from the private key, as is often the case with ECC

        Returns:
            bytes: encoding sufficient information to reconstruct the public and private key
        """

#We create a global crypto providers dictionary to allow any class to access
#loaded crypto providers
CRYPTO_PROVIDERS = {}

class AuthenticatorCryptoProvider(ABC):
    """Abstract class for CryptoProviders that will be used by the Authenticator
    """

    def __init__(self):
        """Initialise a new CryptoProvider instance
        """
        self._alg = None

    def get_alg(self)->int:
        """Get the COSE algorithm that this crypto provider provides

        Returns:
            int: COSE algorithm identifier
        """
        return self._alg

    @classmethod
    def add_provider(cls,provider:'AuthenticatorCryptoProvider'):
        """Adds a crypto provider to the global list of available providers

        Providers are indexed by algorithm.

        TODO Consider how to prioritise between TPM and software based provivders
        that provide the same algorithm

        Args:
            provider (AuthenticatorCryptoProvider): Subclass of AuthenticatorCryptoProvider
                to add to the list
        """
        CRYPTO_PROVIDERS[provider.get_alg()]=provider

    @classmethod
    def shutdown_providers(cls):
        """Calls shutdown on providers to allow them to clean up and gracefully close
        """
        for prov in CRYPTO_PROVIDERS:
            CRYPTO_PROVIDERS[prov].shutdown()

    def shutdown(self):
        """Override to implement additional shutdown operations, like clearing a TPM
        """

    @abstractmethod
    def create_new_key_pair(self,relying_party:str=None)->AuthenticatorCryptoKeyPair:
        """Generate a new key pair using this crypto provider

        This will implement the necessary algorithm for key generation and
        wrap the private and public keys in teh AuthenticatorPublicKey and
        AuthenticatorPrivateKey classes, before constructing an
        AuthenticatorCryptoKeyPair object

        Args:
            relying_party (str, optional): if set may be used during key generation as
                an internal identifier, for example, on a TPM. Default is None
        Returns:
            AuthenticatorCryptoKeyPair: appropriately wrapped key pair
        """

    @abstractmethod
    def load_key_pair(self, data:bytes)->AuthenticatorCryptoKeyPair:
        """Loads a key pair from it byte representation

        The data contained within bytes will be encoded appropriately for
        the underlying crypto provider and may or may not include both keys.

        It is only guaranteed to provide sufficient data to reconstruct both
        keys, but that might require reconstructing the public key from the
        private key if that is how the crypto provider chooses to store the
        key pair

        Args:
            data (bytes): bytes containing sufficient information to reconstruct
                the key pair

        Returns:
            AuthenticatorCryptoKeyPair: Instantiated key pair
        """

    @abstractmethod
    def public_key_from_cose(self, cose_data:dict)->AuthenticatorCryptoPublicKey:
        """Creates a public key from its COSE representation

        This should interogate the COSE dictionary to reconstruct the public key
        as appropriate for the format and algorithm.

        Args:
            cose_data (dict): COSE encoded public key

        Returns:
            AuthenticatorCryptoPublicKey: Public key instantited and wrapped
        """
