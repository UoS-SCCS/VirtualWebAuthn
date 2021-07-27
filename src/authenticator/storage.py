"""Abstract Authenticator Storage class defines interface
that storage mechanisms must implement to act as storage
provider for an Authenticator.

Should consider also how to encrypt/protect the underlying storage medium
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
from typing import Dict, List
from ctap.credential_source import PublicKeyCredentialSource
from authenticator.datatypes import PublicKeyCredentialDescriptor
class DICEAuthenticatorStorage(ABC):
    """Abstract authenticator storage class defining core
    functionality that storage methods must provide

     Args:
            \*\*args: variable number of named arguments to handle subclassing
    """
    def __init__(self,**args):
        pass

    @abstractmethod
    def is_initialised(self)->bool:
        """Check if the storage has been initialised

        If not initialise init_new should be called

        Returns:
            bool: True if initialise, False if not
        """

    @abstractmethod
    def get_master_secret(self)->bytes:
        """gets the master secret

        Returns:
            bytes: bytes containing the master secret
        """

    @abstractmethod
    def init_new(self,master_secret:bytes):
        """Creates a new instance with the specified master secret

        Args:
            master_secret (bytes): master secret to initialise with
        """

    @abstractmethod
    def get_signature_counter(self)->int:
        """Gets the global signature counter

        Returns:
            int: global signature counter
        """

    @abstractmethod
    def update_signature_counter(self, new_counter:int)->bool:
        """Updates the global signature counter with the new value

        Args:
            new_counter (int): new value to set the counter to

        Returns:
            bool: True if set and written, False otherwise
        """

    @abstractmethod
    def increment_signature_counter(self)->bool:
        """Increments the global signature counter

        Returns:
            bool: True if incremented and written, False otherwise
        """
    @abstractmethod
    def update_credential_source(self, rp_id: str,
                                 credential_source: PublicKeyCredentialSource) -> bool:
        """Updates the specified credential source with a new version. This is primarily
        used for updating signature counters after a getAssertion call

        When performing the update the implementer should call get_loaded_bytes
        on the credential_source to get the originally loaded bytes and match based
        on those.

        Args:
            rp_id (str): string of the rp_id
            credential_source (PublicKeyCredentialSource): credential source to update

        Returns:
            bool: [description]
        """
    @abstractmethod
    def add_credential_source(self,rp_id:str,user_id:bytes,
        credential_source:PublicKeyCredentialSource)->bool:
        """Adds the specified credential source indexed by the RpID and the UserId

        Args:
            rp_id (str): Relying party ID
            user_id (bytes): User ID
            credential_source (PublicKeyCredentialSource): credential source to store

        Returns:
            bool: True if written, False otherwise
        """

    @abstractmethod
    def debug(self):
        """Prints a debug string about the contents of the storage medium, i.e. keys,
        RPs etc
        """
    @abstractmethod
    def get_credential_source(self,rp_id:str,user_id:bytes)->PublicKeyCredentialSource:
        """gets a credential source using the Relying Party ID and User ID as indexes

        Args:
            rp_id (str): Relying party to look up
            user_id (bytes): User id within relying party to retrieve

        Returns:
            PublicKeyCredentialSource: credential source found
        """

    @abstractmethod
    def get_credential_source_by_rp(self,rp_id:str, allow_list=None)->Dict:
        """Gets credential sources using the relying party ID as an index and then applying the
        passed in allow_list, if provided

        Args:
            rp_id (str): Relying party to look up
            allow_list ([type], optional): allow list of credentials. Defaults to None.

        Returns:
            PublicKeyCredentialSource: map of credential sources matching the criteria
        """

    @abstractmethod
    def get_pin_retries(self)->int:
        """Gets the number of PIN retries remaining

        Returns:
            int: PIN retries remaining
        """

    @abstractmethod
    def get_pin(self)->bytes:
        """Gets the pin

        Returns:
            bytes: bytes containing the PIN
        """

    @abstractmethod
    def set_pin_retries(self, retries:int)->int:
        """Sets the number of retries remaining

        Args:
            value (int): retries remaining to set

        Returns:
            int: the number of retries remaining
        """

    @abstractmethod
    def set_pin(self, pin_value:bytes):
        """Sets the PIN to the specified bytes

        Args:
            pin_value (bytes): PIN as bytes

        """

    @abstractmethod
    def decrement_pin_retries(self)->int:
        """Decreases PIN retries by one

        Returns:
            int: PIN retries remaining after decrease
        """

    @abstractmethod
    def reset(self)->bool:
        """Resets the storage medium to new

        Warning: this will cause existing credential data to be lost
        should only be called with user permission

        Returns:
            bool: True if reset is successful, False if not
        """

    @abstractmethod
    def get_wrapping_key(self)->bytes:
        """Gets the global wrapping key

        Returns:
            bytes: wrapping key as bytes
        """

    @abstractmethod
    def set_wrapping_key(self, wrap_key:bytes)->bool:
        """Sets the global wrapping key to key bytes

        Args:
            wrap_key (bytes): wrapping key to store

        Returns:
            bool: True if set, False if not
        """
    @abstractmethod
    def delete_field(self, key:str)->bool:
        """Removes the specified key

        Args:
            key (str): key to remove

        Returns:
            bool: True if successful, False if not
        """
    @abstractmethod
    def get_string(self, key:str)->str:
        """Gets an arbitray string from the data store

        This can be used to store additional arbitrary data, for
        example, JSON encoded strings

        Returns:
            str: arbitrary string data or None if not set
        """
    @abstractmethod
    def set_string(self, key:str, data:str)->bool:
        """Sets an abitrary string in the data store

        This can be used to store additional arbitrary data, for
        example, JSON encoded strings

        Args:
            key (str): field key
            data (str): data encoded as a string

        Returns:
            bool: True if stored, False if not
        """
    @abstractmethod
    def has_wrapping_key(self)->bool:
        """Checks whether a wrapping key has been set

        Returns:
            bool: True if a wrapping key has been set, False if not
        """

    @abstractmethod
    def set_uv_value(self, uv_check_value:bytes)->bool:
        """Sets an arbitrary byte value that contains the data to perform
        user verification. It could be biometric, a test encryption or some
        other data.

        Args:
            uv_check_value (bytes): user verification check data

        Returns:
            bool:  True if set, False if not
        """

    @abstractmethod
    def get_uv_value(self)->bytes:
        """Gets the user verification data

        Returns:
            bytes: user verification data if set, or None
        """


    def convert_allow_list_to_map(self, allow_list:List[PublicKeyCredentialDescriptor]):
        """Converts an allow list received from the client into a
        map for use with filtering credentials. In effect iterates
        through credentials in allow list and indexes them by
        user id in a map

        Args:
            allow_list ([PublicKeyCredentialDescriptor]): list of
            allowed Public Key Credential Descriptors

        Returns:
            map : map of allowed credentials indexed by credential ID
        """
        allow = {}
        for allowed in allow_list:
            allow[allowed.get_id()]=allowed.get_type()
        return allow
class DICEAuthenticatorStorageException(Exception):
    """Exception raised when accessing the storage medium

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message="Storage Exception"):
        self.message = message
        super().__init__(self.message)
