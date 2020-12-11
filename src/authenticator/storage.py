"""Abstract Authenticator Storage class defines interface
that storage mechanisms must implement to act as storage
provider for an Authenticator.

Should consider also how to encrypt/protect the underlying
storage medium

"""
from abc import ABC, abstractmethod
from ctap.credential_source import PublicKeyCredentialSource
from authenticator.datatypes import PublicKeyCredentialDescriptor
class DICEAuthenticatorStorage(ABC):
    """Abstract authenticator storage class defining core
    functionality that storage methods must provide

    """
    def __init__(self):
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
    def get_credential_source(self,rp_id:str,user_id:bytes)->PublicKeyCredentialSource:
        """gets a credential source using the Relying Party ID and User ID as indexes

        Args:
            rp_id (str): Relying party to look up
            user_id (bytes): User id within relying party to retrieve

        Returns:
            PublicKeyCredentialSource: credential source found
        """

    @abstractmethod
    def get_credential_source_by_rp(self,rp_id:str, allow_list=None)->{PublicKeyCredentialSource}:
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
    def has_wrapping_key(self)->bool:
        """Checks whether a wrapping key has been set

        Returns:
            bool: True if a wrapping key has been set, False if not
        """

    def convert_allow_list_to_map(self, allow_list:[PublicKeyCredentialDescriptor]):
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
