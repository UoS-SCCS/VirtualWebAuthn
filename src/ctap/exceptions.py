"""Exceptions for transactions and low level HID errors
"""
import ctap.constants
class TransactionStateException(Exception):
    """Exception raised for errors in transaction state.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message="Incorrect transaction state"):
        self.message = message
        super().__init__(self.message)

class TransactionChannelIDException(Exception):
    """Exception raised when the MSG channel ID does not match the transaction channel ID

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message="Incorrect channel ID"):
        self.message = message
        super().__init__(self.message)

class ChannelNotFoundException(Exception):
    """Exception raised when a message is received with an unknown channel ID

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message="Unknown channel ID"):
        self.message = message
        super().__init__(self.message)

class CTAPHIDException(Exception):
    """Exception raised when accessing the storage medium

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, err_code:ctap.constants.CTAPHID_ERROR,message="Something went wrong"):
        self.message = message
        self.err_code = err_code
        super().__init__(self.message)

    def get_error_code(self)->ctap.constants.CTAPHID_ERROR:
        """Gets the error code in this exception

        Returns:
            ctap.constants.CTAPHID_ERROR: error that is set in the exception
        """
        return self.err_code
