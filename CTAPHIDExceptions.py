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