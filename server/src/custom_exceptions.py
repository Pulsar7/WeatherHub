

class InvalidConnectionStatusException(Exception):

    """Exception raised when attempting to set the connection status to false, while authentication is still true."""

    def __init__(self, message:str="Authentication is still true. Connection status cannot be set to false.") -> None:
        self.message = message
        super().__init__(self.message)


class InvalidAuthenticationStatusException(Exception):

    """Exception raised when attempting to set the authentication status to true, while connection is false."""

    def __init__(self, message:str="Connection is false. Authentication status cannot be set to true.") -> None:
        self.message = message
        super().__init__(self.message)


class NotAuthenticatedException(Exception):

    """Exception an operation requiring authentication is attempted without being authenticated."""

    def __init__(self, message:str="Operation requires authentication.") -> None:
        self.message = message
        super().__init__(self.message)

class CannotChangeWriteOnceValuesException(Exception):

    """Exception raised when attempting to change specific client-attributes, which cannot be changed after they've been set."""

    def __init__(self, message:str="Cannnot change write-only-once values.") -> None:
        self.message = message
        super().__init__(self.message)


class BufferingError(Exception):

    """Exception raised when buffering failed with client."""

    def __init__(self, message:str="Buffering with client failed.") -> None:
        self.message = message
        super().__init__(self.message)

class ClientAuthenticationFailedException(Exception):

    """Exception raised when the client authentication-process failed."""

    def __init__(self, message:str="The client authentication-process failed.") -> None:
        self.message = message
        suepr().__init__(self.message)
