class ClientAlreadyConnectedError(Exception):

    """Exception raised when attempting to change a property while the client is already connected."""

    def __init__(self, message="Cannot modify property because the client is already connected to the server."):
        self.message = message
        super().__init__(self.message)


class BufferingError(Exception):

    """Exception raised when buffering failed with server."""

    def __init__(self, message:str="Buffering with server failed.") -> None:
        self.message = message
        super().__init__(self.message)
