import ssl
import time
import socket
#
from .constants import *
from .custom_exceptions import *


class Client:

    """Object for every connected client."""

    def __init__(self, client_socket:socket.socket, ssl_socket:ssl.SSLSocket, client_addr:tuple[str,int]) -> None:
        self._tcp_socket:socket.socket = client_socket
        self._ssl_socket:ssl.SSLSocket = ssl_socket
        self._client_addr:tuple[str,int] = client_addr
        # Set to default-values
        self._client_type:ClientType = ClientType.UNKNOWN
        self._permission:ClientPermission = ClientPermission.UNKNOWN
        self._connection_status:bool = True
        self._authentication_status:bool = False
        self._username:str = ""

    @property
    def tcp_socket(self) -> socket.socket:
        """Returns the 'normal' client-socket."""
        return self._tcp_socket

    @property
    def ssl_socket(self) -> ssl.SSLSocket:
        """Returns the client SSL/TLS-Socket."""
        return self._ssl_socket

    @property
    def client_addr(self) -> tuple[str,int]:
        """Returns the client-address."""
        return self._client_addr

    @property
    def client_type(self) -> ClientType:
        """Returns the client-type."""
        return self._client_type

    @client_type.setter
    def client_type(self, new_client_type:ClientType) -> None:
        """Sets client-type of client."""

        if not self.authentication_status:
            # Cannot change client-type, when client isn't authenticated.
            raise NotAuthenticatedException()

        if self.client_type != ClientType.UNKNOWN:
            # Client-Type can be only set once.
            raise CannotChangeWriteOnceValuesException()

        self._client_type = new_client_type

    @property
    def permission(self) -> ClientPermission:
        """Returns the client permission."""
        return self._permission

    @permission.setter
    def permission(self, new_client_permission:ClientPermission) -> None:
        if not self.authentication_status:
            # Cannot change client-permission, when client isn't authenticated.
            raise NotAuthenticatedException()
        if self.permission != ClientPermission.UNKNOWN:
            # Permission can be only set once.
            raise CannotChangeWriteOnceValuesException()

        self._permission = new_client_permission

    @property
    def connection_status(self) -> bool:
        """Returns the connection-status of the client."""
        return self._connection_status

    @connection_status.setter
    def connection_status(self, new_connection_status:bool) -> None:
        """Sets connection status of client."""

        if new_connection_status == self.connection_status:
            # Nothing to change.
            raise ValueError("New connection status equals current.")
        if self.authentication_status and not new_connection_status:
            # Cannot set connection-status to False, when client is still authenticated.
            raise InvalidConnectionStatusException()
        self._connection_status = new_connection_status

    @property
    def authentication_status(self) -> bool:
        """Returns the authentication-status of the client."""
        return self._authentication_status

    @authentication_status.setter
    def authentication_status(self, new_auth_status:bool) -> None:
        """Sets authentication-status of client."""

        if new_auth_status == self.authentication_status:
            # Nothing to change.
            raise ValueError("New authentication status equals current.")
        if not self.connection_status and new_auth_status:
            # Cannot set authentication-status to True, when there's no connection to the server.
            raise InvalidAuthenticationStatusException()

        self._authentication_status = new_auth_status

    @property
    def username(self) -> str:
        """Returns the client-username."""
        return self._username

    @username.setter
    def username(self, username:str) -> None:
        """Sets username of client."""

        # Check if username is a valid string.
        if not isinstance(username, str):
            raise TypeError("The username has to be a string.")
        if len(username) == 0:
            raise ValueError("No username given.")
        if not self.authentication_status:
            # Cannot set the username, when client isn't even authenticated yet.
            raise NotAuthenticatedException("Cannot set username, when client isn't authenticated.")
        if len(self.username) > 0:
            # Username has been already set. Client is not allowed to change its username.
            raise CannotChangeWriteOnceValuesException()

        self._username = username

    @property
    def repr_str(self) -> str:
        return f"<{self.client_type}/{self.permission}#{self.username}@{self.client_addr[0]}:{self.client_addr[1]}>"
