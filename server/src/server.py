import os
import sys
import ssl
import time
import socket
import threading
import ipaddress
#
from .client import Client


class Server:

    """The TCP server, which manages the incoming data and passes data to other clients."""

    def __init__(self, config:dict) -> None:
        self.config:dict = config
        self._running:bool = True
        self._server_addr:tuple[str,int]|None = None
        self._max_incoming_connections:int|None = None
        self._server_ssl_certfilepath:str|None = None
        self._server_ssl_keyfilepath:str|None = None
        self._server_ssl_keyfilepassword:str = config['server_ssl_keyfilepassword']
        self._max_msg_chunk_size:int|None = None
        self._socket_buffer_size:int|None = None
        self._clients[Client] = []

        #
        self.server_addr = config['server_addr']
        self.max_incoming_connections = config['max_incoming_connections']
        self.server_ssl_certfilepath = config['server_ssl_certfilepath']
        self.server_ssl_keyfilepath = config['server_ssl_keyfilepath']
        self.max_msg_chunk_size = config['max_msg_chunk_size']
        self.socket_buffer_size = config['socket_buffer_size']
        #
        self.server_socket:socket.socket|None = None
        self.server_ssl_context:ssl.SSLContext|None = None

    @property
    def server_addr(self) -> tuple[str,int]:
        """Returns server listening-address."""

        return self._server_addr

    @server_addr.setter
    def server_addr(self, new_server_addr:tuple[str,int]) -> None:
        """Sets the server listening address."""

        # Check value-type.
        if not isinstance(new_server_addr[0], str):
            raise TypeError("Server Hostname/IP-Address has to be a string")
        if not isinstance(new_server_addr[1], int):
            raise TypeError("Server Port has to be an intenger")

        # Check if given host is a valid IP-Address or hostname.
        if not self.check_host(new_server_addr[0]):
            raise ValueError("Server Hostname/IP-Address is invalid")

        # Check if given port is valid.
        if not self.check_port(new_server_addr[1]):
            raise ValueError("Server Port is invalid")

        # Updates server_address.
        self._server_addr = new_server_addr

    def check_port(self, port:int) -> bool:
        """Check if given port is a valid port-number."""

        if port <= 0 or port > 65535:
            return False

        return True

    def check_host(self, host:str) -> bool:
        """Check if given host is a valid hostname or IP-Address."""

        # Get IP-Address if host is a hostname.
        try:
            ip_addr:str = socket.gethostbyname(host)
        except socket.error as _e:
            return False

        try:
            ipv4_addr = ipaddress.IPv4Address(ip_addr)
            return True
        except ipaddress.AddressValueError as _e:
            # Invalid IPv4-Address. Could be a valid IPv6-Address.
            pass

        try:
            ipv6_addr = ipaddress.IPv6Address(ip_addr)
            return True
        except ipaddress.AddressValueError as _e:
            # Invalid IPv4- & IPv6-Address
            return False

    @property
    def max_incoming_connections(self) -> int:
        """Returns amount of maximum incoming connections that the server accepts."""

        return self._max_incoming_connections

    @max_incoming_connections.setter
    def max_incoming_connections(self, new_max_inc_conns:int) -> None:
        """Sets the value of maximum allowed incoming connections."""

        # Check value-type.
        if not isinstance(new_max_inc_conns, int):
            raise TypeError("The amount of maximum incoming connections has to be an integer.")
        # Check if value is greater than 0.
        if new_max_inc_conns <= 0:
            raise ValueError("The amount of maximum incoming connections has to be larger than 0.")
        # Updates max_incoming_connections-value.
        self._max_incoming_connections = new_max_inc_conns

    @property
    def server_ssl_certfilepath(self) -> str:
        """Returns the server SSL/TLS certfilepath."""

        return self._server_ssl_certfilepath

    @server_ssl_certfilepath.setter
    def server_ssl_certfilepath(self, filepath:str) -> None:
        """Sets the server SSL/TLS filepath of its certificate."""

        # Check if filepath is a string.
        if not isinstance(filepath, str):
            raise TypeError("The SSL/TLS Certfilepath has to be a string.")
        # Check if filepath exists.
        if len(filepath) == 0 or not os.path.exists(filepath) or not os.path.isfile(filepath):
            raise ValueError("The SSL/TLS Certfilepath is invalid.")
        # Update certfilepath.
        self._server_ssl_certfilepath = filepath

    @property
    def server_ssl_keyfilepath(self) -> str:
        """Returns the server SSL/TLS keyfilepath."""

        return self._server_ssl_keyfilepath

    @server_ssl_keyfilepath.setter
    def server_ssl_keyfilepath(self, filepath:str) -> None:
        """Sets the server SSL/TLS filepath of its keyfile."""

        # Check if filepath is a string.
        if not isinstance(filepath, str):
            raise TypeError("The SSL/TLS Keyfilepath has to be a string.")
        # Check if filepath exists.
        if len(filepath) == 0 or not os.path.exists(filepath) or not os.path.isfile(filepath):
            raise ValueError("The SSL/TLS Keyfilepath is invalid.")
        # Update the keyfilepath.
        self._server_ssl_keyfilepath = filepath

    @property
    def server_ssl_keyfilepassword(self) -> str:
        """Returns the server SSL/TLS keyfile-password."""

        return self._server_ssl_keyfilepassword

    @property
    def max_msg_chunk_size(self) -> int:
        """Returns the maximum chunk size of a buffered message."""

        return self._max_msg_chunk_size

    @max_msg_chunk_size.setter
    def max_msg_chunk_size(self, chunk_size:int) -> None:
        """Sets the maximum chunk size of a buffered message."""

        # Check if chunk_size is an integer.
        if not isinstance(chunk_size, int):
            raise TypeError("The maximum chunk size of a buffered message has to be an integer.")
        # Check if value is greater than 0.
        if chunk_size <= 0:
            raise ValueError("The maximum chunk size of a buffered message has to be greater than zero.")
        # Update max_msg_chunk_size.
        self._max_msg_chunk_size = chunk_size

    @property
    def socket_buffer_size(self) -> int:
        """Returns the socket buffer size."""

        return self._socket_buffer_size

    @socket_buffer_size.setter
    def socket_buffer_size(self, buffer_size:int) -> None:
        """Sets the socket buffer size."""

        # Check if buffer_size is an integer.
        if not isinstance(buffer_size, int):
            raise TypeError("The socket buffer-size has to be an integer.")
        # Check if value is greater than 0.
        if buffer_size <= 0:
            raise ValueError("The socket buffer-size has to be greater than zero.")
        # Check if value is smaller than the maximum chunk size.
        # If the chunk-size greater than the buffer_size, no message will be received without buffering, which would result in an infinite loop. See declaration of `recv_msg`.
        if buffer_size < self.max_msg_chunk_size:
            raise ValueError("The socket buffer-size has to be greater than the maximum chunk size of a buffered message.")
        # Update the socket-buffer-size.
        self._socket_buffer_size = buffer_size



    def setup_socket(self) -> bool:
        """Setup the server TCP-socket and SSL/TLS-socket for encrypted communication with the clients."""

        if self.server_socket:
            # Server-Socket does already exist.
            return False

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, prot=0) # IPv4-TCP
            self.server_socket.bind(self.server_addr)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # enable address reuse
            self.server_socket.listen(self.max_incoming_connections)
            # Wrap the TCP-Socket with SSL/TLS.
            self.server_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.server_ssl_context.load_cert_chain(certfile=self.server_ssl_certfilepath, keyfile=self.server_ssl_keyfilepath, password=self.server_ssl_keyfilepassword)
            return True
        except socket.error as _e:
            return False


    def run(self) -> None:
        if not self.setup_socket():
            return

        while self._running:
            try:
                pass
            except socket.error as _e:
                break
            except Exception as _e:
                break

        self.close_all_connections()
        # Close server socket
        self.server_ssl_context.shutdown()
        self.server_socket.close()

    def send_msg(self, client:Client, msg:str) -> bool:
        """Send message to specific client via the encrypted SSL/TLS-Socket."""

        if not client.connection_status:
            return False

        if len(msg) == 0:
            return False

        try:
            if len(msg) > self.max_msg_chunk_size:
                # Begin buffering
                total_message_len_with_flags:int = len(MessageFlag.BEGIN_BUFFERING.value + msg + MessageFlag.END_BUFFERING.value)

                counter:int = 0
                chunk:str = "X"

                while chunk != "":
                    chunk = msg[counter:self.max_msg_chunk_size+counter]
                    if not self.send_msg(client, msg=chunk):
                        raise BufferingError("Couldn't send buffered message to client")

                    counter += self.max_msg_chunk_size

                if not self.send_msg(client, msg=MessageFlag.END_BUFFERING.value):
                    raise BufferError("Couldn't send END-Buffering Message-Flag to client")

                return True

            # Without buffering

            client.ssl_socket.sendall(msg.encode())

            return True

        except BufferingError as _e:
            pass

        except socket.error as _e:
            pass

        except Exception as _e:
            pass

        return False

    def recv_msg(self, client:Client) -> tuple[bool, str|None]:
        """Receive a message from a specific client via the encrypted SSL/TLS-Socket."""

        if not client.connection_status:
            return False

        try:
            package:bytes = client.ssl_socket.recv(self.socket_buffer_size)
            response:str = package.decode()
            # Check if buffering is required
            if MessageFlag.BEGIN_BUFFERING.value in response:
                # Begin buffering
                buffered_resp:str = ""
                current_resp:str = response.split(MessageFlag.BEGIN_BUFFERING.value)[1]
                buffered_resp += current_resp

                while MessageFlag.END_BUFFERING.value not in current_resp:
                    status, current_resp = self.recv_msg(client)
                    if not status:
                        raise BufferingError("Something went wrong while trying to receive a buffered message from the client")

                    if MessageFlag.END_BUFFERING.value in current_resp:
                        buffered_resp += current_resp.split(MessageFlag.END_BUFFERING.value)[1]
                        continue

                    buffered_resp += current_resp

                response = buffered_resp

            return (True, response)

    def client_authentication(self, client:Client) -> None:
        """Authenticate client by credentials."""

        if not client.connection_status:
            # Unreachable ???
            return

        # Waiting for credentials
        (status, response) = self.recv_msg(client)
        if not status:
            raise ClientAuthenticationFailedException("Couldn't receive credentials.")

        # Check if request is valid.
        if not check_if_specific_valid_core_command(response, CoreCommand.AUTHENTICATION_REQUEST):
            raise ClientAuthenticationFailedException("Response from client is not a valid authentication-request.")

        # Parse credentials.
        credentials:str = response.split(CoreCommand.AUTHENTICATION_REQUEST.value.command_str)[1]
        username:str = credentials.split(CoreCommand.AUTHENTICATION_REQUEST.value.params[0][0])[1].split(CoreCommand.AUTHENTICATION_REQUEST.value.params[0][1])[0]
        password:str = credentials.split(CoreCommand.AUTHENTICATION_REQUEST.value.params[1][0])[1].split(CoreCommand.AUTHENTICATION_REQUEST.value.params[1][1])[0]

        # Validate credentials in database and get `client-type` and `client-permission` if credentials are correct.


    def handle_client(self, client:Client) -> None:
        """Handle every incoming client connection inside a separate thread."""
        try:
            self.client_authentication(client)
        except ClientAuthenticationFailedException as _e:
            pass

        while client.connection_status and client.authentication_status:
            try:
                pass
            except Exception as _error:
                break
        self.close_connection_to_client(client)
        self._clients.remove(client)

    def close_connection_to_client(self, client:Client) -> None:
        """Close the connection to a single client."""
        if not client.connection_status:
            # Connection is already closed.
            return

        if not self.send_msg(client, msg=str(ResponseCode.NO_ERROR.value.resp_code)+CoreCommand.CLOSE_CONNECTION.value.command_str):
            # Couldn't send msg to client. Connection could be already closed to client.
            pass

        try:
            client.authentication_status = False
            client.connection_status = False
            client.ssl_socket.shutdown(socket.SHUT_RDWR) # Shutdown SSL layer
            client.tcp_socket.shutdown(socket.SHUT_RDWR) # Shutdown TCP layer
        except Exception as _e:
            pass
        finally:
            client.ssl_socket.close()
            client.tcp_socket.close()

    def close_all_connections(self) -> None:
        if len(self._clients) == 0:
            # No client connected.
            return
        for client in self._clients:
            self.close_connection_to_client(client)
        self._clients.clear()
