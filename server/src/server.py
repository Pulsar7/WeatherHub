import os
import sys
import ssl
import time
import socket
import logging
import threading
#
from .utils import *
from .constants import *
from .client import Client
from .custom_exceptions import *
from .database.utils import create_user, authenticate_user


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
        self._responsecode_separator:str|None = None
        self._clients:list[Client] = []

        #
        self.server_addr = config['server_addr']
        self.max_incoming_connections = config['max_incoming_connections']
        self.server_ssl_certfilepath = config['server_ssl_certfilepath']
        self.server_ssl_keyfilepath = config['server_ssl_keyfilepath']
        self.max_msg_chunk_size = config['max_msg_chunk_size']
        self.socket_buffer_size = config['socket_buffer_size']
        self.responsecode_separator = config['responsecode_separator']
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
        if not check_host(new_server_addr[0]):
            raise ValueError("Server Hostname/IP-Address is invalid")

        # Check if given port is valid.
        if not check_port(new_server_addr[1]):
            raise ValueError("Server Port is invalid")

        # Updates server_address.
        self._server_addr = new_server_addr

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

    @property
    def responsecode_separator(self) -> str:
        """Returns the seperator of the response-code and the actual message."""
        return self._responsecode_separator

    @responsecode_separator.setter
    def responsecode_separator(self, separator:str) -> None:
        """Sets the separator of the response-code and the actual message."""

        if not isinstance(separator, str):
            raise TypeError("The response-code separator has to be a string.")

        if len(separator) == 0:
            raise ValueError("The response-code separator can't be empty.")

        if self.responsecode_separator:
            raise CannotChangeWriteOnceValuesException()

        self._responsecode_separator = separator

    def setup_socket(self) -> bool:
        """Setup the server TCP-socket and SSL/TLS-socket for encrypted communication with the clients."""

        if self.server_socket:
            # Server-Socket does already exist.
            logging.warning("Attempted to overwrite current server-socket")
            return False

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=0) # IPv4-TCP
            self.server_socket.bind(self.server_addr)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # enable address reuse
            self.server_socket.listen(self.max_incoming_connections)
            # Wrap the TCP-Socket with SSL/TLS.
            self.server_ssl_context:ssl.SSLContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.server_ssl_context.load_cert_chain(certfile=self.server_ssl_certfilepath, keyfile=self.server_ssl_keyfilepath, password=self.server_ssl_keyfilepassword)
            return True
        except (socket.error, IOError, ssl.SSLError) as _e:
            logging.error(f"Couldn't setup server-socket: {_e}")
            return False

    def get_connection_config_string(self) -> str:
        """Get configuration-string for new incoming connections."""

        return f"<BUFFER_SIZE>{self.socket_buffer_size}</BUFFER_SIZE><MAX_MSG_CHUNK_SIZE>{self.max_msg_chunk_size}</MAX_MSG_CHUNK_SIZE>"

    def run(self) -> None:
        if not self.setup_socket():
            logging.critical("Couldn't setup server-socket. Cannot start.")
            return

        logging.info(f"Server socket has been created. Server is now listening on {self.server_addr}")

        while self._running:
            try:
                (client_socket, client_addr) = self.server_socket.accept()

                logging.info(f"New incoming connection {client_addr}")

                try:
                    # Wrap the client socket with SSL/TLS
                    secure_client_socket:ssl.SSLSocket = self.server_ssl_context.wrap_socket(client_socket, server_side=True)

                    # Create client-object and start a new thread.
                    client:Client = Client(client_socket=client_socket, ssl_socket=secure_client_socket, client_addr=client_addr)
                    client_thread = threading.Thread(target=self.handle_client, args=(client,), daemon=True)
                    # Client thread is a daemon-thread to ensure, that when the main-process exits, the thread will automatically be killed.
                    client_thread.start()

                    self._clients.append(client)
                except ssl.SSLError as _e:
                    logging.error(f"{client_addr}> SSL-Handshake with client failed: {_e}")
                    client_socket.close()
                    logging.warning(f"{client_addr}> Closed connection to client.")
                    continue
            except socket.error as _e:
                logging.critical(f"A socket-error occured: {_e}")
                break

            except KeyboardInterrupt as _e:
                logging.warning("Detected a keyboard-interruption. Closing server.")
                break

            except Exception as _e:
                logging.critical(f"An unexpected exception occured: {_e}")
                break

        self.close_all_connections()
        # Close server socket
        try:
            self.server_socket.close()
        except socket.error as _e:
            logging.error(f"<Socket-Error> {_e}")

    def send_msg(self, client:Client, msg:str, response_code:ResponseCode=ResponseCode.NO_ERROR) -> bool:
        """Send message to specific client via the encrypted SSL/TLS-Socket."""

        if not client.connection_status:
            # Cannot send messages to a closed connection.
            logging.error(f"{client.repr_str} Cannot send a message to a closed connection.")
            return False

        if not isinstance(response_code, ResponseCode):
            logging.error(f"{client.repr_str} The response-code '{resp_code}' is invalid. Cannot send message to client.")
            return False

        msg = str(response_code.value.resp_code)+self.responsecode_separator+msg

        logging.debug(f"{client.repr_str} Message to send: {msg}")

        if len(msg) == 0:
            logging.warning(f"{client.repr_str} Attempted to send an empty message to the client.")
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
            logging.error(f"{client.repr_str} An error occured while trying to send a buffered message to the client: {_e}")

        except socket.error as _e:
            logging.error(f"{client.repr_str} A socket-error occured while trying to send a message to the client: {_e}")

        except Exception as _e:
            logging.error(f"{client.repr_str} An unexcepted exception occured while trying to send a message to the client: {_e}")

        return False

    def recv_msg(self, client:Client) -> tuple[bool, tuple[str, ResponseCode]|None]:
        """Receive a message from a specific client via the encrypted SSL/TLS-Socket."""

        if not client.connection_status:
            # Cannot receive messages from a closed connection.
            logging.error(f"{client.repr_str} Cannot receive a message from a closed connection.")
            return False

        try:
            package:bytes = client.ssl_socket.recv(self.socket_buffer_size)
            response:str = package.decode()
            # Check if buffering is required
            if MessageFlag.BEGIN_BUFFERING.value in response:
                logging.debug(f"{client.repr_str} Received BEGIN_BUFFERING-Flag from client.")
                # Begin buffering
                buffered_resp:str = ""
                current_resp:str = response.split(MessageFlag.BEGIN_BUFFERING.value)[1]
                buffered_resp += current_resp

                while MessageFlag.END_BUFFERING.value not in current_resp:
                    status, resp = self.recv_msg(client)
                    if not status:
                        raise BufferingError("Something went wrong while trying to receive a buffered message from the client")

                    current_resp = resp[0] # response-msg

                    if MessageFlag.END_BUFFERING.value in current_resp:
                        buffered_resp += current_resp.split(MessageFlag.END_BUFFERING.value)[1]
                        logging.debug(f"{client.repr_str} Received END_BUFFERING-Flag from client.")

                        continue

                    buffered_resp += current_resp

                response = buffered_resp

            # Split response from response_code.
            if self.responsecode_separator in response:
                args:list[str] = response.split(self.responsecode_separator)
                response_msg = args[1]
                response_code = get_response_code_by_value(args[0])
                if not response_code:
                    # Client sent an invalid response-code.
                    # Assuming no error.
                    response_code = ResponseCode.NO_ERROR
            else:
                # Client sent no response-code.
                # Assuming no error.
                response_code = ResponseCode.NO_ERROR
                reponse_msg = response

            return (True, (response_msg, response_code))

        except BufferingError as _e:
            logging.error(f"{client.repr_str} A buffering-error occured while receiving a message from the client: {_e}")

        except socket.error as _e:
            logging.error(f"{client.repr_str} A socket-error occured while receiving a message from the client: {_e}")

        except Exception as _e:
            logging.error(f"{client.repr_str} An unexpected error occured while receiving a message from the client: {_e}")

        return (False,None)

    def client_authentication(self, client:Client) -> None:
        """Authenticate client by credentials."""

        if not client.connection_status:
            # Unreachable ???
            logging.error(f"{client.repr_str} Cannot authenticate client with a closed connection.")
            return

        # Waiting for credentials.
        (status, resp) = self.recv_msg(client)
        if not status:
            raise ClientAuthenticationFailedException("Couldn't receive credentials.")

        response:str = resp[0] # response-msg

        logging.debug(f"{client.repr_str} Received credentials from client.")

        # Check if request is valid.
        if not check_if_specific_valid_core_command(response, CoreCommand.AUTHENTICATION_REQUEST):
            self.send_msg(client, "", ResponseCode.INVALID_ARGUMENTS_ERROR)
            raise ClientAuthenticationFailedException("Response from client is not a valid authentication-request.")

        logging.debug(f"{client.repr_str} Received credentials-request is valid.")

        # Parse credentials.
        credentials:str = response.split(CoreCommand.AUTHENTICATION_REQUEST.value.command_str)[1]
        username:str = credentials.split(CoreCommand.AUTHENTICATION_REQUEST.value.params[0][0])[1].split(CoreCommand.AUTHENTICATION_REQUEST.value.params[0][1])[0]
        password:str = credentials.split(CoreCommand.AUTHENTICATION_REQUEST.value.params[1][0])[1].split(CoreCommand.AUTHENTICATION_REQUEST.value.params[1][1])[0]

        logging.debug(f"{client.repr_str} Parsed received credentials 'username' & 'password'")

        # Validate credentials in database and get `client-type` and `client-permission` if credentials are correct.
        if not authenticate_user(username, password):
            logging.error("{client.repr_str} Given credentials are wrong.")
            self.send_msg(client, "", ResponseCode.INVALID_CREDENTIALS_ERROR)
            raise ClientAuthenticationFailedException()

        client.username = username

    def handle_client(self, client:Client) -> None:
        """Handle every incoming client connection inside a separate thread."""

        try:
            # Sending client the connection-configuration-string.
            if not self.send_msg(client, msg=self.get_connection_config_string()):
                raise CannotSendConnectionConfigError()
            # User-Authentication
            self.client_authentication(client)
            user_data = get_user_by_username(client.username)

            if not user_data:
                logging.critical(f"{client.repr_str} Something went wrong. Client is authenticated, but database couldn't get user-data.")
                self.send_msg(client, "", ResponseCode.DATABASE_ERROR) # Send client a database-error-response
                raise ClientAuthenticationFailedException()

            client.authentication_status = True
            client.client_type = user_data.client_type # Change from UNKNOWN to its real client-type.
            client.permission = user_data.client_permission # Change from UNKNOWN to its real permission-type.

            logging.info(f"{client.repr_str} Client has been authenticated successfully.")
        except CannotSendConnectionConfigError as _e:
            # Connection-configuration failed.
            logging.error(f"{client.repr_str} {_e}")
        except ClientAuthenticationFailedException as _e:
            # Authentication-status of client is still False.
            logging.error(f"{client.repr_str} Client authentication failed. Closing connection to client.")

        error_counter:int = 0

        while client.connection_status and client.authentication_status:
            try:
                if error_counter >= 3:
                    raise Exception("Error counter exceeded 3.")

                status, client_resp = self.recv_msg(client)
                if not status:
                    error_counter += 1
                    logging.error(f"{client.repr_str} Couldn't get response from client.")
                    continue

                client_msg:str = client_resp[0] # response-msg
                response:str = ""
                response_code:ResponseCode = ResponseCode.NO_ERROR

                # Check if command is a valid command.
                if check_if_valid_command(client_msg):
                    logging.warning("{client.repr_str} Response-string from client is not a valid command.")
                    response_code = ResponseCode.UNKNOWN_COMMAND_ERROR

                    if check_if_specific_valid_core_command(client_msg, CoreCommand.CLOSE_CONNECTION):
                        # Client wants to close connection.
                        logging.info(f"{client.repr_str} Received close-connection-command from client.")
                        break

                    if client.client_type == ClientType.WEATHER_STATION:
                        # Client is a weather-station.
                        (response, response_code) = handle_weather_station_command(client, client_msg)
                        

                if not self.send_msg(client, msg=response, response_code=response_code):
                    error_counter += 1

            except Exception as _error:
                logging.error(f"{client.repr_str} An unexpected exception occured while handling client: {_error}")
                break

        self.close_connection_to_client(client)
        self._clients.remove(client)
        logging.info(f"{client.repr_str} Closed connection to client.")

    def handle_weather_station_command(self, client:Client, client_msg:str) -> tuple[str, ResponseCode]:
        """Handle weather station commands."""

        response:str = ""
        response_code:ResponseCode = ResponseCode.NO_ERROR

        if check_if_specific_valid_client_command(client_msg, CoreCommand.SEND_WEATHER_REPORT):
            # Weather-station wants to send weather-data.
            if client.permission >= ClientCommand.SEND_WEATHER_REPORT.value.client_permission:
                # Client has sufficient permissions.
                # Get metadata.
                command_params:tuple = ClientCommand.SEND_WEATHER_REPORT.value.params
                metadata_location:str = client_msg.split(command_params[0][0])[1].split(command_params[0][1])[0]
                metadata_timestamp:str = client_msg.split(command_params[1][0])[1].split(command_params[1][1])[0]

            else:
                response_code = ResponseCode.NOT_ALLOWED_COMMAND_ERROR
        else:
            response_code = ResponseCode.NOT_ALLOWED_COMMAND_ERROR

        return (response, response_code)

    def close_connection_to_client(self, client:Client) -> None:
        """Close the connection to a single client."""

        if not client.connection_status:
            # Connection is already closed.
            logging.warning(f"{client.repr_str} Cannot close connection to a connection which is already closed.")
            return

        if not self.send_msg(client, msg=CoreCommand.CLOSE_CONNECTION.value.command_str):
            # Couldn't send msg to client. Connection could be already closed to client.
            logging.error(f"{client.repr_str} Couldn't send CLOSE_CONNECTION-command to client. Connection could be closed already.")

        try:
            if client.authentication_status:
                client.authentication_status = False
            client.connection_status = False

            if client.ssl_socket:
                try:
                    client.ssl_socket.shutdown(socket.SHUT_RDWR) # Shutdown SSL layer
                except (socket.error, OSError) as ssl_e:
                    logging.warning(f"{client.repr_str} Could not shut down SSL socket: {ssl_e}")

            if client.tcp_socket:
                try:
                    client.tcp_socket.shutdown(socket.SHUT_RDWR) # Shutdown TCP layer
                except (socket.error, OSError) as tcp_e:
                    logging.warning(f"{client.repr_str} Could not shut down TCP socket: {tcp_e}")
        except Exception as _e:
            logging.error(f"{client.repr_str} An unexpected exception occured while trying to close connection to the client: {_e}")
        finally:
            # Ensure the SSL socket is closed
            if client.ssl_socket:
                try:
                    client.ssl_socket.close()
                except (socket.error, OSError) as ssl_close_e:
                    logging.warning(f"{client.repr_str} Error closing SSL socket: {ssl_close_e}")
            else:
                logging.debug(f"{client.repr_str} SSL socket already closed or invalid.")

            # Ensure the TCP socket is closed
            if client.tcp_socket:
                try:
                    client.tcp_socket.close()
                except (socket.error, OSError) as tcp_close_e:
                    logging.warning(f"{client.repr_str} Error closing TCP socket: {tcp_close_e}")
            else:
                logging.debug(f"{client.repr_str} TCP socket already closed or invalid.")

            logging.debug(f"{client.repr_str} Closed client sockets.")

    def close_all_connections(self) -> None:
        if len(self._clients) == 0:
            # No client connected.
            logging.info("No client connected. No connection to close.")
            return
        # Iterate through list of connected clients.
        for client in self._clients:
            self.close_connection_to_client(client)
        # Clear whole clients-list.
        self._clients.clear()
        logging.debug("Cleared whole clients-list.")

