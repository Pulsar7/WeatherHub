import os
import ssl
import json
import socket
import getpass
#
from .utils import *
from .config import *
from .constants import *
from .custom_exceptions import *
from .logger import Logger, Console


class Client:

    """TCP/SSL_TLS - Client for the WeatherHub-server."""

    def __init__(self, config:dict) -> None:
        self._config:dict = config
        self._server_address:tuple[str,int]|None = None
        self._server_certificate_filepath:str|None = None
        self._client_certificate_filepath:str|None = None
        self._client_keyfile_path:str|None = None
        self._client_keyfile_password:str|None = None
        self._client_username:str|None = None
        self._client_password:str|None = None
        self._max_msg_chunk_size:int|None = None
        self._buffer_size:int|None = None
        self._responsecode_separator:str|None = None

        self._authentication_staus:bool = False
        self._connection_status:bool = False
        self._client_commands:dict = {}

        #
        self.server_address = config['server_addr']
        self.server_certificate_filepath = config['server_certificate_filepath']
        self.client_certificate_filepath = config['client_certificate_filepath']
        self.client_keyfile_path = config['client_keyfile_path']
        self.client_keyfile_password = config['client_keyfile_password']
        self.client_username = config['client_username']
        self.client_password = config['client_password']
        self.max_msg_chunk_size = config['default_max_msg_chunk_size']
        self.buffer_size = config['default_buffer_size']
        self.responsecode_separator = config['responsecode_separator']
        self.client_tcp_socket:socket.socket|None = None
        self.client_ssl_socket:ssl.SSLSocket|None = None
        self.logger:Logger = Logger(__class__.__name__)

    @property
    def server_address(self) -> tuple[str,int]:
        """Get the Server-host and port."""
        return self._server_address

    @server_address.setter
    def server_address(self, new_server_addr:tuple[str,int]) -> None:
        if self._connection_status:
            raise ClientAlreadyConnectedError()

        if not isinstance(new_server_addr, tuple) or not isinstance(new_server_addr[0], str) or not isinstance(new_server_addr[1], int) or len(new_server_addr) != 2:
            raise TypeError("The server-address has to be a tuple[str,int]")

        if not check_host(new_server_addr[0]):
            raise ValueError("The server-host/IP-Address is invalid.")

        if not check_port(new_server_addr[1]):
            raise ValueError("The server-port is invalid.")

        self._server_address = new_server_addr

    @property
    def server_certificate_filepath(self) -> str:
        """Get the filepath to the trusted server-certificate."""
        return self._server_certificate_filepath

    @server_certificate_filepath.setter
    def server_certificate_filepath(self, filepath:str) -> None:
        """Set the filepath to the trusted server-certificate."""

        if self._connection_status:
            raise ClientAlreadyConnectedError()

        if not isinstance(filepath, str):
            raise TypeError("The server-certificate-filepath has to be a string.")

        if len(filepath) == 0 or not os.path.exists(filepath) or not os.path.isfile(filepath):
            raise ValueError("The server-certificate-filepath is invalid.")

        self._server_certificate_filepath = filepath

    @property
    def client_certificate_filepath(self) -> str:
        """Get the client SSL/TLS-certificate filepath."""
        return self._client_certificate_filepath

    @client_certificate_filepath.setter
    def client_certificate_filepath(self, filepath:str) -> None:
        """Set the filepath to the client SSL/TLS-certificate."""

        if self._connection_status:
            raise ClientAlreadyConnectedError()

        if not isinstance(filepath, str):
            raise TypeError("The client-certificate-filepath has to be a string.")

        if len(filepath) == 0 or not os.path.exists(filepath) or not os.path.isfile(filepath):
            raise ValueError("The client-certificate-filepath is invalid.")

        self._client_certificate_filepath = filepath

    @property
    def client_keyfile_path(self) -> str:
        """Get the path to the client-keyfile."""
        return self._client_keyfile_path

    @client_keyfile_path.setter
    def client_keyfile_path(self, filepath:str) -> None:
        """Set the filepath to the client keyfile."""

        if self._connection_status:
            raise ClientAlreadyConnectedError()

        if not isinstance(filepath, str):
            raise TypeError("The client-keyfile-path has to be a string.")

        if len(filepath) == 0 or not os.path.exists(filepath) or not os.path.isfile(filepath):
            raise ValueError("The client-keyfile-path is invalid.")

        self._client_keyfile_path = filepath

    @property
    def client_keyfile_password(self) -> str:
        """Get the encryption-password of client's keyfile."""
        return self._client_keyfile_password

    @client_keyfile_password.setter
    def client_keyfile_password(self, password:str) -> None:
        """Get the encryption-password of client's keyfile."""

        if self._connection_status:
            raise ClientAlreadyConnectedError()

        if not isinstance(password, str):
            raise TypeError("The keyfile-password has to be a string.")

        if len(password) == 0:
            raise ValueError("The keyfile-password can't be empty.")

        self._client_keyfile_password = password

    @property
    def client_username(self) -> str:
        """Get the client's username."""
        return self._client_username

    @client_username.setter
    def client_username(self, username:str) -> None:
        """Set client's username."""

        if self._connection_status:
            raise ClientAlreadyConnectedError()

        if not isinstance(username, str):
            raise TypeError("The username has to be a string.")

        if len(username) == 0:
            raise ValueError("The username can't be empty.")

        self._client_username = username

    @property
    def client_password(self) -> str:
        """Get client's password."""
        return self._client_password

    @client_password.setter
    def client_password(self, password:str) -> None:
        """Get client's password."""

        if self._connection_status:
            raise ClientAlreadyConnectedError()

        if not isinstance(password, str):
            raise TypeError("The password has to be a string.")

        if len(password) == 0:
            raise ValueError("The password can't be empty.")

        self._client_password = password

    @property
    def max_msg_chunk_size(self) -> int:
        """Get the maximum size of a chunk."""
        return self._max_msg_chunk_size

    @max_msg_chunk_size.setter
    def max_msg_chunk_size(self, size:int) -> None:
        """Set the maximum size of a chunk."""

        if not isinstance(size, int):
            raise TypeError("The chunk-size has to be an integer.")

        if size <= 0 or (self.buffer_size and size > self.buffer_size):
            raise ValueError("The chunk-size cannot be zero or greater than the buffer-size.")

        self._max_msg_chunk_size = size

    @property
    def buffer_size(self) -> int:
        """Get the socket-buffer-size."""
        return self._buffer_size

    @buffer_size.setter
    def buffer_size(self, size:int) -> None:
        """Set the socket-buffer-size."""

        if not isinstance(size, int):
            raise TypeError("The buffer-size has to be an integer.")

        if size <= 0 or (self.max_msg_chunk_size and size < self.max_msg_chunk_size):
            raise ValueError("The buffer-size cannot be zero or smaller than the maxmimum message chunk-size.")

        self._buffer_size = size

    @property
    def responsecode_separator(self) -> str:
        """Get the separator between the response-code and the actual message."""
        return self._responsecode_separator

    @responsecode_separator.setter
    def responsecode_separator(self, separator:str) -> None:
        """Set the separator between the response-code and the actual message."""

        if not isinstance(separator, str):
            raise TypeError("The response-code-separator has to be a string.")

        if len(separator) == 0 or self.max_msg_chunk_size < len(separator):
            raise ValueError("The response-code-separator can't be empty and it can't be longer than the maximum mesage chunk-size.")

        self._responsecode_separator = separator

    def establish_secure_connection(self) -> ssl.SSLSocket|None:
        """Establish a secure SSL/TLS-Connection to the server with the trusted certificate of the server."""

        self.logger.info(f"Establishing connection to server {self.server_address}", progress=True)

        try:
            self.client_tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # IPv4-TCP
            # Create an SSL context for client-side communication
            client_ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            # Load the CA certificate(s) that the client will trust
            client_ssl_context.load_verify_locations(cafile=self.server_certificate_filepath)
            # Load client certificate and key
            client_ssl_context.load_cert_chain(certfile=self.client_certificate_filepath, keyfile=self.client_keyfile_path, password=self.client_keyfile_password)
            # Verify the server certificate
            client_ssl_context.verify_mode = ssl.CERT_REQUIRED
            # Establish TCP connection
            self.client_tcp_socket.connect(self.server_address)
            # Wrap the client socket with SSL/TLS
            client_ssl_socket = client_ssl_context.wrap_socket(self.client_tcp_socket, server_hostname=socket.gethostbyaddr(self.server_address[0])[0])
            self.logger.info(f"SSL established. Peer: {client_ssl_socket.getpeercert()}")
            self._connection_status = True
            return client_ssl_socket
        except (socket.error, ssl.SSLError) as _e:
            self.logger.error(f"Couldn't connect to the server: {_e}")
        except Exception as _e:
            self.logger.error(f"An unexpected error occured while trying to connect to the server: {_e}")
        return None

    def run(self) -> None:
        self.logger.info("Client is running.")

        client_ssl_socket:ssl.SSLSocket|None = self.establish_secure_connection()
        if not client_ssl_socket:
            self.logger.error("Couldn't establish a connection to the server.")
            return
        self.client_ssl_socket = client_ssl_socket

        if self.connection_configuration():
            if self.pwd_authentication_process():
                if self.get_client_commands():
                    self.logger.info("Type `help` to see the available client-commands.")
                    self.logger.info("Press `CTRL+C` or type `close` or `exit` to close the connection.")
                    while self._connection_status:
                        try:
                            user_input:str = input(f"{self.client_username}@{self.server_address[0]}:{self.server_address[1]}$> ")
                            # Process user-input
                            user_input = user_input.strip().replace(" ", "")
                            if any(close_option in user_input.lower() for close_option in ["close","exit"]):
                                # User wants to close the connection.
                                self.logger.info("Closing connection to server.")
                                break

                            if any(help_option in user_input.lower() for help_option in ["help"]):
                                # Printout Client commands.
                                Console().print(self._client_commands)
                                continue

                            if len(user_input) == 0:
                                continue

                            resp_for_server:str|None = self.handle_possible_client_commands(user_input)

                            if resp_for_server:
                                user_input = resp_for_server

                            if not self.send_msg(user_input):
                                self.logger.error("Couldn't send user-input to server!")

                            (status, (resp_msg, resp_code)) = self.recv_msg()
                            if not status:
                                self.logger.error("Couldn't receive a response from the server!")
                                continue

                            self.logger.info(f"<SERVER> ({resp_code.value.description}) {resp_msg}")

                            if resp_msg == CoreCommand.CLOSE_CONNECTION.value.command_str:
                                # Server wants to close connection.
                                self.logger.warning("Server wants to close connection.")
                                break

                            if resp_code == ResponseCode.FORCE_CONNECTION_CLOSURE:
                                # Server is forcing client to close the connection.
                                self.logger.warning("Server is forcing client to re-connect.")
                                break

                        except KeyboardInterrupt as _e:
                            print("\n")
                            self.logger.warning("Detected keyboard-interruption")
                            break
                        except Exception as _e:
                            self.logger.error(f"An unexpected error occured: {_e}")
                            break
                else:
                    self.logger.error("Couldn't get Client-Commands.")
            else:
                self.logger.error("Cannot proceed without being authenticated.")
        else:
            self.logger.error("Connection configuration failed. Cannot proceed.")

        if self.send_msg(CoreCommand.CLOSE_CONNECTION.value.command_str):
            # Connection is still up and running
            # Graceful stop.
            (status, response) = self.recv_msg()
            if status:
                if response[0] == CoreCommand.CLOSE_CONNECTION.value.command_str:
                    self.logger.info("Received a CLOSE-CONNECTION-response from the server.")

        if self.client_tcp_socket:
            self.client_tcp_socket.close()

        if self.client_ssl_socket:
            self.client_ssl_socket.close()


    def handle_possible_client_commands(self, user_input:str) -> str|None:
        """Handle possible client commands in the user-input."""

        if len(user_input) == 0:
            return None

        selected_command:str|None = None

        for client_command in self._client_commands:
            if user_input.lower() in client_command.lower():
                # Valid command.
                selected_command = client_command
                break

        if not selected_command:
            # User input isn't a known client-command.
            return False

        response_for_server:str = f"{selected_command}"
        self.logger.info(f"Selected command: {selected_command}")
        if len(self._client_commands[selected_command]['params']) == 0:
            return response_for_server
        for param in self._client_commands[selected_command]['params']:
            try:
                if any(key in param[0].lower() for key in ["password"]):
                    param_value:str = getpass.getpass(f"{param[0]}> ")
                else:
                    param_value:str = input(f"{param[0]}> ")
                response_for_server += f"{param[0]}{param_value}{param[1]}"
            except KeyboardInterrupt as _e:
                self.logger.warning(f"Detected a keyboard-interruption.")
                return None
            except Exception as _e:
                self.logger.error("An unexpected error occured while trying to get paramters")
                return None

        return response_for_server

    def get_client_commands(self) -> bool:
        """Get Client-Commannds from server."""

        self.logger.info(f"Getting client-commands from server", progress=True)

        if not self._connection_status:
            self.logger.error("Something went wrong. Cannot ask for client-commands via a closed connection.")
            return False

        if not self._authentication_status:
            self.logger.error("Something went wrong. Cannot ask for client-commands, when client isn't authenticated.")
            return False

        # Send request
        if not self.send_msg(msg=ClientCommand.GET_CLIENT_COMMANDS.value.command_str):
            self.logger.error("Couldn't ask for client-commands at server.")
            return False

        # Wait for response
        (status, response) = self.recv_msg()
        if not status:
            self.logger.error("Couldn't receive client-commands from server.")
            return False

        if response[1] != ResponseCode.NO_ERROR:
            self.logger.error(f"Couldn't receive client-commands from server due to ResponseCode-Error: {response[1]}")
            return False

        # Get help-dicitionary.
        try:
            help_string:str = response[0]
            help_dict:dict = json.loads(help_string)
            self._client_commands = help_dict
            self.logger.info(f"Received {len(self._client_commands.keys())} client-commands.")
            return True
        except Exception as _e:
            self.logger.error(f"An unexpected error occured while trying to get help-dictionary: {_e}")
            return False


    def connection_configuration(self) -> bool:
        """Receive connection-configuration string and update buffer_size + max_chunk_size."""

        self.logger.info(f"Current & default connection configuration: buffer_size={self.buffer_size} | max_msg_chunk_size={self.max_msg_chunk_size}")
        self.logger.info("Receiving connection-configuration-string from server", progress=True)

        (status, response) = self.recv_msg()
        if not status:
            self.logger.error("Couldn't receive the connection-configuration-string from the server.")
            return False

        if response[1] != ResponseCode.NO_ERROR:
            self.logger.error(f"Received an ResponseCode-Error: '{response[1]}'")
            return False

        try:
            new_buffer_size:int = int(response[0].split("<BUFFER_SIZE>")[1].split("</BUFFER_SIZE")[0])
            new_max_msg_chunk_size:int = int(response[0].split("<MAX_MSG_CHUNK_SIZE>")[1].split("</MAX_MSG_CHUNK_SIZE>")[0])
        except ValueError as _e:
            self.logger.error(f"Received an invalid connection-configuration-string from the server: `{response[0]}`")
            return False

        try:
            self.buffer_size = new_buffer_size
            self.max_msg_chunk_size = new_max_msg_chunk_size
        except ValueError as _e:
            self.logger.error(f"Received an invalid connection-configuration-string from the server: `{response[0]}` -> {_e}")
            return False

        self.logger.info("Updated connection-configurations.")
        self.logger.info(f"«Connection-Configuration» Buffer-Size={self.buffer_size} | Max-Msg-Chunk-Size={self.max_msg_chunk_size}")

        return True

    def pwd_authentication_process(self) -> bool:
        """Password authentication-process for User-Authentication."""

        core_command:CoreCommand = CoreCommand.AUTHENTICATION_REQUEST
        auth_request_msg:str = core_command.value.command_str

        # Add username
        auth_request_msg += core_command.value.params[0][0]+self.client_username+core_command.value.params[0][1]
        # Add password
        auth_request_msg += core_command.value.params[1][0]+self.client_password+core_command.value.params[1][1]

        if not self.send_msg(auth_request_msg):
            self.logger.error("Couldn't send authentication-request-message to server.")
            return False

        (status, response) = self.recv_msg()
        if not status:
            self.logger.error("Couldn't receive authentication-response from server.")
            return False

        if response[1] == ResponseCode.AUTHENTICATION_SUCCESSFUL:
            self.logger.info("Received an AUTHENTICATION-SUCCESSFUL-response from the server.")
            self._authentication_status = True
            return True

        self.logger.error(f"Received an ResponseCode-Error from the server: {response[1]}")
        return False


    def send_msg(self, msg:str, response_code:ResponseCode=ResponseCode.NO_ERROR) -> bool:
        """Send message to the server via the encrypted SSL/TLS-Socket."""

        if not self._connection_status:
            # Cannot send messages to a closed connection.
            self.logger.error(f"Cannot send a message to a closed connection.")
            return False

        if not isinstance(response_code, ResponseCode):
            self.logger.error(f"The response-code '{resp_code}' is invalid. Cannot send message to server.")
            return False

        resp_code_msg_part:str = str(response_code.value.resp_code)

        if resp_code_msg_part not in msg:
            msg = resp_code_msg_part+self.responsecode_separator+msg

        if len(msg) == 0:
            self.logger.warning(f"Attempted to send an empty message to the server.")
            return False

        try:
            if len(msg) > self.max_msg_chunk_size:
                # Begin buffering
                # Sending Begin-Buffering-Flag
                if not self.send_msg(MessageFlag.BEGIN_BUFFERING.value):
                    raise BufferError("Couldn't send BEGIN-Buffering Message-Flag to server.")
                # Iterate message.
                counter:int = 0
                chunk:str = "X"

                while chunk != "":
                    chunk = msg[counter:self.max_msg_chunk_size+counter]
                    if not self.send_msg(msg=chunk):
                        raise BufferingError("Couldn't send buffered message to client")

                    counter += self.max_msg_chunk_size

                if not self.send_msg(msg=MessageFlag.END_BUFFERING.value):
                    raise BufferError("Couldn't send END-Buffering Message-Flag to server")

                return True

            # Without buffering

            self.client_ssl_socket.sendall(msg.encode())

            return True

        except BufferingError as _e:
            self.logger.error(f"An error occured while trying to send a buffered message to the server: {_e}")

        except socket.error as _e:
            self.logger.error(f"A socket-error occured while trying to send a message to the server: {_e}")

        except Exception as _e:
            self.logger.error(f"An unexcepted exception occured while trying to send a message to the server: {_e}")

        return False


    def recv_msg(self) -> tuple[bool, tuple[str, ResponseCode]|None]:
        """Receive a message from the server via the encrypted SSL/TLS-Socket."""

        if not self._connection_status:
            # Cannot receive messages from a closed connection.
            self.logger.error(f"Cannot receive a message from a closed connection.")
            return False

        try:
            package:bytes = self.client_ssl_socket.recv(self.buffer_size)
            response:str = package.decode()

            # Check if buffering is required
            if MessageFlag.BEGIN_BUFFERING.value in response:
                # Begin buffering
                buffered_resp:str = ""
                current_resp:str = response.split(MessageFlag.BEGIN_BUFFERING.value)[1]
                buffered_resp += current_resp

                while MessageFlag.END_BUFFERING.value not in current_resp:
                    status, resp = self.recv_msg()
                    if not status:
                        raise BufferingError("Something went wrong while trying to receive a buffered message from the server.")

                    current_resp = resp[0] # response-msg

                    if MessageFlag.END_BUFFERING.value in current_resp:
                        buffered_resp += current_resp.split(MessageFlag.END_BUFFERING.value)[1]
                        continue

                    buffered_resp += current_resp

                response = buffered_resp

            # Split response from response_code.
            if self.responsecode_separator in response:
                args:list[str] = response.split(self.responsecode_separator)
                response_msg = args[1]
                response_code = get_response_code_by_value(args[0])
                if not response_code:
                    # Server sent an invalid response-code.
                    # Assuming no error.
                    response_code = ResponseCode.NO_ERROR
            else:
                # Server sent no response-code.
                # Assuming no error.
                response_code = ResponseCode.NO_ERROR
                response_msg = response

            return (True, (response_msg, response_code))

        except BufferingError as _e:
            self.logger.error(f"A buffering-error occured while receiving a message from the server: {_e}")

        except socket.error as _e:
            self.logger.error(f"A socket-error occured while receiving a message from the server: {_e}")

        except Exception as _e:
            self.logger.error(f"An unexpected error occured while receiving a message from the server: {_e}")

        return (False,None)

