import os
import sys
import ssl
import json
import time
import socket
import logging
import threading
import traceback
#
from .utils import *
from .constants import *
from .client import Client
from .custom_exceptions import *
import src.database.utils as db_utils
from src.database.models import User, Station, Measurement


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
            # Force the context to only use TLSv1.3
            self.server_ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
            self.server_ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
            # Load certificate and keyfile.
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

        resp_code_msg_part:str = str(response_code.value.resp_code)

        if resp_code_msg_part not in msg:
            msg = resp_code_msg_part+self.responsecode_separator+msg

        if len(msg) == 0:
            logging.warning(f"{client.repr_str} Attempted to send an empty message to the client.")
            return False

        try:
            if len(msg) > self.max_msg_chunk_size:
                # Begin buffering
                # Sending Begin-Buffering-Flag
                if not self.send_msg(client, MessageFlag.BEGIN_BUFFERING.value):
                    raise BufferError("Couldn't send BEGIN-Buffering Message-Flag to client.")
                # Iterate message.
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
                response_msg = response

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
        if not db_utils.authenticate_user(username, password):
            logging.error("{client.repr_str} Given credentials are wrong.")
            self.send_msg(client, "", ResponseCode.INVALID_CREDENTIALS_ERROR)
            raise ClientAuthenticationFailedException()

        client.authentication_status = True
        client.username = username

    def handle_client(self, client:Client) -> None:
        """Handle every incoming client connection inside a separate thread."""

        logging.info(f"{client.repr_str} The negotiated SSL-Version: {client.ssl_socket.version()}")

        try:
            # Sending client the connection-configuration-string.
            if not self.send_msg(client, msg=self.get_connection_config_string()):
                raise CannotSendConnectionConfigError()

            logging.debug(f"{client.repr_str} Sent client the client the connection-configurations")

            # User-Authentication
            self.client_authentication(client)
            user_data = db_utils.get_user_by_username(client.username)

            if not user_data:
                logging.critical(f"{client.repr_str} Something went wrong. Client is authenticated, but database couldn't get user-data.")
                self.send_msg(client, "", ResponseCode.DATABASE_ERROR) # Send client a database-error-response
                raise ClientAuthenticationFailedException()

            client.client_type = user_data.client_type # Change from UNKNOWN to its real client-type.
            client.permission = user_data.client_permission # Change from UNKNOWN to its real permission-type.

            # Sending client the successful-authentication-response.
            if not self.send_msg(client, "", ResponseCode.AUTHENTICATION_SUCCESSFUL):
                raise ClientAuthenticationFailedException()

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
                if check_if_valid_command(command=client_msg):
                    # Command from client is a valid command.
                    (response, response_code) = self.handle_client_valid_command(client, client_msg)
                    if not response and response_code == ResponseCode.NO_ERROR:
                        # Close connection.
                        logging.info(f"{client.repr_str} Client sent a Close-Connection-Request. Closing connection to client.")
                        break
                    elif response and response_code == ResponseCode.FORCE_CONNECTION_CLOSURE:
                        # Force client to close the connection.
                        logging.info(f"{client.repr_str} Forcing client to close the connection.")
                        # Sending response to client.
                        self.send_msg(client, response, response_code)
                        break
                    elif not response:
                        # Set to empty string.
                        response = ""
                else:
                    # Unknown command.
                    response_code = ResponseCode.UNKNOWN_COMMAND_ERROR
                    response = f"The command `{client_msg}` is unknown."

                if not self.send_msg(client, msg=response, response_code=response_code):
                    logging.error(f"{client.repr_str} An error occured while trying to send response to client. (error_counter={error_counter})")
                    error_counter += 1

            except KeyboardInterrupt as _e:
                    logging.warning(f"{client.repr_str} Detected a keyboard-interruption on server-side. Closing connection to client.")
                    break

            except Exception as _error:
                logging.error(f"{client.repr_str} An unexpected exception occured while handling client: {_error}")
                logging.error(f"«TRACEBACK» {traceback.format_exc()}")  # Log the full traceback
                break

        self.close_connection_to_client(client)
        self._clients.remove(client)
        logging.info(f"{client.repr_str} Closed connection to client.")

    def handle_client_valid_command(self, client:Client, client_msg:str) -> tuple[str|None, ResponseCode]:
        """Handle all possible client-commands."""

        command_map = {
            ClientCommand.CREATE_USER: [self.handle_create_user_command, True],
            ClientCommand.GET_CLIENT_COMMANDS: [self.handle_get_client_commands_command, False],
            ClientCommand.GET_ALL_USERS: [self.handle_get_all_users_command, False],
            ClientCommand.REGISTER_NEW_WEATHER_STATION: [self.handle_register_new_weather_station_command, True],
            ClientCommand.GET_WEATHER_STATIONS_BY_USERNAME: [self.handle_get_weather_stations_by_username_command, True],
            ClientCommand.SEND_WEATHER_REPORT_BY_STATION_NAME: [self.handle_add_weather_report_by_station_name_command, True],
            ClientCommand.DELETE_USER_BY_USERNAME: [self.handle_get_all_users_command, False],
            ClientCommand.DELETE_WEATHER_STATION_BY_STATION_NAME: [self.handle_delete_weather_station_by_station_name, True],
            ClientCommand.GET_ALL_MY_STATIONS: [self.handle_get_all_my_stations, False],
            ClientCommand.SHOW_ALL_CONNECTED_CLIENTS: [self.handle_show_all_connected_clients, False],
            ClientCommand.CHANGE_MY_PASSWORD: [self.handle_change_my_user_password, True],
            ClientCommand.CLOSE_ALL_USER_CLIENT_CONNECTIONS_BY_USERNAME: [self.handle_close_all_user_client_connections_by_username, True],
            ClientCommand.GET_ALL_MEASUREMENTS_BY_STATION_NAME: [self.handle_get_all_measurements_by_station_name, True],
            ClientCommand.GET_ALL_MEASUREMENTS_BY_STATION_ID: [self.handle_get_all_measurements_by_station_id, True],
            ClientCommand.GET_STATION_INFORMATION_BY_STATION_ID: [self.handle_get_station_information_by_station_id, True],
        }

        # Core command: Check for the CLOSE_CONNECTION command first
        if check_if_specific_valid_core_command(client_msg, CoreCommand.CLOSE_CONNECTION):
            return (None, ResponseCode.NO_ERROR)

        # Iterate through the command map
        for command in command_map.keys():
            if check_if_specific_valid_client_command(client_msg, command):
                if command_map[command][1]:
                    return command_map[command][0](client, client_msg)
                return command_map[command][0](client)

        # If no valid command found, return an error or handle it accordingly
        # Shouldn't be reachable, because the command-validation was executed before this function.
        return (None, ResponseCode.UNKNOWN_COMMAND_ERROR)

    def handle_get_station_information_by_station_id(self, client:Client, client_msg:str) -> tuple[str|None, ResponseCode]:
        """Sending client all measurements from a specific station by its station-ID."""

        command:ClientCommand = ClientCommand.GET_STATION_INFORMATION_BY_STATION_ID

        logging.debug(f"{client.repr_str} Client wants to get information about a specific station by its station-ID.")

        # Check if client is allowed to execute this command.
        if not check_if_client_is_allowed_to_execute_client_command(client.client_type, client.permission, command):
            # Client doesn't have sufficient permissions.
            logging.debug(f"{client.repr_str} Clients has insufficient permissions to get information about a specific station by its station-ID.")
            return (None, ResponseCode.NOT_ALLOWED_COMMAND_ERROR)

        # Get arguments.
        command_params:str = client_msg.split(command.value.command_str)[1]
        station_ID_string:str = command_params.split(command.value.params[0][0])[1].split(command.value.params[0][1])[0]

        if len(station_ID_string) == 0:
            logging.debug(f"{client.repr_str} The given station-ID is empty.")
            return ("The station-ID can't be empty.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        # Check if given station-ID is valid.
        try:
            station_ID:int = int(station_ID_string)
        except ValueError as _e:
            logging.debug(f"{client.repr_str} The given station-ID '{station_ID_string}' isn't a valid integer.")
            return ("The given station-ID is invalid.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        station:Station|None = db_utils.get_station_by_ID(station_ID)

        if not station:
            logging.debug(f"{client.repr_str} There is no station with the station-ID '{station_ID}'")
            return ("There is no station with such station-ID.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        resp_string:str = f"\n<--- Station-ID: {station.id} --->\n » Name: {station.station_name}\n » Creation-Timestamp: {convert_timestamp_float_to_str_datetime(station.creation_timestamp)}\n » Location: {station.station_location}\n » Owner-Username: {station.user.username}{' (YOU)' if station.user.username == client.username else ''}\n"
        logging.debug(f"{client.repr_str} Got {len(resp_string)} Bytes long station-information-string for client.")
        return (resp_string, ResponseCode.NO_ERROR)

    def handle_get_all_measurements_by_station_id(self, client:Client, client_msg:str) -> tuple[str|None, ResponseCode]:
        """Sending client all measurements from a specific station by its station-ID."""

        command:ClientCommand = ClientCommand.GET_ALL_MEASUREMENTS_BY_STATION_ID

        logging.debug(f"{client.repr_str} Client wants to get all measurements from a specific station by its station-ID.")

        # Check if client is allowed to execute this command.
        if not check_if_client_is_allowed_to_execute_client_command(client.client_type, client.permission, command):
            # Client doesn't have sufficient permissions.
            logging.debug(f"{client.repr_str} Clients has insufficient permissions to get all measurements from a specific station by its station-ID.")
            return (None, ResponseCode.NOT_ALLOWED_COMMAND_ERROR)

        # Get arguments.
        command_params:str = client_msg.split(command.value.command_str)[1]
        station_ID_string:str = command_params.split(command.value.params[0][0])[1].split(command.value.params[0][1])[0]

        if len(station_ID_string) == 0:
            logging.debug(f"{client.repr_str} The given station-ID is empty.")
            return ("The station-ID can't be empty.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        # Check if given station-ID is valid.
        try:
            station_ID:int = int(station_ID_string)
        except ValueError as _e:
            logging.debug(f"{client.repr_str} The given station-ID '{station_ID_string}' isn't a valid integer.")
            return ("The given station-ID is invalid.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        station:Station|None = db_utils.get_station_by_ID(station_ID)

        if not station:
            logging.debug(f"{client.repr_str} There is no station with the station-ID '{station_ID}'")
            return ("There is no station with such station-ID.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        # Get measurements.
        measurements:list[Measurement]|None = db_utils.get_all_measurements_of_station_by_station(station)
        if not measurements:
            logging.debug(f"{client.repr_str} The station '{station.station_name}' (ID={station.id}) doesn't have any measurements stored.")
            return (f"Couldn't find any measurements of the station '{station.station_name}' (ID={station.id}).", ResponseCode.NO_ERROR)

        counter, json_data = self.get_measurement_list_dict(measurements)
        json_string:str = MessageFlag.JSON_DATA.value + json.dumps(json_data)
        logging.debug(f"{client.repr_str} Found {counter} measurement{'s' if counter > 1 else ''} of the station '{station.station_name}' (ID={station.id})")
        return (json_string, ResponseCode.NO_ERROR)

    def handle_get_all_measurements_by_station_name(self, client:Client, client_msg:str) -> tuple[str|None, ResponseCode]:
        """Sending client all measurements from a specific station by its station-name."""

        command:ClientCommand = ClientCommand.GET_ALL_MEASUREMENTS_BY_STATION_NAME

        logging.debug(f"{client.repr_str} Client wants to get all measurements from a specific station by its station-name.")

        # Check if client is allowed to execute this command.
        if not check_if_client_is_allowed_to_execute_client_command(client.client_type, client.permission, command):
            # Client doesn't have sufficient permissions.
            logging.debug(f"{client.repr_str} Clients has insufficient permissions to get all measurements from a specific station by its station-name.")
            return (None, ResponseCode.NOT_ALLOWED_COMMAND_ERROR)

        # Get arguments.
        command_params:str = client_msg.split(command.value.command_str)[1]
        station_name:str = command_params.split(command.value.params[0][0])[1].split(command.value.params[0][1])[0]

        if len(station_name) == 0:
            logging.debug(f"{client.repr_str} The given station-name is empty.")
            return ("The station-name can't be empty.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        # Check if given station-name is valid.
        station:Station|None = db_utils.get_station_by_name(station_name)

        if not station:
            logging.debug(f"{client.repr_str} The given station-name '{station_name}' is invalid.")
            return (f"The given station-name is invalid.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        # Get measurements.
        measurements:list[Measurement]|None = db_utils.get_all_measurements_of_station_by_station(station)
        if not measurements:
            logging.debug(f"{client.repr_str} The station '{station_name}' doesn't have any measurements stored.")
            return (f"Couldn't find any measurements of the station '{station_name}'.", ResponseCode.NO_ERROR)

        counter, json_data = self.get_measurement_list_dict(measurements)
        json_string:str = MessageFlag.JSON_DATA.value + json.dumps(json_data)
        logging.debug(f"{client.repr_str} Found {counter} measurement{'s' if counter > 1 else ''} of the station '{station_name}'")
        return (json_string, ResponseCode.NO_ERROR)

    def get_measurement_list_dict(self, measurements:list[Measurement]) -> tuple[int, dict[str,float]]:
        """Iterate a list of measurements and save them into a dictionary."""

        json_data:dict = {}
        counter:int = 0
        for measurement in measurements:
            counter += 1
            json_data[measurement.id] = {
                'timestamp': measurement.timestamp,
                'current_temperature_kelvin': measurement.current_temperature_kelvin,
                'current_wind_speed_kph': measurement.current_wind_speed_kph,
                'current_humidity_percent': measurement.current_humidity_percent,
                'current_pressure_hpa': measurement.current_pressure_hpa
            }

        return (counter, json_data)

    def handle_close_all_user_client_connections_by_username(self, client:Client, client_msg:str) -> tuple[str|None, ResponseCode]:
        """Handle connection-closure of all user-clients by its username."""

        command:ClientCommand = ClientCommand.CLOSE_ALL_USER_CLIENT_CONNECTIONS_BY_USERNAME

        logging.debug(f"{client.repr_str} Client wants to close all connections by their username.")

        # Check if client is allowed to execute this command.
        if not check_if_client_is_allowed_to_execute_client_command(client.client_type, client.permission, command):
            # Client doesn't have sufficient permissions.
            logging.debug(f"{client.repr_str} Clients has insufficient permissions to close all connections by their username.")
            return (None, ResponseCode.NOT_ALLOWED_COMMAND_ERROR)

        # Get arguments.
        command_params:str = client_msg.split(command.value.command_str)[1]
        username:str = command_params.split(command.value.params[0][0])[1].split(command.value.params[0][1])[0]

        # Check if given username is valid.
        if len(username) == 0:
            logging.debug(f"{client.repr_str} The given username is empty.")
            return ("The username can't be empty!", ResponseCode.INVALID_ARGUMENTS_ERROR)

        user:User|None = db_utils.get_user_by_username(username)
        if not user:
            logging.debug(f"{client.repr_str} The given username is invalid.")
            return (f"The given username is invalid.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        clients_to_close_conn_to:list[Client] = []
        resp_text:str = ""
        if client.username == user.username:
            resp_text += "This command won't close your connection.\n"
        for _client in self._clients:
            if _client.username == user.username:
                if _client == client:
                    continue
            clients_to_close_conn_to.append(_client)

        if len(clients_to_close_conn_to) == 0:
            resp_text += "There is no connection to close with the given username."
            logging.debug(f"{client.repr_str} There is no connection to close with the given username.")
            return (resp_text, ResponseCode.NO_ERROR)

        resp_text += f"Closing the connection to {len(clients_to_close_conn_to)} client{'s' if len(clients_to_close_conn_to) > 1 else ''}."

        for _client in clients_to_close_conn_to:
            self.close_connection_to_client(_client)

        logging.debug(f"{client.repr_str} Closed all client-connections, who're connected with the username '{user.username}'")
        return (resp_text, ResponseCode.NO_ERROR)

    def handle_change_my_user_password(self, client:Client, client_msg:str) -> tuple[str|None, ResponseCode]:
        """Handle user-password-change of current client-user."""

        command:ClientCommand = ClientCommand.CHANGE_MY_PASSWORD

        logging.debug(f"{client.repr_str} Client wants to change its own user-password.")

        # Check if client is allowed to execute this command.
        if not check_if_client_is_allowed_to_execute_client_command(client.client_type, client.permission, command):
            # Client doesn't have sufficient permissions.
            logging.debug(f"{client.repr_str} Clients has insufficient permissions to change its own user-password.")
            return (None, ResponseCode.NOT_ALLOWED_COMMAND_ERROR)

        # Get arguments.
        command_params:str = client_msg.split(command.value.command_str)[1]
        new_password:str = command_params.split(command.value.params[0][0])[1].split(command.value.params[0][1])[0]

        # Check if given password is valid.
        if len(new_password) == 0:
            return ("The password can't be empty!", ResponseCode.INVALID_ARGUMENTS_ERROR)

        user:User|None = db_utils.get_user_by_username(client.username)
        if not user:
            logging.error(f"{client.repr_str} An error occured while trying to get client's user-object. It seems, that its username doesn't exist.")
            return (f"It seems like your client-username is invalid. Please report this error.", ResponseCode.SERVER_ERROR) # or ResponseCode.DATABASE_ERROR

        if db_utils.verify_password(user.password, new_password):
            logging.debug(f"{client.repr_str} The given password equals the old one. Nothing to change.")
            return (f"Your new password equals the old one. Nothing to change.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        status, resp_text = db_utils.change_user_password(client.username, new_password)
        if not status:
            logging.error(f"{client.repr_str} Couldn't change client's user-password. Database-Error: {resp_text}")
            return (f"Couldn't change your user-password.", ResponseCode.DATABASE_ERROR)

        logging.info(f"{client.repr_str} Client changed its user-password. Forcing client to re-connect.")
        return (f"Your password has been changed successfully. Please re-authenticate.", ResponseCode.FORCE_CONNECTION_CLOSURE)

    def handle_show_all_connected_clients(self, client:Client) -> tuple[str|None, ResponseCode]:
        """Send client information about all connected clients."""

        command:ClientCommand = ClientCommand.SHOW_ALL_CONNECTED_CLIENTS

        logging.debug(f"{client.repr_str} Client wants to get information about all connected clients.")

        # Check if client is allowed to execute this command.
        if not check_if_client_is_allowed_to_execute_client_command(client.client_type, client.permission, command):
            # Client doesn't have sufficient permissions.
            logging.debug(f"{client.repr_str} Clients has insufficient permissions to get information about all connected clients.")
            return (None, ResponseCode.NOT_ALLOWED_COMMAND_ERROR)

        len_of_clients:int = len(self._clients)
        response_str:str = f"\n<--- There {'is' if len_of_clients == 1 else 'are'} {len_of_clients} client{'s' if len_of_clients > 1 else ''} currently connected to the server --->\n"
        for x, _client in enumerate(self._clients):
            response_str += f"{'(YOU) ' if client == _client else ''}« [{x+1}] » Address={_client.client_addr} \n| Username={_client.username} \n| Connection-Status={_client.connection_status} \n| Authentication-Status={_client.authentication_status} \n| Client-Type={_client.client_type} \n| Client-Permission={_client.permission}\n| Connection-Timestamp: {convert_timestamp_float_to_str_datetime(_client.connection_timestamp)}\n"
            if x < len(self._clients):
                response_str += "\n"

        return (response_str, ResponseCode.NO_ERROR)


    def handle_get_all_my_stations(self, client:Client) -> tuple[str|None, ResponseCode]:
        """Send the client information about all of its own weather-stations."""

        command:ClientCommand = ClientCommand.GET_ALL_MY_STATIONS

        logging.debug(f"{client.repr_str} Client wants to get information about all of its own weather-stations.")

        # Check if client is allowed to execute this command.
        if not check_if_client_is_allowed_to_execute_client_command(client.client_type, client.permission, command):
            # Client doesn't have sufficient permissions.
            logging.debug(f"{client.repr_str} Clients has insufficient permissions to get information about all of its own weather-stations.")
            return (None, ResponseCode.NOT_ALLOWED_COMMAND_ERROR)

        user = db_utils.get_user_by_username(client.username)

        if not user:
            logging.error(f"{client.repr_str} Something went wrong while trying to fetch client's user-data from the database. Might be a database-error.")
            return (f"Something went wrong -> Your client-username seems to be wrong: '{client.username}'", ResponseCode.SERVER_ERROR)

        stations:list|None = db_utils.get_all_stations_by_user_id(user_id=user.id)
        if not stations:
            logging.debug(f"{client.repr_str} Couldn't find any weather-station of user '{user.username}'")
            return (f"Couldn't find any weather-station of user '{user.username}'", ResponseCode.NO_ERROR)

        stations_information:str = self.get_stations_information_string(stations, user.username)

        logging.debug(f"{client.repr_str} Fetched all of '{user.username}'s weather-stations.")
        return (stations_information, ResponseCode.NO_ERROR)

    def handle_delete_weather_station_by_station_name(self, client:Client, client_msg:str) -> tuple[str|None, ResponseCode]:
        """Handle weather-station-deletion by its station-name."""

        command:ClientCommand = ClientCommand.DELETE_WEATHER_STATION_BY_STATION_NAME

        logging.debug(f"{client.repr_str} Client wants to delete a weather-station by its station-name.")

        # Check if client is allowed to execute this command.
        if not check_if_client_is_allowed_to_execute_client_command(client.client_type, client.permission, command):
            # Client doesn't have sufficient permissions.
            logging.debug(f"{client.repr_str} Clients has insufficient permissions to delete a weather-station by its station-name.")
            return (None, ResponseCode.NOT_ALLOWED_COMMAND_ERROR)

        # Get arguments.
        command_params:str = client_msg.split(command.value.command_str)[1]
        station_name:str = command_params.split(command.value.params[0][0])[1].split(command.value.params[0][1])[0]

        # Check if given station-name is valid.
        if len(station_name) == 0:
            logging.debug(f"{client.repr_str} The given station-name is empty.")
            return ("The station-name can't be empty!", ResponseCode.INVALID_ARGUMENTS_ERROR)

        station = db_utils.get_station_by_name(station_name)

        if not station:
            logging.debug(f"{client.repr_str} The given station-name is invalid.")
            return (f"There is no station with the station-name '{station_name}'.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        status, error_resp = db_utils.delete_station(station)
        if not status:
            logging.error(f"{client.repr_str} Couldn't delete station by its station-name. Database-Error -> {error_resp}")
            return (f"Couldn't delete station by its station-name '{station_name}'. Database-Error.", ResponseCode.DATABASE_ERROR)

        logging.info(f"{client.repr_str} Client deleted a station by its station-name '{station_name}'.")
        return (f"Deleted a weather-station by its station-name '{station_name}'.", ResponseCode.NO_ERROR)

    def handle_delete_user_by_username_command(self, client:Client, client_msg:str) -> tuple[str|None, ResponseCode]:
        """Handle user-deletion by its username."""

        command:ClientCommand = ClientCommand.DELETE_USER_BY_USERNAME

        logging.debug(f"{client.repr_str} Client wants to delete a user by its username.")

        # Check if client is allowed to execute this command.
        if not check_if_client_is_allowed_to_execute_client_command(client.client_type, client.permission, command):
            # Client doesn't have sufficient permissions.
            logging.debug(f"{client.repr_str} Clients has insufficient permissions to delete a user by its username.")
            return (None, ResponseCode.NOT_ALLOWED_COMMAND_ERROR)

        # Get arguments.
        command_params:str = client_msg.split(command.value.command_str)[1]
        username:str = command_params.split(command.value.params[0][0])[1].split(command.value.params[0][1])[0]

        # Check if given username is valid.
        if len(username) == 0:
            logging.debug(f"{client.repr_str} The given username is empty.")
            return ("The username can't be empty!", ResponseCode.INVALID_ARGUMENTS_ERROR)

        user:User|None = db_utils.get_user_by_username(username)

        if not user:
            logging.debug(f"{client.repr_str} The given username does not exist.")
            return (f"The given username '{username}' does not exist!", ResponseCode.INVALID_ARGUMENTS_ERROR)

        status, resp_text = db_utils.delete_user_by_user(user)
        if not status:
            logging.error(f"{client.repr_str} Couldn't delete user by its username '{username}'. -> {resp_text}")
            return (f"Couldn't delete the user, because of a database-error.", ResponseCode.DATABASE_ERROR)

        logging.info(f"{client.repr_str} Client deleted the user with the username '{username}'.")
        return (f"Successfully deleted the user '{username}'.", ResponseCode.NO_ERROR)


    def handle_get_all_users_command(self, client:Client) -> tuple[str|None, ResponseCode]:
        """Sending the client the information about all users in the database."""

        command:ClientCommand = ClientCommand.GET_ALL_USERS

        logging.debug(f"{client.repr_str} Client wants to get all users from the database.")

        # Check if client is allowed to execute this command.
        if not check_if_client_is_allowed_to_execute_client_command(client.client_type, client.permission, command):
            # Client doesn't have sufficient permissions.
            logging.debug(f"{client.repr_str} Client has insufficient permissions to get all users from the database.")
            return (None, ResponseCode.NOT_ALLOWED_COMMAND_ERROR)

        users:list|None = db_utils.get_all_users()
        if not users:
            logging.error(f"{client.repr_str} Couldn't fetch any user from the database. Database-Error?")
            return ("Couldn't fetch any user from the database. Something went wrong.", ResponseCode.DATABASE_ERROR)

        resp:str = f"\n<--- {len(users)} User{'' if len(users) == 1 else 's'} --->\n"

        for x, user in enumerate(users):
            resp += f"({x+1}) '{user.username}' » ID={user.id} » CLIENT-TYPE={user.client_type} » CLIENT-PERMISSION={user.client_permission} » CREATION-TIMESTAMP={convert_timestamp_float_to_str_datetime(user.creation_timestamp)}\n"

        return (resp, ResponseCode.NO_ERROR)

    def handle_add_weather_report_by_station_name_command(self, client:Client, client_msg:str) -> tuple[str|None, ResponseCode]:
        """Handle new incoming measurements of a weather-station by its station-id."""
        """
            1. The client sends the required weather-report-parameters.
            2. Check if the client is a weather-station.
            3. Check if the weather-station is allowed to add a weather-report to the given weather-station.
            4. Add the measurement (if it's valid) to the database.

        """

        command:ClientCommand = ClientCommand.SEND_WEATHER_REPORT_BY_STATION_NAME

        logging.debug(f"{client.repr_str} Client wants to add a weather-report to a station by its station-name.")

        # Check if client is allowed to execute this command.
        if not check_if_client_is_allowed_to_execute_client_command(client.client_type, client.permission, command):
            # Client doesn't have sufficient permissions.
            logging.debug(f"{client.repr_str} Client has insufficient permissions to add a weather-report to a station by its station-name.")
            return (None, ResponseCode.NOT_ALLOWED_COMMAND_ERROR)

        # Get arguments.
        command_params:str = client_msg.split(command.value.command_str)[1]
        station_name:str = command_params.split(command.value.params[0][0])[1].split(command.value.params[0][1])[0]
        timestamp_string:str = command_params.split(command.value.params[1][0])[1].split(command.value.params[1][1])[0]
        current_temp_k = command_params.split(command.value.params[2][0])[1].split(command.value.params[2][1])[0]
        current_wind_speed_kph = command_params.split(command.value.params[3][0])[1].split(command.value.params[3][1])[0]
        current_humidity_percent = command_params.split(command.value.params[4][0])[1].split(command.value.params[4][1])[0]
        current_pressure_hpa = command_params.split(command.value.params[5][0])[1].split(command.value.params[5][1])[0]

        # Check if station with given station-name exists.
        station:Station|None = db_utils.get_station_by_name(station_name)
        if not station:
            return (f"There is no station with the name '{station_name}'.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        # Check if user is allowed to add measurements to given station.
        if station.user.username != client.username:
            # Check if client-permission may be sufficient.
            user:User|None = db_utils.get_user_by_username(client.username)
            if not user:
                logging.error(f"{client.repr_str} Couldn't check if client is allowed to execute this command.")
                return ("Couldn't check if you're allowed to execute this command. Please report this incident.", ResponseCode.SERVER_ERROR)

            # Check if user has ROOT-Permissions.
            # Because a client with ROOT-Permissions is allowed to add measurements to other weather-stations too.
            if user.client_permission != ClientPermission.ROOT:
                logging.error(f"{client.repr_str} Client doesn't have sufficient permission to add a measurement-report to another weather-station. Weather-Station-Owner={station.user.username}")
                return (f"You're not allowed to add a measurement-report to the weather-station '{station.station_name}' ({station.id}), because you're not the owner of this station.", ResponseCode.NOT_ALLOWED_COMMAND_ERROR)

        # Check if given timestamp-string is valid and convert it to a float-timestamp.
        float_timestamp:float|None = get_timestamp_float_from_str(timestamp_string)
        if not float_timestamp:
            return ("The given timestamp is invalid.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        # Check if current-temperature-in-kelvin is valid and convert it to a float.
        float_current_temp_k:float|None = get_temp_float_from_str(current_temp_k)
        if not float_current_temp_k:
            return (f"The given current-temperature in Kelvin is invalid.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        # Check if current-wind-speed-kph is valid and convert it to a float.
        float_current_wind_speed_kph:float|None = get_velocity_float_from_str(current_wind_speed_kph)
        if not float_current_wind_speed_kph:
            return (f"The given current-wind-speed in KPH is invalid.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        # Check if current-humidity-percent is valid and convert it to a float.
        float_current_humidity_percent:float|None = get_percent_float_from_str(current_humidity_percent)
        if not float_current_humidity_percent:
            return (f"The given current-humdity in percent is invalid.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        # Check if current-pressure-hpa is valid and convert it to a float.
        try:
            float_current_pressure_hpa:float = float(current_pressure_hpa)
        except ValueError as _e:
            return (f"The given current-pressure in HPA is invalid.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        # Save given data into the database.
        data:dict[str,float] = {
            'timestamp': float_timestamp,
            'current_temperature_kelvin': float_current_temp_k,
            'current_wind_speed_kph': float_current_wind_speed_kph,
            'current_humidty_percent': float_current_humidity_percent,
            'current_pressure_hpa': float_current_pressure_hpa
        }
        status, new_measurement_obj = db_utils.add_measurement_to_station_by_station(station, data)
        if not status:
            logging.error(f"{client.repr_str} Couldn't add measurement to station (station_name='{station.station_name}') due to a database-error -> {new_measurement_obj}")
            return (f"Couldn't add the measurement to station (name='{station.station_name}').", ResponseCode.DATABASE_ERROR)

        logging.info(f"{client.repr_str} Client added a measurement to the station (station_name='{station.station_name}') with the ID={new_measurement_obj.id}")
        return (f"Successfully added a new measurement to the station with the name '{station.station_name}'.", ResponseCode.NO_ERROR)

    def handle_get_weather_stations_by_username_command(self, client:Client, client_msg:str) -> tuple[str|None, ResponseCode]:
        """Send client all weather-stations by username."""

        command:ClientCommand = ClientCommand.GET_WEATHER_STATIONS_BY_USERNAME

        logging.debug(f"{client.repr_str} Client wants to get all weather-stations by username.")

        # Check if client is allowed to execute this command.
        if not check_if_client_is_allowed_to_execute_client_command(client.client_type, client.permission, command):
            # Client doesn't have sufficient permissions.
            logging.debug(f"{client.repr_str} Client has insufficient permissions to get all weather-stations by username.")
            return (None, ResponseCode.NOT_ALLOWED_COMMAND_ERROR)

        # Get arguments.
        command_params:str = client_msg.split(command.value.command_str)[1]
        user_username:str = command_params.split(command.value.params[0][0])[1].split(command.value.params[0][1])[0]

        # Check if given username is valid.
        if len(user_username) == 0:
            return ("The user-username can't be empty!", ResponseCode.INVALID_ARGUMENTS_ERROR)

        user = db_utils.get_user_by_username(user_username)

        if not user:
            return (f"The user-username '{user_username}' does not exist.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        stations:list[Station]|None = db_utils.get_all_stations_by_user_id(user_id=user.id)
        if not stations:
            logging.debug(f"{client.repr_str} Couldn't find any weather-station of user '{user.username}'")
            return (f"Couldn't find any weather-station of user '{user.username}'", ResponseCode.NO_ERROR)

        stations_information:str = self.get_stations_information_string(stations, user.username)
        logging.debug(f"{client.repr_str} Fetched {len(stations)} weather-stations of user '{user.username}'")

        return (stations_information, ResponseCode.NO_ERROR)

    def get_stations_information_string(self, stations:list[Station], username:str|None=None) -> str:
        """Create a stations-information string for the client."""

        stations_len:int = len(stations)
        stations_information:str = f"""\n<--- Found {stations_len} weather-station{'' if stations_len == 1 else 's'}{f" of user '{username}'" if username else ""} --->\n"""
        for x, station in enumerate(stations):
            stations_information += f"({x+1}) Station-ID: {station.id} » Station-Name: {station.station_name} » Station-Location: {station.station_location}\n"

        return stations_information

    def handle_register_new_weather_station_command(self, client:Client, client_msg:str) -> tuple[str|None, ResponseCode]:
        """Handle new weather-station registration."""

        command:ClientCommand = ClientCommand.REGISTER_NEW_WEATHER_STATION

        logging.debug(f"{client.repr_str} Client is trying to register a new weather-station.")

        # Check if client is allowed to execute this command.
        if not check_if_client_is_allowed_to_execute_client_command(client.client_type, client.permission, command):
            # Client doesn't have sufficient permissions.
            logging.debug(f"{client.repr_str} Client has insufficient permissions to register a new weather-station.")
            return (None, ResponseCode.NOT_ALLOWED_COMMAND_ERROR)

        # Get arguments.
        command_params:str = client_msg.split(command.value.command_str)[1]
        user_username:str = command_params.split(command.value.params[0][0])[1].split(command.value.params[0][1])[0]
        station_name:str = command_params.split(command.value.params[1][0])[1].split(command.value.params[1][1])[0]
        station_location:str = command_params.split(command.value.params[2][0])[1].split(command.value.params[2][1])[0]

        # Check if given username is valid.
        if len(user_username) == 0:
            return ("The user-username can't be empty!", ResponseCode.INVALID_ARGUMENTS_ERROR)

        user = db_utils.get_user_by_username(user_username)

        if not user:
            return (f"The user-username '{user_username}' does not exist.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        # Check if station-name is valid.
        if len(station_name) == 0:
            return ("The station-name can't be empty!", ResponseCode.INVALID_ARGUMENTS_ERROR)

        if db_utils.get_station_by_name(station_name):
            # Station with the same name already exists.
            return (f"A station already exists with the name '{station_name}'.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        # Check if station-location is valid.
        if len(station_location) == 0:
            return ("The station-location can't be empty!", ResponseCode.INVALID_ARGUMENTS_ERROR)

        if not check_station_location(station_location):
            # Station-Location is invalid.
            return ("Invalid station-location. Please use the ISO 6709 standard.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        if not db_utils.create_new_station(user.id, station_name, station_location):
            # Database-Error
            return (f"Couldn't add the station with the name '{station_name}' (location='{station_location}') , due to a database-error.", ResponseCode.DATABASE_ERROR)

        logging.info(f"{client.repr_str} Registered a new weather-station with with the name '{station_name}' at the location '{station_location}' for the user '{user.username}'.")

        return (f"Created new station with the name '{station_name}' (location='{station_location}')", ResponseCode.NO_ERROR)

    def handle_get_client_commands_command(self, client:Client) -> tuple[str|None, ResponseCode]:
        """Handle get-client-commands command from client by sending the Enum-content."""

        command:ClientCommand = ClientCommand.GET_CLIENT_COMMANDS

        logging.debug(f"{client.repr_str} Client asks for available client-commands.")

        # Check if client is allowed to execute this command.
        if not check_if_client_is_allowed_to_execute_client_command(client.client_type, client.permission, command):
            # Client doesn't have sufficient permissions.
            logging.debug(f"{client.repr_str} Client has insufficient permissions to get a list of all available client-commands.")
            return (None, ResponseCode.NOT_ALLOWED_COMMAND_ERROR)

        # Get help-string.
        help_dict:dict = {}
        for client_command in ClientCommand:
            if not check_if_client_is_allowed_to_execute_client_command(client.client_type, client.permission, client_command):
                # Client is not allowed to execute the command, so it doesn't need it.
                continue

            help_dict[client_command.value.command_str] = {'params':client_command.value.params}

        help_string:str = MessageFlag.JSON_DATA.value + json.dumps(help_dict)

        logging.info(f"{client.repr_str} Got help-string for client ({len(help_string)} Bytes)")

        return (help_string, ResponseCode.NO_ERROR)


    def handle_create_user_command(self, client:Client, client_msg:str) -> tuple[str|None, ResponseCode]:
        """Handle user-creation command from client."""

        logging.debug(f"{client.repr_str} Client is trying to create a new user.")

        command:ClientCommand = ClientCommand.CREATE_USER

        # Check if client is allowed to execute this command.
        if not check_if_client_is_allowed_to_execute_client_command(client.client_type, client.permission, command):
            # Client doesn't have sufficient permissions.
            logging.debug(f"{client.repr_str} Client has insufficient permissions to create a new user.")
            return (None, ResponseCode.NOT_ALLOWED_COMMAND_ERROR)

        # Get arguments
        command_params:str = client_msg.split(command.value.command_str)[1]
        username:str = command_params.split(command.value.params[0][0])[1].split(command.value.params[0][1])[0]
        password:str = command_params.split(command.value.params[1][0])[1].split(command.value.params[1][1])[0]
        try:
            client_type:ClientType = ClientType(int(command_params.split(command.value.params[2][0])[1].split(command.value.params[2][1])[0]))
            client_permission:ClientPermission = ClientPermission(int(command_params.split(command.value.params[3][0])[1].split(command.value.params[3][1])[0]))
            if client_type == ClientType.UNKNOWN:
                # Cannot set a user as UNKNOWN.
                raise ValueError("Cannot set a user client-type to UNKNOWN.")
            if client_permission == ClientPermission.UNKNOWN:
                # Cannot set a user as UNKNOWN.
                raise ValueError("Cannot set a user client-permission to UNKNOWN.")
        except ValueError as _e:
            # Given client-type or/and client_permission is invalid.
            return ("Given client-type or/and client-permission is invalid.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        # Check username
        if len(username) == 0:
            return ("The username can't be empty!", ResponseCode.INVALID_ARGUMENTS_ERROR)

        if db_utils.get_user_by_username(username):
            # Username already exists.
            return (f"The username '{username}' is already in use. Choose another one.", ResponseCode.INVALID_ARGUMENTS_ERROR)

        if not db_utils.create_user(username=username, password=password, client_type=client_type, client_permission=client_permission):
            # Couldn't create new user.
            return (f"Something went wrong while trying to create a user with the username '{username}'", ResponseCode.DATABASE_ERROR)

        logging.info(f"{client.repr_str} Client created a new user with the username '{username}'")

        return (f"Created new User '{username}'.", ResponseCode.NO_ERROR)


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

