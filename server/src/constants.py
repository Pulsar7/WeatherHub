from enum import Enum, auto
from collections import namedtuple


class ClientType(Enum):
    UNKNOWN = -1
    ADMIN_CLIENT = 0
    WEATHER_STATION = 1
    DATA_VISUALIZER = 2


class ClientPermission(Enum):
    UNKNOWN = -1
    NORMAL = 0
    ROOT = 1

# Define a (Response)Code structure with named fields for clarity
Code = namedtuple('Code', ['resp_code', 'description'])

class ResponseCode(Enum):
    NO_ERROR = Code(100, "NO ERROR")
    INVALID_CREDENTIALS_ERROR = Code(200, "INVALID CREDENTIALS ERROR")
    INVALID_ARGUMENTS_ERROR = Code(300, "INVALID ARGUMENTS ERRROR")
    SERVER_ERROR = Code(400, "SERVER ERROR")
    DATABASE_ERROR = Code(500, "DATABASE ERROR")
    UNKNOWN_ERROR = Code(600, "UNKNOWN ERROR")
    RECEIVING_ERROR = Code(700, "RECEIVING ERROR")
    SENDING_ERROR = Code(800, "SENDING_ERROR")
    AUTHENTICATION_SUCCESSFUL = Code(1000, "AUTHENTICATION SUCCESSFUL")
    UNKNOWN_COMMAND_ERROR = Code(1100, "UNKNOWN COMMAND ERROR")
    NOT_ALLOWED_COMMAND_ERROR = Code(1200, "NOT ALLOWED COMMAND ERROR")

class MessageFlag(Enum):
    BEGIN_BUFFERING = "!~BEGINBUFFERING~!"
    END_BUFFERING = "!~ENDBUFFERING~!"

# Define a CoreCommand structure with named fields for clarity.
Core_Command = namedtuple('Core_Command', ['client_permission', 'command_str', 'params'])

class CoreCommand(Enum):
    CLOSE_CONNECTION = Core_Command(ClientPermission.NORMAL, "!#CloseConnection#!", ())

    AUTHENTICATION_REQUEST = Core_Command(ClientPermission.NORMAL, "!#AuthenticationRequest#!",
                            ( ("<USERNAME>", "</USERNAME>"), ("<PASSWORD>", "</PASSWORD>") ))

# Define a ClientCommand structure with named fields for clarity.
Client_Command = namedtuple('Client_Command', ['allowed_client_types', 'client_permission', 'command_str', 'params'])

class ClientCommand(Enum):
    CREATE_USER = Client_Command((ClientType.ADMIN_CLIENT,), ClientPermission.ROOT, "!#CreateUser#!",
                            ( ("<USERNAME>", "</USERNAME>"), ("<PASSWORD>", "</PASSWORD>"),
                              ("<CLIENTTYPE>","</CLIENTTYPE>"), ("<CLIENTPERMISSION>", "</CLIENTPERMISSION>") ))

    SEND_WEATHER_REPORT = Client_Command((ClientType.WEATHER_STATION, ), ClientPermission.NORMAL, "!#SendWeatherReport#!",
                            ( ("<METADATA_WEATHERSTATIONLOCATION>", "</METADATA_WEATHERSTATION_LOCATION>"),
                              ("<METADATA_TIMESTAMP>", "</METADATA_TIMESTAMP>"), ("<WEATHERDATA>", "</WEATHERDATA>") ))

    GET_CLIENT_COMMANDS = Client_Command((ClientType.ADMIN_CLIENT, ClientType.DATA_VISUALIZER), ClientPermission.NORMAL, "!#GetClientCommands#!", ())
