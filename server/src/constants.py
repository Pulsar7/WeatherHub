from enum import Enum, auto


class ClientType(Enum):
    UNKNOWN = auto()
    ADMIN = auto()
    WEATHER_STATION = auto()
    DATA_VIRTUALIZER = auto()


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
    AUTHENTICATION_SUCCESSFUL = Code(900, "AUTHENTICATION SUCCESSFUL")


class MessageFlag(Enum):
    BEGIN_BUFFERING = "!~BEGINBUFFERING~!"
    END_BUFFERING = "!~ENDBUFFERING~!"


# Define a Command structure with named fields for clarity
Command = namedtuple('Command', ['client_permission', 'command_str', 'params'])


class CoreCommands(Enum):
    CLOSE_CONNECTION = Command(ClientPermission.NORMAL, "!#CloseConnection#!", ())
    AUTHENTICATION_REQUEST = Command(ClientPermission.NORMAL, "!#AuthenticationRequest#!",
                            ( ("<USERNAME>", "</USERNAME>"), ("<PASSWORD>", "</PASSWORD>") ))


class ClientCommands(Enum):
    pass
