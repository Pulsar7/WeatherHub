from enum import Enum
from collections import namedtuple


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


# Define a Command structure with named fields for clarity
Command = namedtuple('Command', ['command_str', 'params'])


class CoreCommand(Enum):
    CLOSE_CONNECTION = Command("!#CloseConnection#!", ())

    AUTHENTICATION_REQUEST = Command("!#AuthenticationRequest#!",
                            ( ("<USERNAME>", "</USERNAME>"), ("<PASSWORD>", "</PASSWORD>") ))
