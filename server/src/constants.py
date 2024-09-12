from enum import Enum, auto
from collections import namedtuple


class ClientType(Enum):
    UNKNOWN = auto()
    ADMIN_CLIENT = auto()
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
    AUTHENTICATION_SUCCESSFUL = Code(1000, "AUTHENTICATION SUCCESSFUL")
    UNKNOWN_COMMAND_ERROR = Code(1100, "UNKNOWN COMMAND ERROR")
    NOT_ALLOWED_COMMAND_ERROR = Code(1200, "NOT ALLOWED COMMAND ERROR")

class MessageFlag(Enum):
    BEGIN_BUFFERING = "!~BEGINBUFFERING~!"
    END_BUFFERING = "!~ENDBUFFERING~!"

# Define a Command structure with named fields for clarity
Command = namedtuple('Command', ['client_permission', 'command_str', 'params'])


class CoreCommand(Enum):
    CLOSE_CONNECTION = Command(ClientPermission.NORMAL, "!#CloseConnection#!", ())
    AUTHENTICATION_REQUEST = Command(ClientPermission.NORMAL, "!#AuthenticationRequest#!",
                            ( ("<USERNAME>", "</USERNAME>"), ("<PASSWORD>", "</PASSWORD>") ))

class ClientCommand(Enum):
    CREATE_USER = Command(ClientPermission.ROOT, "!#CreateUser#!",
                            ( ("<USERNAME>", "</USERNAME>"), ("<PASSWORD>", "</PASSWORD>"),
                              ("<CLIENTTYPE>","</CLIENTTYPE>"), ("<CLIENTPERMISSION>", "</CLIENTPERMISSION>") ))
    SEND_WEATHER_REPORT = Command(ClientPermission.NORMAL, "!#SendWeatherReport#!",
                            ( ("<METADATA_WEATHERSTATIONLOCATION>", "</METADATA_WEATHERSTATION_LOCATION>"),
                              ("<METADATA_TIMESTAMP>", "</METADATA_TIMESTAMP>"), ("<WEATHERDATA>", "</WEATHERDATA>") ))


### FUNCTIONS ###

def get_response_code_by_int(code_int:int) -> ResponseCode|None:
    """Convert integer to corresponding ResponseCode Enum member based on resp_code."""

    for code in ResponseCode:
        if code.value.resp_code == code_int:
            return code

    # No matching ResponseCode.
    return None

def check_if_specific_valid_client_command(command:str, client_command:ClientCommand) -> bool:
    """Check if the given string equals the given client-command-syntax."""

    if len(command) == 0:
        return False

    if not isinstance(client_command, ClientCommand):
        raise TypeError("Given client-commannd has to be from the type ClientCommand.")

    if client_command.value.command_str not in command:
        return False

    if len(client_command.value.params) == 0:
        if len(command) > len(client.command.value.command_str):
            # If client-command has no paramters, the command has to be equal to the command_str.
            return False

        return True

    for param in client_command.value.params:
        if param not in command:
            return False

    return True


def check_if_specific_valid_core_command(command:str, core_command:CoreCommand) -> bool:
    """Check if the given string equals the given core-command-syntax."""

    if len(command) == 0:
        return False

    if not isinstance(core_command, CoreCommand):
        raise TypeError("Given core-command has to be from the type CoreCommand.")

    if core_command.value.command_str not in command:
        return False

    if len(core_command.value.params) == 0:
        if len(command) > len(core_command.value.command_str):
            # If core-command has no paramters, the command has to be equal to the command_str.
            return False
        return True

    for param in core_command.value.params:
        if param not in command:
            return False

    return True


def check_if_valid_command(command:str) -> bool:
    """Check if given command-string is a valid CoreCommand or ClientCommand."""

    for core_command in CoreCommand:
        if check_if_specific_valid_core_command(command, core_command):
            return True

    for client_command in ClientCommand:
        if check_if_specific_valid_client_command(command, client_command):
            return True

    return False
