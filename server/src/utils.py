import re
import socket
import string
import ipaddress
#
from .constants import *


def check_station_location(location_string:str) -> bool:
    """Check if a given location-string is valid accordingly to the ISO 6709 standard."""

    pattern:str = r"^[+-]?\d{1,2}(?:\.\d+)?[+-]?\d{1,3}(?:\.\d+)?(?:/[+-]?\d+(?:\.\d+)?)?$"
    regex = re.compile(pattern)

    if regex.match(location_string):
        return True
    else:
        return False


def check_if_client_is_allowed_to_execute_client_command(client_type:ClientType, client_permission:ClientPermission, command:ClientCommand) -> bool:
    """Check if client with given attributes is allowed to execute given client-command."""

    if client_permission.value < command.value.client_permission.value or client_type not in command.value.allowed_client_types:
        return False

    return True

def check_host(host:str) -> bool:
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


def check_port(port:int) -> bool:
    """Check if given port is a valid port-number."""

    if port <= 0 or port > 65535:
        return False

    return True

def get_response_code_by_value(code:str|int) -> ResponseCode|None:
    """Convert code-string to corresponding ResponseCode Enum member based on resp_code."""

    if not isinstance(code, int):
        try:
            code_int:int = int(code)
        except ValueError as _e:
            return None
    else:
        code_int:int = code

    for _code in ResponseCode:
        if _code.value.resp_code == code_int:
            return _code

    # No matching ResponseCode.
    return None

def check_if_specific_valid_client_command(command:str, client_command:ClientCommand) -> bool:
    """Check if the given string equals the given client-command-syntax."""

    if len(command) == 0:
        return False

    if not isinstance(client_command, ClientCommand):
        raise TypeError("Given client-command has to be from the type ClientCommand.")

    if client_command.value.command_str not in command:
        return False


    if len(client_command.value.params) == 0:
        if len(command) > len(client_command.value.command_str):
            # If client-command has no paramters, the command has to be equal to the command_str.
            return False

        return True

    for param_pear in list(client_command.value.params):
        for param in param_pear:
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

    for param_pear in list(core_command.value.params):
        for param in param_pear:
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


