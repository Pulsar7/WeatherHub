import socket
import ipaddress
#
from .constants import *

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
