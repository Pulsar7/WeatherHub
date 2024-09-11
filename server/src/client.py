import ssl
import time
import socket
#
from .constants import *


class Client:

    """Object for every connected client."""

    def __init__(self, client_socket:socket.socket, ssl_socket:ssl.SSLSocket, client_addr:tuple[str,int], client_type:ClientType=

