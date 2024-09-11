import os
import sys
import ssl
import time
import socket
import ipaddress
#


class Server:

    """The TCP server, which manages the incoming data and passes data to other clients."""

    def __init__(self, config:dict) -> None:
        self.config:dict = config
        self._running:bool = True
        self._server_addr:tuple[str,int]|None = None
        self._clients[Client] = []

        self.server_addr = config['server_addr']

    @property
    def server_addr(self) -> tuple[str,int]:
        return self._server_addr

    @server_addr.setter
    def server_addr(self, new_server_addr:tuple[str,int]) -> None:
        if not isinstance(new_server_addr[0], str):
            raise TypeError("Server Hostname/IP-Address has to be a string")
        if not isinstance(new_server_addr[1], int):
            raise TypeError("Server Port has to be an intenger")

        if not self.check_host(new_server_addr[0]):
            raise ValueError("Server Hostname/IP-Address is invalid")
        
        if not self.check_port(new_server_addr[1]):
            raise ValueError("Server Port is invalid")

        self._server_addr = new_server_addr

    def check_port(self, port:int) -> bool:
        """Check if given port is a valid port-number."""
        if port <= 0 or port > 65535:
            return False
        
        return True

    def check_host(self, host:str) -> bool:
        """Check if given host is a valid hostname or IP-Address."""
        try:
            ip_addr:str = socket.gethostbyname(host)
        except socket.error as _e:
            return False
        
        try:
            ipv4_addr = ipaddress.IPv4Address(ip_addr)
            return True
        except ipaddress.AddressValueError as _e:
            # Invalid IPv4-Address
            pass
        
        try:
            ipv6_addr = ipaddress.IPv6Address(ip_addr)
            return True
        except ipaddress.AddressValueError as _e:
            # Invalid IPv4- & IPv6-Address
            return False

    

    def run(self) -> None:
        pass
