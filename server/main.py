"""

    WeatherHub / Version 1.0

    # Python-Version: 3.10.12
    # Author: Pulsar

"""
import time
import logging
#
from src.config import *
from src.server import Server
from src.logging_config import setup_logging


def main() -> None:
    setup_logging()
    start:float = time.time()
    logging.info(f"Started at {start}")
    server:Server = Server(config=server_config)
    server.run()
    logging.info(f"Closed after {time.time()-start} seconds")



if __name__ == '__main__':
    server_config:dict = {
        'server_addr': (SERVER_HOST, SERVER_PORT),
        'server_ssl_keyfilepath': SERVER_SSL_KEYFILEPATH,
        'server_ssl_certfilepath': SERVER_SSL_CERTFILEPATH,
        'server_ssl_keyfilepassword': SERVER_SSL_KEYFILEPASSWORD,
        'max_incoming_connections': MAX_INCOMING_CONNECTIONS,
        'max_msg_chunk_size': MAX_MSG_CHUNK_SIZE,
        'socket_buffer_size': SOCKET_BUFFER_SIZE
    }
    main()
