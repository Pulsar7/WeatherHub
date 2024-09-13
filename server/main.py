"""

    WeatherHub / Version 1.0

    # Python-Version: 3.10.12
    # Author: Pulsar

"""
import os
import time
import logging
import argparse
#
from src.config import *
from src.constants import *
from src.server import Server
from src.database.models import User
from src.database.utils import create_user
from src.logging_config import setup_logging


def main() -> None:
    setup_logging(cli_output=args.cli_logger)
    from src.database.database_manager import initialize_database
    initialize_database()
    print(create_user(username="admin", password="lol1234", client_type=ClientType.ADMIN_CLIENT, client_permission=ClientPermission.ROOT))
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
        'socket_buffer_size': SOCKET_BUFFER_SIZE,
        'responsecode_separator': RESPONSECODE_SEPARATOR
    }

    parser = argparse.ArgumentParser(os.path.basename(__file__))
    parser.add_argument('-c', '--cli-logger', help="Enable CLI-output in addition to the file-logger", action="store_true")
    args:list = parser.parse_args()

    main()
