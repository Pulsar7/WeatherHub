"""

    WeatherHub / Admin-Client / Version 1.0

    # Python-Version: 3.10.12
    # Author: Pulsar

"""
import os
import time
import argparse
#
from src.config import *
from src.constants import *
from src.client import Client
from src.logger import Logger


def main() -> None:
    logger:Logger = Logger(label=os.path.basename(__file__), timezone=TIMEZONE)
    start:float = time.time()
    logger.info(f"Started at {start}")
    client:Client = Client(config)
    client.run()
    logger.info(f"Closed after {time.time()-start} seconds.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(os.path.basename(__file__))
    parser.add_argument('-s', '--server-host', help="Server Hostname/IP-Address", type=str, required=True)
    parser.add_argument('-p', '--server-port', help="Server Port", type=int, required=True)

    args:list = parser.parse_args()

    server_addr:tuple[str, int] = (args.server_host, args.server_port)
    config:dict = {
        'server_addr': server_addr,
        'timezone': TIMEZONE,
        'server_certificate_filepath': SERVER_CERTIFICATE_FILEPATH,
        'client_certificate_filepath': CLIENT_CERTIFICATE_FILEPATH,
        'client_keyfile_path': CLIENT_KEYFILE_PATH,
        'client_keyfile_password': CLIENT_KEYFILE_PASSWORD,
        'client_username': CLIENT_USERNAME,
        'client_password': CLIENT_PASSWORD,
        'default_max_msg_chunk_size': DEFAULT_MAX_MSG_CHUNK_SIZE,
        'default_buffer_size': DEFAULT_BUFFER_SIZE,
        'responsecode_separator': RESPONSECODE_SEPARATOR
    }


    main()
