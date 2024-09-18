"""

    WeatherHub / Weather-Station-Client / Version 1.0

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
from src.client import Client
from src.logging_config import setup_logging


def main() -> None:
    setup_logging(args.cli_output)
    start:float = time.time()
    logging.info(f"Started at {start}")
    client:Client = Client(config)
    client.run()
    logging.info(f"Closed after {time.time()-start} seconds.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(os.path.basename(__file__))
    parser.add_argument('-c', '--cli-output', help="Output logs in CLI", action="store_true")

    args:list = parser.parse_args()

    config:dict = {
        'server_addr': (SERVER_HOST, SERVER_PORT),
        'timezone': TIMEZONE,
        'server_certificate_filepath': SERVER_CERTIFICATE_FILEPATH,
        'client_certificate_filepath': CLIENT_CERTIFICATE_FILEPATH,
        'client_keyfile_path': CLIENT_KEYFILE_PATH,
        'client_keyfile_password': CLIENT_KEYFILE_PASSWORD,
        'client_username': CLIENT_USERNAME,
        'client_password': CLIENT_PASSWORD,
        'default_max_msg_chunk_size': DEFAULT_MAX_MSG_CHUNK_SIZE,
        'default_buffer_size': DEFAULT_BUFFER_SIZE,
        'responsecode_separator': RESPONSECODE_SEPARATOR,
        'weather_station_name': WEATHER_STATION_NAME
    }


    main()
