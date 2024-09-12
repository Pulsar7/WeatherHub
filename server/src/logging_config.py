import os
import time
import logging
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
#
from .config import LOG_DIRPATH, LOG_FILENAME

# Create the log directory if it doesn't exist
if not os.path.exists(LOG_DIRPATH):
    os.makedirs(LOG_DIRPATH)

def setup_logging(cli_output:bool=False):
    """Set up logging configuration for the project."""

    # Create log file handler with rotation every day
    log_filename = os.path.join(LOG_DIRPATH, LOG_FILENAME)

    # TimedRotatingFileHandler rotates logs every day (midnight) and keeps 7 backups
    file_handler = TimedRotatingFileHandler(log_filename, when="midnight", interval=1, backupCount=7, utc=True)

    # Log format with ISO 8601 UTC time
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] [%(threadName)s] %(module)s: %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%SZ'
    )

    # Apply formatter to file_handler
    file_handler.setFormatter(formatter)

    handlers:list = [file_handler]

    if cli_output:
        # Console log handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        handlers.append(console_handler)

    # Set root logger settings
    logging.basicConfig(level=logging.DEBUG, handlers=handlers)

    # Ensure logs use UTC time
    logging.Formatter.converter = time.gmtime  # Use UTC for timestamps

    logging.info("Logging is set up and using ISO 8601 format with UTC time.")

