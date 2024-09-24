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


class ModuleFilter(logging.Filter):
    """Filter out log records from the 'base' module."""
    def filter(self, record):
        # Suppress messages where the module is 'base'
        return record.module != 'base'


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
    # Add custom filter to suppress messages from 'base' module
    file_handler.addFilter(ModuleFilter())

    handlers:list = [file_handler]

    if cli_output:
        # Console log handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        handlers.append(console_handler)

    # Set root logger settings
    #logging.basicConfig(level=logging.DEBUG, handlers=handlers)
    # Set root logger settings
    root_logger = logging.getLogger()  # Get the root logger
    root_logger.setLevel(logging.DEBUG)  # Global log level
    for handler in handlers:
        root_logger.addHandler(handler)


    # Ensure logs use UTC time
    logging.Formatter.converter = time.gmtime  # Use UTC for timestamps

    # Suppress SQLAlchemy INFO logs at various levels
    sqlalchemy_logger = logging.getLogger('sqlalchemy')
    sqlalchemy_logger.handlers.clear()  # Remove any existing handlers to avoid conflicts
    sqlalchemy_logger.setLevel(logging.WARNING)

    logging.info("Logging is set up and using ISO 8601 format with UTC time.")
