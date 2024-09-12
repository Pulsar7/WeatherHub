import os
import time
import logging
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime
#
from .config import LOG_DIRPATH, LOG_FILENAME

# Create the log directory if it doesn't exist
if not os.path.exists(LOG_DIRPATH):
    os.makedirs(LOG_DIRPATH)

def setup_logging():
    """Set up logging configuration for the project."""

    # Create log file handler with rotation every day
    log_filename = os.path.join(LOG_DIRPATH, LOG_FILENAME)

    # TimedRotatingFileHandler rotates logs every day (midnight) and keeps 7 backups
    handler = TimedRotatingFileHandler(log_filename, when="midnight", interval=1, backupCount=7, utc=True)

    # Log format with ISO 8601 UTC time
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] [%(threadName)s] %(module)s: %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%SZ'
    )

    # Apply formatter to handler
    handler.setFormatter(formatter)

    # Set root logger settings
    logging.basicConfig(level=logging.DEBUG, handlers=[handler])

    # Ensure logs use UTC time
    logging.Formatter.converter = time.gmtime  # Use UTC for timestamps

    logging.info("Logging is set up and using ISO 8601 format with UTC time.")

