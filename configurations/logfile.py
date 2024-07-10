import logging
from logging.handlers import TimedRotatingFileHandler
import datetime

def setup_logger(log_file_format="TrustMe_%Y-%m-%d.log", log_level=logging.INFO, filename=None):
    """
    Set up a rotating logger with a specified log file format and log level.

    Args:
        log_file_format (str): Log file name format using strftime codes.
        log_level (int): Logging level (default is logging.INFO).
    """
    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    handler = TimedRotatingFileHandler(datetime.datetime.now().strftime(log_file_format), when="midnight", interval=1, backupCount=7)
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    return logger

