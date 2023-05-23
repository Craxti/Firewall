# firewall/logging.py
import logging
from logging.handlers import RotatingFileHandler
import yaml


def setup_logging(log_file, log_level):
    logger = logging.getLogger('firewall')
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    file_handler = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    if log_level:
        if log_level == "DEBUG":
            logger.setLevel(logging.DEBUG)
        elif log_level == "INFO":
            logger.setLevel(logging.INFO)
        elif log_level == "WARNING":
            logger.setLevel(logging.WARNING)
        elif log_level == "ERROR":
            logger.setLevel(logging.ERROR)
        elif log_level == "CRITICAL":
            logger.setLevel(logging.CRITICAL)

    return logger


def load_logging_config(config_file):
    with open(config_file, 'r') as file:
        config = yaml.safe_load(file)

    log_file = config.get('log_file', 'firewall.log')
    log_level = config.get('log_level', 'INFO')

    return log_file, log_level
