import logging
from logging.handlers import RotatingFileHandler
from typing import Any, Dict

from flask import Request


def setup_logging():
    """Configure application logging"""
    logging.basicConfig(level=logging.INFO)
    
    # Create a file handler that logs even debug messages
    handler = RotatingFileHandler(
        'logs/sql_injection_demo.log',
        maxBytes=10000,
        backupCount=1
    )
    handler.setLevel(logging.INFO)
    
    # Create a logging format
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    # Add the handlers to the root logger
    logging.getLogger().addHandler(handler)

def log_attack_attempt(request: Request, endpoint: str, payload: Dict[str, Any], blocked: bool):
    """Log SQL injection attempt details"""
    logger = logging.getLogger('security')
    log_message = (
        f"SQL Injection Attempt - "
        f"Endpoint: {endpoint} - "
        f"IP: {request.remote_addr} - "
        f"Payload: {payload} - "
        f"Blocked: {blocked}"
    )
    logger.warning(log_message)