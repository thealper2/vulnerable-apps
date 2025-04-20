import re
from typing import Union

from config import Config


def validate_input(input_str: Union[str, int, float]) -> bool:
    """
    Validate input against whitelist of allowed characters.
    Returns True if input is safe, False if potentially malicious.
    """
    if not isinstance(input_str, str):
        return True
        
    # Check length
    if len(input_str) > Config.MAX_INPUT_LENGTH:
        return False
        
    # Check against whitelist regex
    if not re.match(Config.ALLOWED_CHARS, input_str):
        return False
        
    return True