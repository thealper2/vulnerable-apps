# models/security_types.py
from enum import Enum
from typing import NewType

# Type aliases for better type hints
URL = NewType("URL", str)
SanitizedURL = NewType("SanitizedURL", str)
IPAddress = NewType("IPAddress", str)


class HTTPMethods(str, Enum):
    """Allowed HTTP methods for SSRF protection"""

    GET = "GET"
    POST = "POST"
    HEAD = "HEAD"
