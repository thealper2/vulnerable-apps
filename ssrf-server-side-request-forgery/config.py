# config.py
from enum import Enum


class AllowedSchemes(str, Enum):
    """Allowed URL schemes for SSRF protection"""

    HTTP = "http"
    HTTPS = "https"


class BlocklistTargets(str, Enum):
    """Targets that should be blocked"""

    LOCALHOST = "localhost"
    PRIVATE_IP = "private_ip"
    METADATA = "metadata"


# Configuration constants
ALLOWED_DOMAINS = {"", ""}
BLOCKLIST = {"localhost", "127.0.0.1"}
MAX_REQUEST_SIZE = 1024 * 1024  # 1MB
REQUEST_TIMEOUT = 5  # seconds
