import re
from typing import Optional

import bleach


def sanitize_input(input_str: str) -> str:
    """Sanitize input using bleach library"""
    return bleach.clean(input_str, tags=[], attributes={}, styles=[], strip=True)


def whitelist_input(input_str: str) -> Optional[str]:
    """Allow only alphanumeric and basic punctuation"""
    if re.match(r"^[a-zA-Z0-9\s.,!?]+$", input_str):
        return input_str
    return None


def set_secure_headers(response, csp: bool = False):
    """Set secure headers for the response"""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"

    if csp:
        # Strict CSP policy that blocks all inline scripts and only allows same origin
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
        )
    return response
