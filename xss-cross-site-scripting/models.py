from dataclasses import dataclass
from enum import Enum

from pydantic import BaseModel, constr, validator


class XSSType(str, Enum):
    """Enumeration of XSS protection types"""

    VULNERABLE = "vulnerable"
    ESCAPE_HTML = "escape-html"
    CSP = "csp"
    SANITIZE = "sanitize"
    WHITELIST = "whitelist"
    NO_JS = "no-js"
    JINJA_AUTOESCAPE = "jinja-autoescape"
    HTTPONLY_COOKIE = "httponly-cookie"
    DOM_PROTECTED = "dom-protected"


@dataclass
class UserInput:
    """Data class for user input"""

    input: str
    xss_type: XSSType


class UserInputModel(BaseModel):
    """Pydantic model for validating user input"""

    input: constr(min_length=1, max_length=500)
    xss_type: XSSType

    @validator("input")
    def escape_html_chars(cls, v):
        # This is just for validation, actual escaping happens in the endpoint
        return v
