# models/request_models.py
from typing import Optional

from pydantic import BaseModel, field_validator

from .security_types import HTTPMethods


class SSRFRequest(BaseModel):
    """Base model for SSRF vulnerable endpoint"""

    url: str
    method: HTTPMethods = HTTPMethods.GET
    headers: Optional[dict] = None

    @field_validator("url")
    def validate_url(cls, v):
        if not v:
            raise ValueError("URL cannot be empty")
        return v


class ProtectedSSRFRequest(SSRFRequest):
    """Model for protected endpoints with additional validation"""

    pass
