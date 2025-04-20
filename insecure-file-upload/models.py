import re
import uuid
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, validator

from config import Config


class FileUploadResponse(BaseModel):
    """Response model for file upload endpoints."""

    success: bool
    message: str
    filename: Optional[str] = None
    filepath: Optional[str] = None
    filesize: Optional[int] = None
    filetype: Optional[str] = None


class FileValidationMethod(str, Enum):
    """Enumeration of file validation methods."""

    MIME_TYPE = "mime_type"
    EXTENSION = "extension"
    MAGIC_NUMBER = "magic_number"
    SIZE_LIMIT = "size_limit"
    RANDOM_FILENAME = "random_filename"
    MALWARE_SCAN = "malware_scan"
    SANITIZE_FILENAME = "sanitize_filename"
    CONVERT_FORMAT = "convert_format"
    REMOTE_ACCESS_CONTROL = "remote_access_control"
    MULTIPART_VALIDATION = "multipart_validation"


class SecureUploadRequest(BaseModel):
    """Request model for secure file uploads."""

    file: bytes = Field(..., description="File content as bytes")
    filename: str = Field(..., description="Original filename")
    content_type: str = Field(..., description="Content-Type header value")

    @validator("filename")
    def sanitize_filename(cls, v):
        """Sanitize filename to prevent path traversal attacks."""
        if Config.SANITIZE_FILENAMES:
            # Remove directory paths
            filename = Path(v).name
            # Replace spaces
            filename = filename.replace(" ", "_")
            # Remove non-alphanumeric characters
            filename = re.sub(r"(?u)[^-\w.]", "", filename)
            return filename
        return v

    @validator("content_type")
    def validate_content_type(cls, v):
        """Validate content type against allowed MIME types."""
        if v not in Config.ALLOWED_MIME_TYPES:
            raise ValueError(f"Unsupported content type: {v}")
        return v
