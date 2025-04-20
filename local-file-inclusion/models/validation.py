from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, validator

from models.enums import ProtectionMethod


class FileRequest(BaseModel):
    """Base model for file requests."""

    file_path: str = Field(..., description="Path to the file to be read")
    protection_method: ProtectionMethod = Field(
        default=ProtectionMethod.VULNERABLE, description="Protection method to use"
    )


class FileResponse(BaseModel):
    """Response model for file content."""

    success: bool
    content: Optional[str] = None
    error: Optional[str] = None
    protection_method: ProtectionMethod
    warnings: Optional[list[str]] = None


class FileMetadata(BaseModel):
    """Metadata about a file being accessed."""

    normalized_path: Path
    file_size: int
    mime_type: Optional[str] = None
    is_symlink: bool = False
    symlink_target: Optional[Path] = None

    @validator("normalized_path")
    def path_must_exist(cls, v: Path) -> Path:
        """Validate that the path exists."""
        if not v.exists():
            raise ValueError(f"Path does not exist: {v}")
        return v
