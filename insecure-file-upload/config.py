from enum import Enum
from pathlib import Path
from typing import Dict, List, Set

# Base directory
BASE_DIR = Path(__file__).parent


class AllowedMimeTypes(str, Enum):
    """Enumeration of allowed MIME types for secure uploads."""

    JPEG = "image/jpeg"
    PNG = "image/png"
    PDF = "application/pdf"
    GIF = "image/gif"
    PLAIN_TEXT = "text/plain"


class AllowedExtensions(str, Enum):
    """Enumeration of allowed file extensions for secure uploads."""

    JPG = ".jpg"
    JPEG = ".jpeg"
    PNG = ".png"
    PDF = ".pdf"
    GIF = ".gif"
    TXT = ".txt"


# Configuration settings
class Config:
    # File upload settings
    MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB
    UPLOAD_FOLDER = BASE_DIR / "uploads"
    SECURE_UPLOAD_FOLDER = UPLOAD_FOLDER / "secure"
    INSECURE_UPLOAD_FOLDER = UPLOAD_FOLDER / "insecure"

    # Allowed settings
    ALLOWED_MIME_TYPES: Set[str] = {mime.value for mime in AllowedMimeTypes}
    ALLOWED_EXTENSIONS: Set[str] = {ext.value for ext in AllowedExtensions}

    # Magic numbers for file signature validation
    MAGIC_NUMBERS: Dict[str, bytes] = {
        "image/jpeg": b"\xff\xd8\xff",
        "image/png": b"\x89PNG\r\n\x1a\n",
        "application/pdf": b"%PDF",
        "image/gif": b"GIF87a" + b";",
    }

    # Security settings
    RANDOMIZE_FILENAMES = True
    SANITIZE_FILENAMES = True
    SCAN_FOR_MALICIOUS_CONTENT = True
    CONVERT_IMAGES_TO_JPG = False

    @classmethod
    def init_app(cls):
        """Initialize application directories."""
        cls.UPLOAD_FOLDER.mkdir(exist_ok=True)
        cls.SECURE_UPLOAD_FOLDER.mkdir(exist_ok=True)
        cls.INSECURE_UPLOAD_FOLDER.mkdir(exist_ok=True)
