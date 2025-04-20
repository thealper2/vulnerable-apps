import imghdr
import re
import uuid
from pathlib import Path
from typing import Optional, Tuple

import magic

from config import Config


def validate_file_size(file_data: bytes) -> bool:
    """Validate that file size is within allowed limits."""
    return len(file_data) <= Config.MAX_FILE_SIZE


def validate_file_extension(filename: str) -> bool:
    """Validate file extension against allowed extensions."""
    file_ext = Path(filename).suffix.lower()
    return file_ext in Config.ALLOWED_EXTENSIONS


def validate_magic_number(file_data: bytes, expected_type: str) -> bool:
    """Validate file signature (magic number) matches expected type."""
    if expected_type not in Config.MAGIC_NUMBERS:
        return False

    magic_number = Config.MAGIC_NUMBERS[expected_type]
    return file_data.startswith(magic_number)


def randomize_filename(filename: str) -> str:
    """Generate a random filename while preserving the extension."""
    ext = Path(filename).suffix
    return f"{uuid.uuid4().hex}{ext}"


def scan_for_malicious_content(file_data: bytes) -> bool:
    """
    Basic scan for malicious content in files.
    In a real application, this would use an antivirus API.
    """
    # Simple check for PHP tags (very basic example)
    php_tags = [b"<?php", b"<?=", b"<? ", b"<%", b"%>"]
    return not any(tag in file_data for tag in php_tags)


def get_file_mime_type(file_data: bytes) -> str:
    """Detect MIME type from file content."""
    mime = magic.Magic(mime=True)
    return mime.from_buffer(file_data)


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal and other attacks."""
    # Normalize path
    filename = str(Path(filename).name)

    # Replace spaces
    filename = filename.replace(" ", "_")

    # Remove non-alphanumeric characters
    filename = re.sub(r"(?u)[^-\w.]", "", filename)

    return filename
