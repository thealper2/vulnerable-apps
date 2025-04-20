import uuid
from pathlib import Path
from typing import Optional

from config import Config


def secure_file_storage(
    file_data: bytes,
    original_filename: str,
    content_type: str,
    validation_methods: list,
) -> Optional[Path]:
    """
    Securely store a file after applying all specified validation methods.

    Args:
        file_data: The file content as bytes
        original_filename: The original filename
        content_type: The content type from the request
        validation_methods: List of validation methods to apply

    Returns:
        Path to the saved file if successful, None otherwise
    """
    from utils.file_validation import (
        get_file_mime_type,
        randomize_filename,
        sanitize_filename,
        scan_for_malicious_content,
        validate_file_extension,
        validate_file_size,
        validate_magic_number,
    )

    # Apply validations based on the specified methods
    try:
        # Always validate size
        if not validate_file_size(file_data):
            raise ValueError("File size exceeds allowed limit")

        filename = original_filename

        # Apply security measures based on validation methods
        if "sanitize_filename" in validation_methods:
            filename = sanitize_filename(filename)

        if "random_filename" in validation_methods:
            filename = randomize_filename(filename)

        if "extension" in validation_methods:
            if not validate_file_extension(filename):
                raise ValueError("File extension not allowed")

        if "mime_type" in validation_methods:
            detected_mime = get_file_mime_type(file_data)
            if detected_mime not in Config.ALLOWED_MIME_TYPES:
                raise ValueError(f"Detected MIME type {detected_mime} not allowed")

        if "magic_number" in validation_methods:
            detected_mime = get_file_mime_type(file_data)
            if not validate_magic_number(file_data, detected_mime):
                raise ValueError("File signature doesn't match content type")

        if "malware_scan" in validation_methods:
            if not scan_for_malicious_content(file_data):
                raise ValueError("File contains potentially malicious content")

        # Save the file
        filepath = Config.SECURE_UPLOAD_FOLDER / filename
        with open(filepath, "wb") as f:
            f.write(file_data)

        return filepath

    except Exception as e:
        print(f"Error during secure file storage: {str(e)}")
        return None
