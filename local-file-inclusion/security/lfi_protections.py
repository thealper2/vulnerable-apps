import os
import re
from pathlib import Path
from typing import Optional, Tuple

from config import config
from models.enums import ProtectionMethod
from security.file_handlers import FileHandler


class LFIProtections:
    """Implementation of various LFI protection methods."""

    @staticmethod
    def vulnerable(
        file_path: str,
    ) -> Tuple[Optional[str], Optional[str], ProtectionMethod]:
        """Vulnerable endpoint - no protection at all."""
        try:
            with open(file_path, "r") as f:
                content = f.read()
            return content, None, ProtectionMethod.VULNERABLE
        except Exception as e:
            return None, str(e), ProtectionMethod.VULNERABLE

    @staticmethod
    def allowlist(
        file_path: str,
    ) -> Tuple[Optional[str], Optional[str], ProtectionMethod]:
        """Only allow files from a predefined whitelist."""
        filename = Path(file_path).name
        if filename not in config.ALLOWED_FILES:
            return (
                None,
                f"File {filename} not in allowed list",
                ProtectionMethod.ALLOWLIST,
            )

        metadata, error = FileHandler.get_file_metadata(file_path)
        if error:
            return None, error, ProtectionMethod.ALLOWLIST

        content, error = FileHandler.read_file_safely(metadata.normalized_path)
        return content, error, ProtectionMethod.ALLOWLIST

    @staticmethod
    def extension_check(
        file_path: str,
    ) -> Tuple[Optional[str], Optional[str], ProtectionMethod]:
        """Only allow files with specific extensions."""
        path = Path(file_path)
        if path.suffix.lower() not in config.ALLOWED_EXTENSIONS:
            return (
                None,
                f"Extension {path.suffix} not allowed",
                ProtectionMethod.EXTENSION_CHECK,
            )

        metadata, error = FileHandler.get_file_metadata(file_path)
        if error:
            return None, error, ProtectionMethod.EXTENSION_CHECK

        content, error = FileHandler.read_file_safely(metadata.normalized_path)
        return content, error, ProtectionMethod.EXTENSION_CHECK

    @staticmethod
    def path_traversal_block(
        file_path: str,
    ) -> Tuple[Optional[str], Optional[str], ProtectionMethod]:
        """Block path traversal attempts."""
        if ".." in file_path or "../" in file_path or "%2e%2e" in file_path.lower():
            return (
                None,
                "Path traversal detected",
                ProtectionMethod.PATH_TRAVERSAL_BLOCK,
            )

        # Normalize path and check again
        normalized_path = os.path.normpath(file_path)
        if ".." in normalized_path or "../" in normalized_path:
            return (
                None,
                "Path traversal detected after normalization",
                ProtectionMethod.PATH_TRAVERSAL_BLOCK,
            )

        metadata, error = FileHandler.get_file_metadata(normalized_path)
        if error:
            return None, error, ProtectionMethod.PATH_TRAVERSAL_BLOCK

        content, error = FileHandler.read_file_safely(metadata.normalized_path)
        return content, error, ProtectionMethod.PATH_TRAVERSAL_BLOCK

    @staticmethod
    def absolute_path_required(
        file_path: str,
    ) -> Tuple[Optional[str], Optional[str], ProtectionMethod]:
        """Require files to be in specific allowed directories."""
        metadata, error = FileHandler.get_file_metadata(file_path)
        if error:
            return None, error, ProtectionMethod.ABSOLUTE_PATH_REQUIRED

        # Check if the path is within allowed directories
        allowed = False
        for allowed_dir in config.ALLOWED_DIRECTORIES:
            if str(metadata.normalized_path).startswith(str(allowed_dir)):
                allowed = True
                break

        if not allowed:
            return (
                None,
                "File not in allowed directories",
                ProtectionMethod.ABSOLUTE_PATH_REQUIRED,
            )

        content, error = FileHandler.read_file_safely(metadata.normalized_path)
        return content, error, ProtectionMethod.ABSOLUTE_PATH_REQUIRED

    @staticmethod
    def path_normalization(
        file_path: str,
    ) -> Tuple[Optional[str], Optional[str], ProtectionMethod]:
        """Normalize path and ensure it's within allowed directory."""
        try:
            # Normalize the path
            normalized_path = Path(file_path).absolute().resolve()

            # Ensure it's within the default allowed directory
            if not str(normalized_path).startswith(str(config.DEFAULT_ALLOWED_DIR)):
                return None, "Access denied", ProtectionMethod.PATH_NORMALIZATION

            metadata, error = FileHandler.get_file_metadata(str(normalized_path))
            if error:
                return None, error, ProtectionMethod.PATH_NORMALIZATION

            content, error = FileHandler.read_file_safely(metadata.normalized_path)
            return content, error, ProtectionMethod.PATH_NORMALIZATION
        except Exception as e:
            return None, str(e), ProtectionMethod.PATH_NORMALIZATION

    @staticmethod
    def blacklist(
        file_path: str,
    ) -> Tuple[Optional[str], Optional[str], ProtectionMethod]:
        """Block known dangerous patterns (weak protection)."""
        lower_path = file_path.lower()
        for pattern in config.BLACKLISTED_PATTERNS:
            if pattern.lower() in lower_path:
                return (
                    None,
                    f"Blacklisted pattern detected: {pattern}",
                    ProtectionMethod.BLACKLIST,
                )

        metadata, error = FileHandler.get_file_metadata(file_path)
        if error:
            return None, error, ProtectionMethod.BLACKLIST

        content, error = FileHandler.read_file_safely(metadata.normalized_path)
        return content, error, ProtectionMethod.BLACKLIST

    @staticmethod
    def regex_validation(
        file_path: str,
    ) -> Tuple[Optional[str], Optional[str], ProtectionMethod]:
        """Validate filename with strict regex pattern."""
        if not re.fullmatch(config.SAFE_FILENAME_PATTERN, file_path):
            return (
                None,
                "Filename doesn't match safe pattern",
                ProtectionMethod.REGEX_VALIDATION,
            )

        metadata, error = FileHandler.get_file_metadata(file_path)
        if error:
            return None, error, ProtectionMethod.REGEX_VALIDATION

        content, error = FileHandler.read_file_safely(metadata.normalized_path)
        return content, error, ProtectionMethod.REGEX_VALIDATION

    @staticmethod
    def mime_check(
        file_path: str,
    ) -> Tuple[Optional[str], Optional[str], ProtectionMethod]:
        """Check file MIME type before serving."""
        metadata, error = FileHandler.get_file_metadata(file_path)
        if error:
            return None, error, ProtectionMethod.MIME_CHECK

        if metadata.mime_type not in config.ALLOWED_MIME_TYPES:
            return (
                None,
                f"MIME type {metadata.mime_type} not allowed",
                ProtectionMethod.MIME_CHECK,
            )

        content, error = FileHandler.read_file_safely(metadata.normalized_path)
        return content, error, ProtectionMethod.MIME_CHECK

    @staticmethod
    def symlink_check(
        file_path: str,
    ) -> Tuple[Optional[str], Optional[str], ProtectionMethod]:
        """Check for symlinks pointing outside allowed directories."""
        metadata, error = FileHandler.get_file_metadata(file_path)
        if error:
            return None, error, ProtectionMethod.SYMLINK_CHECK

        if metadata.is_symlink:
            # Check if symlink target is within allowed directories
            target_allowed = False
            for allowed_dir in config.ALLOWED_DIRECTORIES:
                if str(metadata.symlink_target).startswith(str(allowed_dir)):
                    target_allowed = True
                    break

            if not target_allowed:
                return (
                    None,
                    "Symlink target not in allowed directories",
                    ProtectionMethod.SYMLINK_CHECK,
                )

        content, error = FileHandler.read_file_safely(metadata.normalized_path)
        return content, error, ProtectionMethod.SYMLINK_CHECK

    @staticmethod
    def file_size_limit(
        file_path: str,
    ) -> Tuple[Optional[str], Optional[str], ProtectionMethod]:
        """Enforce maximum file size limit."""
        metadata, error = FileHandler.get_file_metadata(file_path)
        if error:
            return None, error, ProtectionMethod.FILE_SIZE_LIMIT

        if metadata.file_size > config.MAX_FILE_SIZE:
            return (
                None,
                f"File size exceeds {config.MAX_FILE_SIZE} bytes limit",
                ProtectionMethod.FILE_SIZE_LIMIT,
            )

        content, error = FileHandler.read_file_safely(metadata.normalized_path)
        return content, error, ProtectionMethod.FILE_SIZE_LIMIT

    @staticmethod
    def read_limit(
        file_path: str,
    ) -> Tuple[Optional[str], Optional[str], ProtectionMethod]:
        """Basic implementation of read limit (this is more about API design)."""
        # In a real implementation, you would track requests per user/session
        # Here we just demonstrate the concept by limiting to one file read per call
        return LFIProtections.path_normalization(file_path)
