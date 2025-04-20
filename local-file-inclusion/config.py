from pathlib import Path
from typing import List, Set


class Config:
    # Allowed directories for file access
    ALLOWED_DIRECTORIES: Set[Path] = {
        Path("allowed_files").absolute(),
        Path("static").absolute(),
    }

    # Default allowed directory
    DEFAULT_ALLOWED_DIR: Path = Path("allowed_files").absolute()

    # Allowed file extensions
    ALLOWED_EXTENSIONS: Set[str] = {".txt", ".log", ".csv"}

    # Allowed filenames (whitelist approach)
    ALLOWED_FILES: Set[str] = {"readme.txt", "notes.txt", "data.csv"}

    # Blacklisted patterns
    BLACKLISTED_PATTERNS: List[str] = ["..", "/etc", "/passwd", "~", ".ssh", ".config"]

    # Maximum file size (1MB)
    MAX_FILE_SIZE: int = 1024 * 1024

    # Regex pattern for safe filenames
    SAFE_FILENAME_PATTERN: str = r"^[a-zA-Z0-9_\-\/]+\.(txt|log|csv)$"

    # Allowed MIME types
    ALLOWED_MIME_TYPES: Set[str] = {"text/plain", "text/csv", "application/json"}


config = Config()
