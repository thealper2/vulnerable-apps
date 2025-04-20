from pathlib import Path
from typing import Optional, Tuple

import magic

from config import config
from models.validation import FileMetadata


class FileHandler:
    """Handles file operations with security checks."""

    @staticmethod
    def get_file_metadata(
        file_path: str,
    ) -> Tuple[Optional[FileMetadata], Optional[str]]:
        """Get file metadata with security checks."""
        try:
            # Normalize the path first
            normalized_path = Path(file_path).absolute().resolve()

            # Basic existence check
            if not normalized_path.exists():
                return None, "File does not exist"

            # Check if it's a directory
            if normalized_path.is_dir():
                return None, "Path is a directory, not a file"

            # Get file size
            file_size = normalized_path.stat().st_size

            # Check if it's a symlink
            is_symlink = normalized_path.is_symlink()
            symlink_target = normalized_path.resolve() if is_symlink else None

            # Get MIME type
            mime_type = None
            try:
                mime = magic.Magic(mime=True)
                mime_type = mime.from_file(str(normalized_path))
            except:
                pass

            metadata = FileMetadata(
                normalized_path=normalized_path,
                file_size=file_size,
                mime_type=mime_type,
                is_symlink=is_symlink,
                symlink_target=symlink_target,
            )

            return metadata, None
        except Exception as e:
            return None, f"Error getting file metadata: {str(e)}"

    @staticmethod
    def read_file_safely(
        file_path: Path, max_size: int = config.MAX_FILE_SIZE
    ) -> Tuple[Optional[str], Optional[str]]:
        """Read a file with size limitation."""
        try:
            # Check file size before reading
            file_size = file_path.stat().st_size
            if file_size > max_size:
                return None, f"File size {file_size} exceeds maximum allowed {max_size}"

            # Read the file
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(max_size)

            return content, None
        except Exception as e:
            return None, f"Error reading file: {str(e)}"
