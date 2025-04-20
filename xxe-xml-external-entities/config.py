from enum import Enum


class Config(Enum):
    """Application configuration constants"""

    UPLOAD_FOLDER = "uploads"
    ALLOWED_EXTENSIONS = {"txt", "pdf", "png"}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
