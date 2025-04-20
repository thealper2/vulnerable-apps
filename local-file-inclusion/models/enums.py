from enum import Enum


class ProtectionMethod(str, Enum):
    """Enumeration of LFI protection methods implemented in the API."""

    VULNERABLE = "vulnerable"
    ALLOWLIST = "allowlist"
    EXTENSION_CHECK = "extension_check"
    PATH_TRAVERSAL_BLOCK = "path_traversal_block"
    ABSOLUTE_PATH_REQUIRED = "absolute_path_required"
    PATH_NORMALIZATION = "path_normalization"
    BLACKLIST = "blacklist"
    REGEX_VALIDATION = "regex_validation"
    MIME_CHECK = "mime_check"
    SYMLINK_CHECK = "symlink_check"
    FILE_SIZE_LIMIT = "file_size_limit"
    READ_LIMIT = "read_limit"
