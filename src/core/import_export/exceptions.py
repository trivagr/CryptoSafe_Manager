class ImportExportError(Exception):
    """Base error for vault import/export and sharing operations."""


class UnsupportedFormatError(ImportExportError):
    """Raised when an import/export format is unknown or unavailable."""


class ImportValidationError(ImportExportError):
    """Raised when imported data fails validation or sanitization."""