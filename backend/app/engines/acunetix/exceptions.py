"""Acunetix exception hierarchy."""


class AcunetixError(Exception):
    """Base exception for all Acunetix engine errors."""
    pass


class AcunetixAuthError(AcunetixError):
    """Raised when Acunetix API authentication fails."""
    pass


class AcunetixConnectionError(AcunetixError):
    """Raised when network connection to Acunetix host fails."""
    pass


class AcunetixTargetNotFoundError(AcunetixError):
    """Raised when a specified target is not found in Acunetix."""
    pass


class AcunetixScanExecutionError(AcunetixError):
    """Raised when starting or controlling a scan fails."""
    pass


class AcunetixRateLimitError(AcunetixError):
    """Raised when Acunetix API rate limit is exceeded."""
    pass
