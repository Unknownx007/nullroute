# ============================================================
#  File: nullroute/core/errors.py
# ============================================================
class NullrouteError(Exception):
    """Base class for all NULLROUTE errors."""


class HttpError(NullrouteError):
    """Raised when an HTTP request fails."""


class FetchError(NullrouteError):
    """Raised when fetching page assets fails."""


class ParseError(NullrouteError):
    """Raised when HTML/JS parsing fails."""


class AnalysisError(NullrouteError):
    """Raised when an analyzer fails."""
