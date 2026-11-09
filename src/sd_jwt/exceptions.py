"""
SD-JWT Exceptions Module.

Defines standardized exception classes for SD-JWT processing, including
time claim validation errors (exp, nbf, iat) and claim conflicts.
"""


class SDJWTException(Exception):
    """Base exception for all SD-JWT errors."""

    pass


class SDJWTHasSDClaimException(SDJWTException):
    """Exception raised when input data contains the special _sd claim reserved for SD-JWT internal data."""

    def __init__(self, error_location: any):
        super().__init__(
            f"Input data contains the special claim '_sd' reserved for SD-JWT internal data. Location: {error_location!r}"
        )


class SDJWTTimeValidationException(SDJWTException, ValueError):
    """Base exception for time-based JWT validation errors (exp, nbf, iat)."""

    pass


class SDJWTExpiredException(SDJWTTimeValidationException):
    """Raised when an SD-JWT credential or Key Binding JWT has expired (current_time >= exp + clock_skew)."""

    pass


class SDJWTNotYetValidException(SDJWTTimeValidationException):
    """Raised when an SD-JWT credential or Key Binding JWT is not yet valid (nbf or future iat)."""

    pass
