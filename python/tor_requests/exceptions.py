"""Exception hierarchy for tor-requests.

Note: The native Rust extension currently raises standard Python exceptions:
    - RuntimeError: Tor bootstrap failures, channel errors
    - ConnectionError: Connection failures, stream/tunnel closed
    - TimeoutError: Operation timed out
    - OSError: I/O errors
    - ValueError: Configuration errors

These custom exception classes are provided for future use and for
application code that wants a unified exception hierarchy. You can
catch TorError as a base class in combination with the standard
exceptions above.
"""

from __future__ import annotations


class TorError(Exception):
    """Base exception for all tor-requests errors."""


class ConfigError(TorError):
    """Error in Tor configuration."""


class BootstrapError(TorError):
    """Error during Tor client bootstrap."""


class TunnelClosedError(TorError):
    """Raised when attempting to use a closed tunnel."""


class StreamError(TorError):
    """Error during stream I/O (connect, send, recv)."""


class StreamClosedError(StreamError):
    """Raised when attempting to use a closed stream."""
