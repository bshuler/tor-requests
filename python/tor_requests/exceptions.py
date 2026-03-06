"""Exception hierarchy for tor-requests."""

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
