"""tor-requests: Transparent Tor routing for Python.

Drop-in socket replacement that routes TCP traffic through the Tor
network without installing Tor on the operating system.

Quick Start:
    from tor_requests import tor_context
    import requests

    with tor_context():
        r = requests.get("https://check.torproject.org/api/ip")
        print(r.json())  # Shows a Tor exit node IP
"""

from __future__ import annotations

from .config import TorConfig
from .exceptions import (
    BootstrapError,
    ConfigError,
    StreamClosedError,
    StreamError,
    TorError,
    TunnelClosedError,
)


def __getattr__(name):
    """Lazy imports for components that depend on the native Rust module."""
    if name == "TorSocket":
        from .socket import TorSocket

        globals()["TorSocket"] = TorSocket
        return TorSocket
    if name == "TorTlsSocket":
        from .tls import TorTlsSocket

        globals()["TorTlsSocket"] = TorTlsSocket
        return TorTlsSocket
    if name == "AsyncTorSocket":
        from .async_socket import AsyncTorSocket

        globals()["AsyncTorSocket"] = AsyncTorSocket
        return AsyncTorSocket
    if name == "tor_context":
        from .context import tor_context

        globals()["tor_context"] = tor_context
        return tor_context
    if name == "create_session":
        from .session import create_session

        globals()["create_session"] = create_session
        return create_session
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__version__ = "0.1.0"

__all__ = [
    "TorConfig",
    "TorSocket",
    "TorTlsSocket",
    "AsyncTorSocket",
    "tor_context",
    "create_session",
    "TorError",
    "ConfigError",
    "BootstrapError",
    "TunnelClosedError",
    "StreamError",
    "StreamClosedError",
]
