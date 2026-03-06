"""Context manager for transparent Tor routing.

Provides `tor_context()` which monkeypatches `socket.socket` so that
all TCP connections in the block go through the Tor network.
"""

from __future__ import annotations

import socket as stdlib_socket
import ssl as stdlib_ssl
from contextlib import contextmanager
from typing import TYPE_CHECKING, Iterator, Optional

if TYPE_CHECKING:
    from ._native import TorTunnel

from .config import TorConfig
from .socket import TorSocket


@contextmanager
def tor_context(config: Optional[TorConfig] = None) -> Iterator[TorTunnel]:
    """Context manager that routes all TCP connections through Tor.

    Monkeypatches `socket.socket` so that any AF_INET + SOCK_STREAM socket
    creation returns a TorSocket instead. Non-TCP sockets continue to use
    the real socket implementation.

    Also monkeypatches `ssl.SSLContext.wrap_socket` so that TLS works with
    our memory BIO-based implementation.

    Args:
        config: Tor configuration. Uses defaults if None.

    Yields:
        The TorTunnel instance.

    Raises:
        RuntimeError: If tor_context() is called while already active.

    Example:
        with tor_context() as tunnel:
            import requests
            r = requests.get("https://check.torproject.org/api/ip")
            print(r.json())  # Shows a Tor exit node IP
    """
    if getattr(stdlib_socket.socket, "_tor_active", False):
        raise RuntimeError("tor_context() cannot be nested")

    from . import _native
    from .tls import TorTlsSocket

    if config is None:
        config = TorConfig()

    native_config = config.to_native()
    tunnel = _native.TorTunnel(native_config)

    original = stdlib_socket.socket

    class PatchedSocket(original):
        """socket.socket subclass that intercepts TCP connections."""

        _tor_active = True

        def __new__(
            cls,
            family: int = stdlib_socket.AF_INET,
            type: int = stdlib_socket.SOCK_STREAM,
            proto: int = 0,
            fileno=None,
        ):
            if (
                family in (stdlib_socket.AF_INET, stdlib_socket.AF_INET6)
                and (type & stdlib_socket.SOCK_STREAM)
                and fileno is None
            ):
                return TorSocket(tunnel)
            return original(family, type, proto, fileno)

    original_wrap_socket = stdlib_ssl.SSLContext.wrap_socket

    def patched_wrap_socket(self, sock, *args, **kwargs):
        if isinstance(sock, TorSocket):
            server_hostname = kwargs.get("server_hostname")
            return TorTlsSocket(
                sock,
                self,
                server_hostname=server_hostname,
            )
        return original_wrap_socket(self, sock, *args, **kwargs)

    stdlib_socket.socket = PatchedSocket
    stdlib_ssl.SSLContext.wrap_socket = patched_wrap_socket

    try:
        yield tunnel
    finally:
        stdlib_socket.socket = original
        stdlib_ssl.SSLContext.wrap_socket = original_wrap_socket
        tunnel.close()
