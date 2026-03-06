"""Convenience helpers for using tor-requests with the requests library."""

from __future__ import annotations

import threading
from typing import Optional

from .config import TorConfig
from .socket import TorSocket

_create_connection_lock = threading.Lock()


def create_session(config: Optional[TorConfig] = None, **kwargs):
    """Create a requests.Session that routes all traffic through Tor.

    Args:
        config: Tor configuration. Uses defaults if None.
        **kwargs: Additional arguments passed to requests.Session.

    Returns:
        A requests.Session with Tor routing enabled.

    Example:
        session = create_session()
        response = session.get("https://check.torproject.org/api/ip")
        print(response.json())  # Shows a Tor exit node IP
        session.close()
    """
    try:
        import requests
        import urllib3.util.connection  # noqa: F401
    except ImportError:
        raise ImportError(
            "The 'requests' package is required for create_session(). "
            "Install it with: pip install tor-requests[requests]"
        )

    from . import _native

    if config is None:
        config = TorConfig()

    native_config = config.to_native()
    tunnel = _native.TorTunnel(native_config)

    class TorAdapter(requests.adapters.HTTPAdapter):
        def __init__(self, tor_tunnel, **adapter_kwargs):
            self._tor_tunnel = tor_tunnel
            super().__init__(**adapter_kwargs)

        def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
            import urllib3.util.connection

            original_create_connection = urllib3.util.connection.create_connection

            def tor_create_connection(
                address, timeout=None, source_address=None, socket_options=None
            ):
                sock = TorSocket(self._tor_tunnel)
                if timeout is not None:
                    sock.settimeout(timeout)
                sock.connect(address)
                return sock

            with _create_connection_lock:
                urllib3.util.connection.create_connection = tor_create_connection
                try:
                    return super().send(request, stream, timeout, verify, cert, proxies)
                finally:
                    urllib3.util.connection.create_connection = original_create_connection

    session = requests.Session(**kwargs) if kwargs else requests.Session()

    adapter = TorAdapter(tunnel)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session._tor_tunnel = tunnel

    original_close = session.close

    def close_with_tunnel():
        original_close()
        tunnel.close()

    session.close = close_with_tunnel

    return session
