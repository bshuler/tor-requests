"""Unit tests for tor_requests __init__ lazy imports."""
import sys
from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def mock_native(monkeypatch):
    """Mock _native so imports don't fail."""
    mock = MagicMock()
    monkeypatch.setitem(sys.modules, "tor_requests._native", mock)
    return mock


class TestLazyImports:
    def test_import_tor_socket(self):
        import tor_requests
        # Clear any cached value
        tor_requests.__dict__.pop("TorSocket", None)
        result = tor_requests.TorSocket
        from tor_requests.socket import TorSocket
        assert result is TorSocket

    def test_import_tor_tls_socket(self):
        import tor_requests
        tor_requests.__dict__.pop("TorTlsSocket", None)
        result = tor_requests.TorTlsSocket
        from tor_requests.tls import TorTlsSocket
        assert result is TorTlsSocket

    def test_import_async_tor_socket(self):
        import tor_requests
        tor_requests.__dict__.pop("AsyncTorSocket", None)
        result = tor_requests.AsyncTorSocket
        from tor_requests.async_socket import AsyncTorSocket
        assert result is AsyncTorSocket

    def test_import_tor_context(self):
        import tor_requests
        tor_requests.__dict__.pop("tor_context", None)
        result = tor_requests.tor_context
        from tor_requests.context import tor_context
        assert result is tor_context

    def test_import_create_session(self):
        import tor_requests
        tor_requests.__dict__.pop("create_session", None)
        result = tor_requests.create_session
        from tor_requests.session import create_session
        assert result is create_session

    def test_unknown_attribute_raises(self):
        import tor_requests
        with pytest.raises(AttributeError, match="no attribute"):
            _ = tor_requests.nonexistent_thing

    def test_version(self):
        import tor_requests
        assert tor_requests.__version__ == "0.1.0"

    def test_cached_after_first_access(self):
        import tor_requests
        tor_requests.__dict__.pop("TorSocket", None)
        first = tor_requests.TorSocket
        second = tor_requests.TorSocket  # Should use cached globals()
        assert first is second
