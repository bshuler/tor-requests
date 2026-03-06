"""Unit tests for the tor_context context manager."""

import socket as stdlib_socket
import ssl as stdlib_ssl
import sys
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def mock_native(monkeypatch):
    """Mock the _native module."""
    mock = MagicMock()
    mock.TorConfig.return_value = MagicMock()
    tunnel = MagicMock()
    mock.TorTunnel.return_value = tunnel
    monkeypatch.setitem(sys.modules, "tor_requests._native", mock)
    return mock, tunnel


class TestTorContext:
    def test_monkeypatch_and_restore(self, mock_native):
        from tor_requests.config import TorConfig
        from tor_requests.context import tor_context

        original_socket = stdlib_socket.socket
        original_wrap = stdlib_ssl.SSLContext.wrap_socket

        config = TorConfig()
        with tor_context(config):
            assert stdlib_socket.socket is not original_socket
            assert stdlib_ssl.SSLContext.wrap_socket is not original_wrap

        assert stdlib_socket.socket is original_socket
        assert stdlib_ssl.SSLContext.wrap_socket is original_wrap

    def test_restores_on_exception(self, mock_native):
        from tor_requests.config import TorConfig
        from tor_requests.context import tor_context

        original_socket = stdlib_socket.socket
        config = TorConfig()

        with pytest.raises(RuntimeError):
            with tor_context(config):
                raise RuntimeError("test error")

        assert stdlib_socket.socket is original_socket

    def test_tunnel_closed_on_exit(self, mock_native):
        from tor_requests.config import TorConfig
        from tor_requests.context import tor_context

        _, tunnel = mock_native
        config = TorConfig()

        with tor_context(config):
            pass

        tunnel.close.assert_called_once()

    def test_default_config(self, mock_native):
        from tor_requests.context import tor_context

        with tor_context():
            pass

    def test_yields_tunnel(self, mock_native):
        from tor_requests.config import TorConfig
        from tor_requests.context import tor_context

        _, tunnel = mock_native
        config = TorConfig()

        with tor_context(config) as t:
            assert t is tunnel
