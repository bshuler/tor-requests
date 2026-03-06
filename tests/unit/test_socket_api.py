"""Unit tests for the TorSocket API surface.

These tests verify the socket API compatibility without requiring
a real Tor tunnel -- they use mocks for the native layer.
"""

import socket as stdlib_socket
from unittest.mock import MagicMock

import pytest
from tor_requests.socket import TorSocket


@pytest.fixture
def mock_tunnel():
    """Create a mock TorTunnel."""
    tunnel = MagicMock()
    tunnel._isolation = False
    stream = MagicMock()
    stream.send.return_value = 5
    stream.recv.return_value = b"hello"
    tunnel.create_stream.return_value = stream
    tunnel.create_isolated_stream.return_value = stream
    return tunnel


@pytest.fixture
def sock(mock_tunnel):
    """Create a TorSocket with a mock tunnel."""
    return TorSocket(mock_tunnel)


class TestTorSocket:
    def test_initial_state(self, sock):
        assert sock.fileno() == -1
        assert sock.family == stdlib_socket.AF_INET
        assert sock.type == stdlib_socket.SOCK_STREAM
        assert sock.gettimeout() is None

    def test_connect(self, sock, mock_tunnel):
        sock.connect(("example.com", 443))
        mock_tunnel.create_stream.assert_called_once_with("example.com", 443)
        assert sock.getpeername() == ("example.com", 443)

    def test_connect_twice_raises(self, sock):
        sock.connect(("example.com", 443))
        with pytest.raises(OSError, match="Already connected"):
            sock.connect(("example.com", 80))

    def test_send_before_connect_raises(self, sock):
        with pytest.raises(OSError, match="Not connected"):
            sock.send(b"hello")

    def test_recv_before_connect_raises(self, sock):
        with pytest.raises(OSError, match="Not connected"):
            sock.recv(1024)

    def test_send(self, sock, mock_tunnel):
        sock.connect(("example.com", 80))
        n = sock.send(b"hello")
        assert n == 5

    def test_recv(self, sock, mock_tunnel):
        sock.connect(("example.com", 80))
        data = sock.recv(1024)
        assert data == b"hello"

    def test_sendall(self, sock, mock_tunnel):
        sock.connect(("example.com", 80))
        mock_tunnel.create_stream.return_value.send.return_value = 5
        sock.sendall(b"hello")

    def test_close(self, sock, mock_tunnel):
        sock.connect(("example.com", 80))
        sock.close()
        mock_tunnel.create_stream.return_value.close.assert_called_once()

    def test_close_idempotent(self, sock, mock_tunnel):
        sock.connect(("example.com", 80))
        sock.close()
        sock.close()  # Should not raise.

    def test_settimeout(self, sock):
        sock.settimeout(5.0)
        assert sock.gettimeout() == 5.0

    def test_setsockopt_noop(self, sock):
        sock.setsockopt(stdlib_socket.SOL_SOCKET, stdlib_socket.SO_REUSEADDR, 1)

    def test_getpeername_before_connect(self, sock):
        with pytest.raises(OSError, match="Not connected"):
            sock.getpeername()

    def test_context_manager(self, mock_tunnel):
        with TorSocket(mock_tunnel) as sock:
            sock.connect(("example.com", 80))
        mock_tunnel.create_stream.return_value.close.assert_called()

    def test_makefile(self, sock, mock_tunnel):
        sock.connect(("example.com", 80))
        f = sock.makefile("rb")
        assert f.readable()
        f.close()

    def test_repr_idle(self, sock):
        r = repr(sock)
        assert "idle" in r

    def test_repr_connected(self, sock):
        sock.connect(("example.com", 80))
        r = repr(sock)
        assert "connected" in r
        assert "example.com" in r

    def test_connect_after_close_raises(self, sock):
        sock.close()
        with pytest.raises(OSError, match="closed"):
            sock.connect(("example.com", 80))

    def test_isolation_uses_isolated_stream(self, mock_tunnel):
        mock_tunnel._isolation = True
        sock = TorSocket(mock_tunnel)
        sock.connect(("example.com", 443))
        mock_tunnel.create_isolated_stream.assert_called_once_with("example.com", 443)
