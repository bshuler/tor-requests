"""Unit tests for TorTlsSocket."""

import ssl
from unittest.mock import MagicMock, patch

import pytest
from tor_requests.tls import TorTlsSocket


@pytest.fixture
def mock_tor_socket():
    """Create a mock TorSocket."""
    sock = MagicMock()
    sock._remote_addr = ("example.com", 443)
    sock.family = 2  # AF_INET
    sock.gettimeout.return_value = None
    # Make recv return some data for the handshake
    sock.recv.return_value = b""
    sock.getpeername.return_value = ("example.com", 443)
    return sock


class TestTorTlsSocket:
    def test_fileno_returns_minus_one(self, mock_tor_socket):
        with patch.object(ssl.SSLContext, "wrap_bio") as mock_wrap:
            mock_sslobj = MagicMock()
            mock_wrap.return_value = mock_sslobj
            mock_sslobj.do_handshake.return_value = None

            tls = TorTlsSocket(
                mock_tor_socket,
                ssl.create_default_context(),
                server_hostname="example.com",
            )
            assert tls.fileno() == -1

    def test_getpeername(self, mock_tor_socket):
        with patch.object(ssl.SSLContext, "wrap_bio") as mock_wrap:
            mock_sslobj = MagicMock()
            mock_wrap.return_value = mock_sslobj
            mock_sslobj.do_handshake.return_value = None

            tls = TorTlsSocket(
                mock_tor_socket,
                ssl.create_default_context(),
                server_hostname="example.com",
            )
            assert tls.getpeername() == ("example.com", 443)

    def test_close_idempotent(self, mock_tor_socket):
        with patch.object(ssl.SSLContext, "wrap_bio") as mock_wrap:
            mock_sslobj = MagicMock()
            mock_wrap.return_value = mock_sslobj
            mock_sslobj.do_handshake.return_value = None

            tls = TorTlsSocket(
                mock_tor_socket,
                ssl.create_default_context(),
                server_hostname="example.com",
            )
            tls.close()
            tls.close()  # Should not raise

    def test_context_manager(self, mock_tor_socket):
        with patch.object(ssl.SSLContext, "wrap_bio") as mock_wrap:
            mock_sslobj = MagicMock()
            mock_wrap.return_value = mock_sslobj
            mock_sslobj.do_handshake.return_value = None

            with TorTlsSocket(
                mock_tor_socket,
                ssl.create_default_context(),
                server_hostname="example.com",
            ) as tls:
                assert tls is not None
