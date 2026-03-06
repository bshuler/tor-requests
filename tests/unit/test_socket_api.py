"""Unit tests for the TorSocket API surface.

These tests verify the socket API compatibility without requiring
a real Tor tunnel -- they use mocks for the native layer.
"""

import io
import socket as stdlib_socket
from unittest.mock import MagicMock, patch

import pytest
from tor_requests.socket import TorSocket, _SocketFileWrapper


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

    # --- sendall ---

    def test_sendall_before_connect_raises(self, sock):
        """Line 63: sendall before connect raises OSError."""
        with pytest.raises(OSError, match="Not connected"):
            sock.sendall(b"hello")

    def test_sendall_connection_closed(self, sock, mock_tunnel):
        """Line 63/70: send() returning 0 means connection closed, should raise OSError."""
        sock.connect(("example.com", 80))
        mock_tunnel.create_stream.return_value.send.return_value = 0
        with pytest.raises(OSError, match="Connection closed during send"):
            sock.sendall(b"hello")

    def test_sendall_multiple_chunks(self, sock, mock_tunnel):
        """Line 70: sendall loops when send() returns less than the total."""
        sock.connect(("example.com", 80))
        stream = mock_tunnel.create_stream.return_value
        # First call sends 2 bytes, second call sends the remaining 3
        stream.send.side_effect = [2, 3]
        sock.sendall(b"hello")
        assert stream.send.call_count == 2

    # --- recv ---

    def test_recv_when_closed(self, sock):
        """Line 77: recv on a closed socket (no stream) returns b''."""
        sock.close()
        result = sock.recv(1024)
        assert result == b""

    def test_recv_with_timeout(self, sock, mock_tunnel):
        """Lines 80-81: when _timeout is set, timeout_ms is passed to stream.recv."""
        sock.connect(("example.com", 80))
        sock.settimeout(2.5)
        stream = mock_tunnel.create_stream.return_value
        stream.recv.return_value = b"data"
        data = sock.recv(1024)
        assert data == b"data"
        stream.recv.assert_called_once_with(1024, 2500)

    # --- recv_into ---

    def test_recv_into(self, sock, mock_tunnel):
        """Lines 86-89: recv_into fills the provided buffer and returns byte count."""
        sock.connect(("example.com", 80))
        stream = mock_tunnel.create_stream.return_value
        stream.recv.return_value = b"hi"
        buf = bytearray(10)
        n = sock.recv_into(buf, 2)
        assert n == 2
        assert buf[:2] == b"hi"

    # --- _decref_socketios ---

    def test_decref_socketios(self, sock, mock_tunnel):
        """Lines 103-105: decref closes stream when socket is closed and refs drop below 1."""
        sock.connect(("example.com", 80))
        stream = mock_tunnel.create_stream.return_value
        sock._makefile_refs = 1
        sock._closed = True
        sock._decref_socketios()
        assert sock._makefile_refs == 0
        stream.close.assert_called_once()
        assert sock._stream is None

    # --- shutdown ---

    def test_shutdown(self, sock, mock_tunnel):
        """Line 109: shutdown() delegates to close()."""
        sock.connect(("example.com", 80))
        stream = mock_tunnel.create_stream.return_value
        sock.shutdown(stdlib_socket.SHUT_RDWR)
        stream.close.assert_called_once()
        assert sock._closed

    # --- setblocking ---

    def test_setblocking_true(self, sock):
        """Lines 121-122: setblocking(True) sets timeout to None."""
        sock.settimeout(5.0)
        sock.setblocking(True)
        assert sock.gettimeout() is None

    def test_setblocking_false(self, sock):
        """Lines 123-124: setblocking(False) sets timeout to 0.0."""
        sock.setblocking(False)
        assert sock.gettimeout() == 0.0

    # --- getsockopt ---

    def test_getsockopt(self, sock):
        """Line 132: getsockopt always returns 0."""
        result = sock.getsockopt(stdlib_socket.SOL_SOCKET, stdlib_socket.SO_ERROR)
        assert result == 0

    # --- getsockname ---

    def test_getsockname(self, sock):
        """Line 136: getsockname returns the wildcard address."""
        assert sock.getsockname() == ("0.0.0.0", 0)

    # --- makefile ---

    def test_makefile_adds_binary(self, sock, mock_tunnel):
        """Line 151: mode without 'b' has 'b' appended automatically."""
        sock.connect(("example.com", 80))
        f = sock.makefile("r")
        assert isinstance(f, io.BufferedReader)
        f.close()

    def test_makefile_unbuffered(self, sock, mock_tunnel):
        """Lines 156-157: buffering=0 returns the raw _SocketFileWrapper."""
        sock.connect(("example.com", 80))
        f = sock.makefile("rb", buffering=0)
        assert isinstance(f, _SocketFileWrapper)

    def test_makefile_write_mode(self, sock, mock_tunnel):
        """Lines 164-165: mode containing 'w' returns BufferedWriter."""
        sock.connect(("example.com", 80))
        f = sock.makefile("wb")
        assert isinstance(f, io.BufferedWriter)
        f.close()

    def test_makefile_rwpair_mode(self, sock, mock_tunnel):
        """Lines 166-167: mode without 'r' or 'w' returns BufferedRWPair."""
        sock.connect(("example.com", 80))
        f = sock.makefile("b")
        assert isinstance(f, io.BufferedRWPair)

    # --- wrap_tls ---

    def test_wrap_tls(self, sock, mock_tunnel):
        """Lines 171-177: wrap_tls creates a TorTlsSocket with a default SSL context."""
        sock.connect(("example.com", 443))
        with patch("tor_requests.tls.TorTlsSocket") as MockTls:
            MockTls.return_value = MagicMock()
            result = sock.wrap_tls("example.com")
            MockTls.assert_called_once()
            assert result is MockTls.return_value

    # --- family property ---

    def test_family_ipv6(self, mock_tunnel):
        """Line 182: connecting to an IPv6 address makes family return AF_INET6."""
        sock = TorSocket(mock_tunnel)
        sock.connect(("::1", 80))
        assert sock.family == stdlib_socket.AF_INET6

    # --- proto property ---

    def test_proto_property(self, sock):
        """Line 191: proto always returns 0."""
        assert sock.proto == 0

    # --- _SocketFileWrapper ---

    def test_socket_file_wrapper_readinto(self, sock, mock_tunnel):
        """Lines 211-214: readinto fills the provided buffer from sock.recv."""
        sock.connect(("example.com", 80))
        stream = mock_tunnel.create_stream.return_value
        stream.recv.return_value = b"ab"
        raw = _SocketFileWrapper(sock)
        buf = bytearray(10)
        n = raw.readinto(buf)
        assert n == 2
        assert buf[:2] == b"ab"

    def test_socket_file_wrapper_write(self, sock, mock_tunnel):
        """Lines 217-218: write calls sendall and returns the byte count."""
        sock.connect(("example.com", 80))
        stream = mock_tunnel.create_stream.return_value
        stream.send.return_value = 5
        raw = _SocketFileWrapper(sock)
        n = raw.write(b"hello")
        assert n == 5
        stream.send.assert_called()

    def test_socket_file_wrapper_writable(self, sock):
        """Line 224: writable() returns True."""
        raw = _SocketFileWrapper(sock)
        assert raw.writable() is True

    def test_socket_file_wrapper_fileno(self, sock):
        """Line 227: fileno() delegates to sock.fileno() which returns -1."""
        raw = _SocketFileWrapper(sock)
        assert raw.fileno() == -1

    def test_socket_file_wrapper_close(self, sock, mock_tunnel):
        """close() calls _decref_socketios on the underlying socket."""
        sock.connect(("example.com", 80))
        stream = mock_tunnel.create_stream.return_value
        sock._makefile_refs = 1
        raw = _SocketFileWrapper(sock)
        sock._closed = True
        raw.close()
        assert sock._makefile_refs == 0
        stream.close.assert_called_once()
        assert sock._stream is None
