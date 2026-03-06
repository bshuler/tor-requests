"""Unit tests for TorTlsSocket."""

import io
import socket as stdlib_socket
import ssl
from unittest.mock import MagicMock, patch

import pytest
from tor_requests.tls import TorTlsSocket, _TlsFileWrapper


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


@pytest.fixture
def tls_socket(mock_tor_socket):
    """Create a TorTlsSocket with a mocked SSLObject."""
    with patch.object(ssl.SSLContext, "wrap_bio") as mock_wrap:
        mock_sslobj = MagicMock()
        mock_wrap.return_value = mock_sslobj
        mock_sslobj.do_handshake.return_value = None
        tls = TorTlsSocket(
            mock_tor_socket,
            ssl.create_default_context(),
            server_hostname="example.com",
        )
        tls._mock_sslobj = mock_sslobj  # Store for test access
        yield tls


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

    def test_do_handshake_want_read(self, mock_tor_socket):
        """Handshake retries on SSLWantReadError then succeeds."""
        with patch.object(ssl.SSLContext, "wrap_bio") as mock_wrap:
            mock_sslobj = MagicMock()
            mock_wrap.return_value = mock_sslobj
            # First call raises SSLWantReadError, second succeeds
            mock_sslobj.do_handshake.side_effect = [
                ssl.SSLWantReadError("want read"),
                None,
            ]
            mock_tor_socket.recv.return_value = b"some data"

            TorTlsSocket(
                mock_tor_socket,
                ssl.create_default_context(),
                server_hostname="example.com",
            )
            assert mock_sslobj.do_handshake.call_count == 2

    def test_do_handshake_want_write(self, mock_tor_socket):
        """Handshake retries on SSLWantWriteError then succeeds."""
        with patch.object(ssl.SSLContext, "wrap_bio") as mock_wrap:
            mock_sslobj = MagicMock()
            mock_wrap.return_value = mock_sslobj
            # First call raises SSLWantWriteError, second succeeds
            mock_sslobj.do_handshake.side_effect = [
                ssl.SSLWantWriteError("want write"),
                None,
            ]

            TorTlsSocket(
                mock_tor_socket,
                ssl.create_default_context(),
                server_hostname="example.com",
            )
            assert mock_sslobj.do_handshake.call_count == 2

    def test_no_handshake_on_connect(self, mock_tor_socket):
        """do_handshake_on_connect=False skips handshake at construction."""
        with patch.object(ssl.SSLContext, "wrap_bio") as mock_wrap:
            mock_sslobj = MagicMock()
            mock_wrap.return_value = mock_sslobj

            TorTlsSocket(
                mock_tor_socket,
                ssl.create_default_context(),
                server_hostname="example.com",
                do_handshake_on_connect=False,
            )
            mock_sslobj.do_handshake.assert_not_called()

    def test_send(self, tls_socket):
        """send() writes data to sslobj and flushes."""
        tls_socket._mock_sslobj.write.return_value = 4
        result = tls_socket.send(b"data")
        tls_socket._mock_sslobj.write.assert_called_once_with(b"data")
        assert result == 4

    def test_sendall(self, tls_socket):
        """sendall() sends all data via the sslobj write loop."""
        tls_socket._mock_sslobj.write.return_value = 4
        tls_socket.sendall(b"data")
        tls_socket._mock_sslobj.write.assert_called_once()

    def test_sendall_partial(self, tls_socket):
        """sendall() loops until all data is sent when write returns partial count."""
        tls_socket._mock_sslobj.write.side_effect = [2, 2]
        tls_socket.sendall(b"data")
        assert tls_socket._mock_sslobj.write.call_count == 2

    def test_recv_success(self, tls_socket):
        """recv() returns data from sslobj.read."""
        tls_socket._mock_sslobj.read.return_value = b"hello"
        result = tls_socket.recv(1024)
        assert result == b"hello"
        tls_socket._mock_sslobj.read.assert_called_once_with(1024)

    def test_recv_want_read_then_empty(self, tls_socket):
        """recv() returns b"" when SSLWantReadError and no incoming pending data."""
        tls_socket._mock_sslobj.read.side_effect = ssl.SSLWantReadError("want read")
        # _incoming.pending will be 0 (no data received into the BIO)
        mock_tor_socket = tls_socket._sock
        mock_tor_socket.recv.return_value = b""

        result = tls_socket.recv(1024)
        assert result == b""

    def test_recv_want_read_then_data(self, tls_socket):
        """recv() retries after SSLWantReadError when incoming data is pending."""
        call_count = 0

        def read_side_effect(bufsize):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ssl.SSLWantReadError("want read")
            return b"hello"

        tls_socket._mock_sslobj.read.side_effect = read_side_effect
        # Make _pull_incoming write data so pending > 0
        tls_socket._sock.recv.return_value = b"encrypted"
        # We need _incoming.pending to be non-zero after _pull_incoming
        # Patch the _incoming BIO's pending property
        tls_socket._incoming.write(b"x")  # Put something in the real BIO

        result = tls_socket.recv(1024)
        assert result == b"hello"

    def test_recv_want_write(self, tls_socket):
        """recv() flushes outgoing on SSLWantWriteError then retries."""
        tls_socket._mock_sslobj.read.side_effect = [
            ssl.SSLWantWriteError("want write"),
            b"data",
        ]
        result = tls_socket.recv(1024)
        assert result == b"data"
        assert tls_socket._mock_sslobj.read.call_count == 2

    def test_recv_zero_return(self, tls_socket):
        """recv() returns b"" on SSLZeroReturnError (clean close)."""
        tls_socket._mock_sslobj.read.side_effect = ssl.SSLZeroReturnError()
        result = tls_socket.recv(1024)
        assert result == b""

    def test_recv_into(self, tls_socket):
        """recv_into() fills buffer with received data."""
        tls_socket._mock_sslobj.read.return_value = b"hi"
        buf = bytearray(10)
        n = tls_socket.recv_into(buf)
        assert n == 2
        assert buf[:2] == b"hi"

    def test_recv_into_uses_buffer_length_when_nbytes_zero(self, tls_socket):
        """recv_into() uses len(buffer) when nbytes=0."""
        tls_socket._mock_sslobj.read.return_value = b"abc"
        buf = bytearray(5)
        n = tls_socket.recv_into(buf, nbytes=0)
        tls_socket._mock_sslobj.read.assert_called_once_with(5)
        assert n == 3

    def test_recv_into_uses_nbytes_when_set(self, tls_socket):
        """recv_into() uses nbytes when non-zero."""
        tls_socket._mock_sslobj.read.return_value = b"ab"
        buf = bytearray(10)
        n = tls_socket.recv_into(buf, nbytes=3)
        tls_socket._mock_sslobj.read.assert_called_once_with(3)
        assert n == 2

    def test_close_with_makefile_refs(self, tls_socket):
        """close() does not call _real_close when makefile refs > 0."""
        tls_socket._makefile_refs = 1
        tls_socket._real_close = MagicMock()
        tls_socket.close()
        tls_socket._real_close.assert_not_called()
        assert tls_socket._closed is True

    def test_real_close_unwrap_exception(self, tls_socket):
        """_real_close() still calls sock.close even if sslobj.unwrap raises."""
        tls_socket._mock_sslobj.unwrap.side_effect = Exception("unwrap failed")
        tls_socket._real_close()
        tls_socket._sock.close.assert_called_once()

    def test_real_close_calls_unwrap_and_sock_close(self, tls_socket):
        """_real_close() calls unwrap and sock.close on success."""
        tls_socket._mock_sslobj.unwrap.return_value = None
        tls_socket._real_close()
        tls_socket._mock_sslobj.unwrap.assert_called_once()
        tls_socket._sock.close.assert_called_once()

    def test_decref_socketios_no_real_close_when_not_closed(self, tls_socket):
        """_decref_socketios() decrements refs but does not close if not _closed."""
        tls_socket._makefile_refs = 2
        tls_socket._real_close = MagicMock()
        tls_socket._decref_socketios()
        assert tls_socket._makefile_refs == 1
        tls_socket._real_close.assert_not_called()

    def test_decref_socketios_triggers_real_close(self, tls_socket):
        """_decref_socketios() calls _real_close when _closed and refs hit 0."""
        tls_socket._makefile_refs = 1
        tls_socket._closed = True
        tls_socket._real_close = MagicMock()
        tls_socket._decref_socketios()
        assert tls_socket._makefile_refs == 0
        tls_socket._real_close.assert_called_once()

    def test_decref_socketios_no_real_close_refs_still_positive(self, tls_socket):
        """_decref_socketios() does not close when refs still > 0 even if _closed."""
        tls_socket._makefile_refs = 2
        tls_socket._closed = True
        tls_socket._real_close = MagicMock()
        tls_socket._decref_socketios()
        assert tls_socket._makefile_refs == 1
        tls_socket._real_close.assert_not_called()

    def test_shutdown(self, tls_socket):
        """shutdown() delegates to close()."""
        tls_socket.close = MagicMock()
        tls_socket.shutdown(stdlib_socket.SHUT_RDWR)
        tls_socket.close.assert_called_once()

    def test_settimeout(self, tls_socket):
        """settimeout() delegates to sock."""
        tls_socket.settimeout(30.0)
        tls_socket._sock.settimeout.assert_called_once_with(30.0)

    def test_gettimeout(self, tls_socket):
        """gettimeout() delegates to sock."""
        tls_socket._sock.gettimeout.return_value = 30.0
        result = tls_socket.gettimeout()
        assert result == 30.0
        tls_socket._sock.gettimeout.assert_called()

    def test_setblocking(self, tls_socket):
        """setblocking() delegates to sock."""
        tls_socket.setblocking(False)
        tls_socket._sock.setblocking.assert_called_once_with(False)

    def test_setsockopt_noop(self, tls_socket):
        """setsockopt() is a no-op and does not raise."""
        tls_socket.setsockopt(stdlib_socket.SOL_SOCKET, stdlib_socket.SO_REUSEADDR, 1)
        # No assertion needed — just verify it doesn't raise

    def test_getsockopt_returns_zero(self, tls_socket):
        """getsockopt() always returns 0."""
        result = tls_socket.getsockopt(stdlib_socket.SOL_SOCKET, stdlib_socket.SO_REUSEADDR)
        assert result == 0

    def test_getsockname(self, tls_socket):
        """getsockname() delegates to sock."""
        tls_socket._sock.getsockname.return_value = ("127.0.0.1", 12345)
        result = tls_socket.getsockname()
        assert result == ("127.0.0.1", 12345)
        tls_socket._sock.getsockname.assert_called_once()

    def test_makefile_unbuffered(self, tls_socket):
        """makefile(buffering=0) returns raw _TlsFileWrapper."""
        f = tls_socket.makefile("rb", buffering=0)
        assert isinstance(f, _TlsFileWrapper)
        assert tls_socket._makefile_refs == 1
        f.close()

    def test_makefile_read_mode(self, tls_socket):
        """makefile("r") returns BufferedReader."""
        f = tls_socket.makefile("r")
        assert isinstance(f, io.BufferedReader)
        assert tls_socket._makefile_refs == 1
        f.close()

    def test_makefile_write_mode(self, tls_socket):
        """makefile("wb") returns BufferedWriter."""
        f = tls_socket.makefile("wb")
        assert isinstance(f, io.BufferedWriter)
        assert tls_socket._makefile_refs == 1
        f.close()

    def test_makefile_rw_mode(self, tls_socket):
        """makefile() with mode lacking 'r' and 'w' returns BufferedRWPair."""
        f = tls_socket.makefile("b")
        assert isinstance(f, io.BufferedRWPair)
        assert tls_socket._makefile_refs == 1
        f.close()

    def test_makefile_adds_b_to_mode(self, tls_socket):
        """makefile() adds 'b' to mode when not present."""
        f = tls_socket.makefile("r")
        # The mode used internally must contain 'b'; result is BufferedReader not text
        assert isinstance(f, io.BufferedReader)
        f.close()

    def test_version(self, tls_socket):
        """version() delegates to sslobj."""
        tls_socket._mock_sslobj.version.return_value = "TLSv1.3"
        assert tls_socket.version() == "TLSv1.3"
        tls_socket._mock_sslobj.version.assert_called_once()

    def test_cipher(self, tls_socket):
        """cipher() delegates to sslobj."""
        tls_socket._mock_sslobj.cipher.return_value = ("AES256", "TLSv1.3", 256)
        assert tls_socket.cipher() == ("AES256", "TLSv1.3", 256)
        tls_socket._mock_sslobj.cipher.assert_called_once()

    def test_getpeercert(self, tls_socket):
        """getpeercert() delegates to sslobj."""
        tls_socket._mock_sslobj.getpeercert.return_value = {"subject": ()}
        result = tls_socket.getpeercert()
        tls_socket._mock_sslobj.getpeercert.assert_called_once_with(False)
        assert result == {"subject": ()}

    def test_getpeercert_binary_form(self, tls_socket):
        """getpeercert(binary_form=True) passes flag to sslobj."""
        tls_socket._mock_sslobj.getpeercert.return_value = b"\x30\x82"
        result = tls_socket.getpeercert(binary_form=True)
        tls_socket._mock_sslobj.getpeercert.assert_called_once_with(True)
        assert result == b"\x30\x82"

    def test_family_property(self, tls_socket):
        """family property returns sock.family."""
        tls_socket._sock.family = 2
        assert tls_socket.family == 2

    def test_type_property(self, tls_socket):
        """type property returns SOCK_STREAM."""
        assert tls_socket.type == stdlib_socket.SOCK_STREAM

    def test_proto_property(self, tls_socket):
        """proto property returns 0."""
        assert tls_socket.proto == 0

    def test_repr_with_version(self, tls_socket):
        """__repr__ includes TLS version and remote addr."""
        tls_socket._mock_sslobj.version.return_value = "TLSv1.3"
        tls_socket._sock._remote_addr = ("example.com", 443)
        r = repr(tls_socket)
        assert "TLSv1.3" in r
        assert "example.com" in r

    def test_repr_handshaking(self, tls_socket):
        """__repr__ shows 'handshaking' when version() returns None."""
        tls_socket._mock_sslobj.version.return_value = None
        r = repr(tls_socket)
        assert "handshaking" in r

    def test_flush_outgoing_sends_data(self, tls_socket):
        """_flush_outgoing() calls sock.sendall when outgoing BIO has data."""
        tls_socket._outgoing.write(b"encrypted bytes")
        tls_socket._flush_outgoing()
        tls_socket._sock.sendall.assert_called_with(b"encrypted bytes")


class TestTlsFileWrapper:
    @pytest.fixture
    def file_wrapper(self, tls_socket):
        """Create a _TlsFileWrapper backed by a tls_socket."""
        return _TlsFileWrapper(tls_socket)

    def test_readinto(self, file_wrapper, tls_socket):
        """readinto() fills the buffer with data from tls_socket.recv."""
        tls_socket._mock_sslobj.read.return_value = b"hello"
        buf = bytearray(10)
        n = file_wrapper.readinto(buf)
        assert n == 5
        assert buf[:5] == b"hello"

    def test_write(self, file_wrapper, tls_socket):
        """write() sends data through tls_socket.sendall and returns length."""
        tls_socket._mock_sslobj.write.return_value = 4
        n = file_wrapper.write(b"data")
        assert n == 4
        tls_socket._mock_sslobj.write.assert_called()

    def test_readable_returns_true(self, file_wrapper):
        """readable() always returns True."""
        assert file_wrapper.readable() is True

    def test_writable_returns_true(self, file_wrapper):
        """writable() always returns True."""
        assert file_wrapper.writable() is True

    def test_fileno_returns_minus_one(self, file_wrapper):
        """fileno() returns -1 (delegated from TorTlsSocket.fileno)."""
        assert file_wrapper.fileno() == -1

    def test_close_calls_decref(self, file_wrapper, tls_socket):
        """close() calls _decref_socketios on the backing tls_socket."""
        tls_socket._decref_socketios = MagicMock()
        file_wrapper.close()
        tls_socket._decref_socketios.assert_called_once()
        assert file_wrapper.closed is True

    def test_close_idempotent(self, file_wrapper, tls_socket):
        """close() can be called multiple times without double-decrementing."""
        tls_socket._decref_socketios = MagicMock()
        file_wrapper.close()
        file_wrapper.close()
        # _decref_socketios should only be called once (the `if not self.closed` guard)
        tls_socket._decref_socketios.assert_called_once()
