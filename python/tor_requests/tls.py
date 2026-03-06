"""TLS wrapper for TorSocket using memory BIOs.

Python's ssl.SSLContext.wrap_socket() requires a real socket with a file
descriptor. Since TorSocket has no fd, we use ssl.MemoryBIO +
ssl.SSLObject to implement TLS without real fds.
"""

from __future__ import annotations

import io
import socket as stdlib_socket
import ssl
from typing import TYPE_CHECKING, Any, Optional, Tuple

if TYPE_CHECKING:
    from .socket import TorSocket


class TorTlsSocket:
    """TLS-wrapped TorSocket using memory BIOs.

    Provides the same API as ssl.SSLSocket so that http.client, urllib3,
    and requests can use it transparently.
    """

    def __init__(
        self,
        sock: TorSocket,
        context: ssl.SSLContext,
        server_hostname: Optional[str] = None,
        server_side: bool = False,
        do_handshake_on_connect: bool = True,
    ):
        self._sock = sock
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._sslobj = context.wrap_bio(
            self._incoming,
            self._outgoing,
            server_side=server_side,
            server_hostname=server_hostname,
        )
        self._closed = False
        self._makefile_refs = 0

        if do_handshake_on_connect:
            self.do_handshake()

    def do_handshake(self) -> None:
        """Perform TLS handshake over the Tor stream."""
        while True:
            try:
                self._sslobj.do_handshake()
                self._flush_outgoing()
                break
            except ssl.SSLWantReadError:
                self._flush_outgoing()
                self._pull_incoming()
            except ssl.SSLWantWriteError:
                self._flush_outgoing()

    def _flush_outgoing(self) -> None:
        """Send any pending encrypted data from outgoing BIO to the socket."""
        data = self._outgoing.read()
        if data:
            self._sock.sendall(data)

    def _pull_incoming(self) -> None:
        """Read encrypted data from socket into incoming BIO."""
        data = self._sock.recv(16384)
        if data:
            self._incoming.write(data)

    def send(self, data: bytes, flags: int = 0) -> int:
        """Send data through the TLS layer."""
        n = self._sslobj.write(data)
        self._flush_outgoing()
        return n

    def sendall(self, data: bytes, flags: int = 0) -> None:
        """Send all data through the TLS layer."""
        view = memoryview(data)
        total = len(view)
        sent = 0
        while sent < total:
            n = self._sslobj.write(view[sent:])
            self._flush_outgoing()
            sent += n

    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        """Receive data through the TLS layer."""
        while True:
            try:
                return self._sslobj.read(bufsize)
            except ssl.SSLWantReadError:
                self._pull_incoming()
                if not self._incoming.pending:
                    return b""
            except ssl.SSLZeroReturnError:
                return b""

    def recv_into(self, buffer: bytearray, nbytes: int = 0, flags: int = 0) -> int:
        """Receive data into a pre-allocated buffer."""
        data = self.recv(nbytes or len(buffer), flags)
        n = len(data)
        buffer[:n] = data
        return n

    def close(self) -> None:
        """Close the TLS connection."""
        if self._closed:
            return
        self._closed = True
        if self._makefile_refs < 1:
            self._real_close()

    def _real_close(self) -> None:
        """Actually close the underlying resources."""
        try:
            self._sslobj.unwrap()
            self._flush_outgoing()
        except Exception:
            pass
        self._sock.close()

    def _decref_socketios(self) -> None:
        """Called by _TlsFileWrapper.close() to decrement makefile refs."""
        self._makefile_refs -= 1
        if self._closed and self._makefile_refs < 1:
            self._real_close()

    def shutdown(self, how: int) -> None:
        """Shut down the TLS connection."""
        self.close()

    def settimeout(self, timeout: Optional[float]) -> None:
        """Set socket timeout."""
        self._sock.settimeout(timeout)

    def gettimeout(self) -> Optional[float]:
        """Get socket timeout."""
        return self._sock.gettimeout()

    def setblocking(self, flag: bool) -> None:
        """Set blocking/non-blocking mode."""
        self._sock.setblocking(flag)

    def setsockopt(self, level: int, optname: int, value: Any) -> None:
        """Set socket option (no-op)."""
        pass

    def getsockopt(self, level: int, optname: int, buflen: int = 0) -> int:
        """Get socket option (stub)."""
        return 0

    def getsockname(self) -> Tuple[str, int]:
        """Get the local address."""
        return self._sock.getsockname()

    def getpeername(self) -> Tuple[str, int]:
        """Get the remote address."""
        return self._sock.getpeername()

    def fileno(self) -> int:
        """Return the file descriptor (-1 since no real fd)."""
        return -1

    def makefile(self, mode: str = "r", buffering: int = -1, **kwargs) -> io.IOBase:
        """Create a file-like object for the TLS socket."""
        if "b" not in mode:
            mode = mode + "b"

        self._makefile_refs += 1
        raw = _TlsFileWrapper(self)

        if buffering == 0 or ("b" in mode and buffering < 0):
            return raw

        if buffering < 0:
            buffering = io.DEFAULT_BUFFER_SIZE

        if "r" in mode:
            return io.BufferedReader(raw, buffer_size=buffering)
        elif "w" in mode:
            return io.BufferedWriter(raw, buffer_size=buffering)
        else:
            return io.BufferedRWPair(raw, raw, buffer_size=buffering)

    def version(self) -> Optional[str]:
        """Return the TLS protocol version."""
        return self._sslobj.version()

    def cipher(self) -> Optional[tuple]:
        """Return the current cipher."""
        return self._sslobj.cipher()

    def getpeercert(self, binary_form: bool = False):
        """Return the peer's certificate."""
        return self._sslobj.getpeercert(binary_form)

    @property
    def family(self) -> int:
        return self._sock.family

    @property
    def type(self) -> int:
        return stdlib_socket.SOCK_STREAM

    @property
    def proto(self) -> int:
        return 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self) -> str:
        ver = self.version() or "handshaking"
        return f"<TorTlsSocket {ver} remote={self._sock._remote_addr}>"


class _TlsFileWrapper(io.RawIOBase):
    """Wraps a TorTlsSocket as io.RawIOBase for makefile() support."""

    def __init__(self, sock: TorTlsSocket):
        self._sock = sock

    def readinto(self, b: bytearray) -> int:
        data = self._sock.recv(len(b))
        n = len(data)
        b[:n] = data
        return n

    def write(self, b: bytes) -> int:
        self._sock.sendall(b)
        return len(b)

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return True

    def fileno(self) -> int:
        return self._sock.fileno()

    def close(self) -> None:
        if not self.closed:
            super().close()
            self._sock._decref_socketios()
