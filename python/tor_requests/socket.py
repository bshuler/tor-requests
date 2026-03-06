"""Drop-in socket.socket replacement that tunnels through Tor.

TorSocket implements the same interface as socket.socket for
TCP (AF_INET, SOCK_STREAM) connections. When used as a replacement,
all TCP traffic is transparently routed through the Tor network.
"""

from __future__ import annotations

import io
import socket as stdlib_socket
from typing import TYPE_CHECKING, Any, Optional, Tuple

if TYPE_CHECKING:
    from . import _native


class TorSocket:
    """A socket-like object that tunnels TCP through Tor.

    Implements the essential subset of the socket.socket API used by
    urllib3, requests, httpx, and other HTTP libraries.

    Not a true subclass of socket.socket because we don't create a
    real file descriptor — all I/O goes through the Rust tunnel.
    """

    AF_INET = stdlib_socket.AF_INET
    AF_INET6 = stdlib_socket.AF_INET6
    SOCK_STREAM = stdlib_socket.SOCK_STREAM

    def __init__(self, tunnel: _native.TorTunnel):
        self._tunnel = tunnel
        self._stream: Optional[_native.TorStream] = None
        self._remote_addr: Optional[Tuple[str, int]] = None
        self._timeout: Optional[float] = None
        self._closed = False
        self._makefile_refs = 0

    def connect(self, address: Tuple[str, int]) -> None:
        """Connect to a remote host through the Tor network."""
        if self._stream is not None:
            raise OSError("Already connected")
        if self._closed:
            raise OSError("Socket is closed")

        host, port = address
        self._remote_addr = address
        if self._tunnel._isolation:
            self._stream = self._tunnel.create_isolated_stream(host, port)
        else:
            self._stream = self._tunnel.create_stream(host, port)

    def send(self, data: bytes, flags: int = 0) -> int:
        """Send data through the tunnel."""
        if self._stream is None:
            raise OSError("Not connected")
        return self._stream.send(data)

    def sendall(self, data: bytes, flags: int = 0) -> None:
        """Send all data through the tunnel."""
        if self._stream is None:
            raise OSError("Not connected")
        mv = memoryview(data)
        total = len(mv)
        sent = 0
        while sent < total:
            n = self._stream.send(bytes(mv[sent:]))
            if n == 0:
                raise OSError("Connection closed during send")
            sent += n

    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        """Receive data from the tunnel."""
        if self._stream is None:
            if self._closed:
                return b""
            raise OSError("Not connected")
        timeout_ms = None
        if self._timeout is not None:
            timeout_ms = int(self._timeout * 1000)
        return bytes(self._stream.recv(bufsize, timeout_ms))

    def recv_into(self, buffer: bytearray, nbytes: int = 0, flags: int = 0) -> int:
        """Receive data into a pre-allocated buffer."""
        data = self.recv(nbytes or len(buffer), flags)
        n = len(data)
        buffer[:n] = data
        return n

    def close(self) -> None:
        """Close the connection."""
        if self._closed:
            return
        self._closed = True
        if self._makefile_refs < 1 and self._stream is not None:
            self._stream.close()
            self._stream = None

    def _decref_socketios(self) -> None:
        """Called by _SocketFileWrapper.close() to decrement makefile refs."""
        self._makefile_refs -= 1
        if self._closed and self._makefile_refs < 1 and self._stream is not None:
            self._stream.close()
            self._stream = None

    def shutdown(self, how: int) -> None:
        """Shut down the connection."""
        self.close()

    def settimeout(self, timeout: Optional[float]) -> None:
        """Set socket timeout."""
        self._timeout = timeout

    def gettimeout(self) -> Optional[float]:
        """Get socket timeout."""
        return self._timeout

    def setblocking(self, flag: bool) -> None:
        """Set blocking/non-blocking mode."""
        if flag:
            self.settimeout(None)
        else:
            self.settimeout(0.0)

    def setsockopt(self, level: int, optname: int, value: Any) -> None:
        """Set socket option (no-op for Tor sockets)."""
        pass

    def getsockopt(self, level: int, optname: int, buflen: int = 0) -> int:
        """Get socket option (stub)."""
        return 0

    def getsockname(self) -> Tuple[str, int]:
        """Get the local address of the socket."""
        return ("0.0.0.0", 0)

    def getpeername(self) -> Tuple[str, int]:
        """Get the remote address of the socket."""
        if self._remote_addr is None:
            raise OSError("Not connected")
        return self._remote_addr

    def fileno(self) -> int:
        """Return the file descriptor (-1 since no real fd)."""
        return -1

    def makefile(self, mode: str = "r", buffering: int = -1, **kwargs) -> io.IOBase:
        """Create a file-like object for the socket."""
        if "b" not in mode:
            mode = mode + "b"

        self._makefile_refs += 1
        raw = _SocketFileWrapper(self)

        if buffering == 0:
            return raw

        if buffering < 0:
            buffering = io.DEFAULT_BUFFER_SIZE

        if "r" in mode:
            return io.BufferedReader(raw, buffer_size=buffering)
        elif "w" in mode:
            return io.BufferedWriter(raw, buffer_size=buffering)
        else:
            return io.BufferedRWPair(raw, raw, buffer_size=buffering)

    def wrap_tls(self, hostname: str, context=None):
        """Wrap this socket with TLS for HTTPS communication."""
        import ssl

        from .tls import TorTlsSocket

        if context is None:
            context = ssl.create_default_context()
        return TorTlsSocket(self, context, server_hostname=hostname)

    @property
    def family(self) -> int:
        if self._remote_addr is not None and ":" in self._remote_addr[0]:
            return stdlib_socket.AF_INET6
        return stdlib_socket.AF_INET

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
        state = "connected" if self._stream else "idle"
        return f"<TorSocket {state} remote={self._remote_addr}>"


class _SocketFileWrapper(io.RawIOBase):
    """Wraps a TorSocket as an io.RawIOBase for makefile() support."""

    def __init__(self, sock: TorSocket):
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
