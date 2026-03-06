"""Unit tests for AsyncTorSocket."""

from unittest.mock import MagicMock

import pytest
from tor_requests.async_socket import AsyncTorSocket


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


class TestAsyncTorSocket:
    @pytest.mark.asyncio
    async def test_connect(self, mock_tunnel):
        sock = AsyncTorSocket(mock_tunnel)
        await sock.connect(("example.com", 80))
        mock_tunnel.create_stream.assert_called_once_with("example.com", 80)

    @pytest.mark.asyncio
    async def test_send(self, mock_tunnel):
        sock = AsyncTorSocket(mock_tunnel)
        await sock.connect(("example.com", 80))
        n = await sock.send(b"hello")
        assert n == 5

    @pytest.mark.asyncio
    async def test_recv(self, mock_tunnel):
        sock = AsyncTorSocket(mock_tunnel)
        await sock.connect(("example.com", 80))
        data = await sock.recv(1024)
        assert data == b"hello"

    @pytest.mark.asyncio
    async def test_close(self, mock_tunnel):
        sock = AsyncTorSocket(mock_tunnel)
        await sock.connect(("example.com", 80))
        await sock.close()
        mock_tunnel.create_stream.return_value.close.assert_called()

    @pytest.mark.asyncio
    async def test_context_manager(self, mock_tunnel):
        async with AsyncTorSocket(mock_tunnel) as sock:
            await sock.connect(("example.com", 80))

    @pytest.mark.asyncio
    async def test_connect_after_close_raises(self, mock_tunnel):
        sock = AsyncTorSocket(mock_tunnel)
        await sock.close()
        with pytest.raises(OSError, match="closed"):
            await sock.connect(("example.com", 80))

    @pytest.mark.asyncio
    async def test_send_before_connect_raises(self, mock_tunnel):
        sock = AsyncTorSocket(mock_tunnel)
        with pytest.raises(OSError, match="Not connected"):
            await sock.send(b"hello")

    def test_repr_idle(self, mock_tunnel):
        sock = AsyncTorSocket(mock_tunnel)
        assert "idle" in repr(sock)

    @pytest.mark.asyncio
    async def test_connect_isolated(self, mock_tunnel):
        mock_tunnel._isolation = True
        sock = AsyncTorSocket(mock_tunnel)
        await sock.connect(("example.com", 80))
        mock_tunnel.create_isolated_stream.assert_called_once_with("example.com", 80)

    @pytest.mark.asyncio
    async def test_connect_already_connected_raises(self, mock_tunnel):
        sock = AsyncTorSocket(mock_tunnel)
        await sock.connect(("example.com", 80))
        with pytest.raises(OSError, match="Already connected"):
            await sock.connect(("example.com", 80))

    @pytest.mark.asyncio
    async def test_sendall(self, mock_tunnel):
        sock = AsyncTorSocket(mock_tunnel)
        await sock.connect(("example.com", 80))
        mock_tunnel.create_stream.return_value.send.return_value = 5
        await sock.sendall(b"hello")

    @pytest.mark.asyncio
    async def test_sendall_connection_closed(self, mock_tunnel):
        sock = AsyncTorSocket(mock_tunnel)
        await sock.connect(("example.com", 80))
        mock_tunnel.create_stream.return_value.send.return_value = 0
        with pytest.raises(OSError, match="Connection closed"):
            await sock.sendall(b"hello")

    @pytest.mark.asyncio
    async def test_recv_before_connect_raises(self, mock_tunnel):
        sock = AsyncTorSocket(mock_tunnel)
        with pytest.raises(OSError, match="Not connected"):
            await sock.recv(1024)

    @pytest.mark.asyncio
    async def test_sendall_before_connect_raises(self, mock_tunnel):
        sock = AsyncTorSocket(mock_tunnel)
        with pytest.raises(OSError, match="Not connected"):
            await sock.sendall(b"hello")

    @pytest.mark.asyncio
    async def test_close_already_closed(self, mock_tunnel):
        sock = AsyncTorSocket(mock_tunnel)
        await sock.close()
        await sock.close()  # Second close should be no-op

    @pytest.mark.asyncio
    async def test_custom_loop(self, mock_tunnel):
        import asyncio
        loop = asyncio.get_running_loop()
        sock = AsyncTorSocket(mock_tunnel, loop=loop)
        await sock.connect(("example.com", 80))
        assert sock._loop is loop

    def test_repr_connected(self, mock_tunnel):
        # Manually set state to simulate connected
        sock = AsyncTorSocket(mock_tunnel)
        sock._stream = MagicMock()
        sock._remote_addr = ("example.com", 80)
        assert "connected" in repr(sock)
        assert "example.com" in repr(sock)
