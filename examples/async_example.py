"""Async example: using AsyncTorSocket."""

import asyncio

from tor_requests import TorConfig
from tor_requests._native import TorTunnel
from tor_requests.async_socket import AsyncTorSocket


async def main():
    config = TorConfig()
    native_config = config.to_native()
    tunnel = TorTunnel(native_config)

    try:
        async with AsyncTorSocket(tunnel) as sock:
            await sock.connect(("httpbin.org", 80))
            await sock.send(
                b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"
            )

            response = b""
            while True:
                chunk = await sock.recv(4096)
                if not chunk:
                    break
                response += chunk

            print(response.decode())
    finally:
        tunnel.close()


asyncio.run(main())
