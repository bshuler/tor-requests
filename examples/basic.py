"""Basic example: raw socket through Tor."""

from tor_requests import TorConfig, TorSocket
from tor_requests._native import TorTunnel

config = TorConfig()
native_config = config.to_native()
tunnel = TorTunnel(native_config)

try:
    sock = TorSocket(tunnel)
    sock.connect(("httpbin.org", 80))
    sock.sendall(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")

    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk

    print(response.decode())
    sock.close()
finally:
    tunnel.close()
