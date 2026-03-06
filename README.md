# tor-requests

Drop-in socket replacement for transparent Tor routing in Python.

Routes TCP traffic through the [Tor network](https://www.torproject.org/) using [arti-client](https://gitlab.torproject.org/tpo/core/arti) (the Tor Project's pure-Rust Tor implementation). No need to install the Tor daemon — everything is self-contained in a native Python extension.

## Installation

```bash
pip install tor-requests
```

For `requests` library integration:

```bash
pip install tor-requests[requests]
```

## Quick Start

### Context Manager (recommended)

Route all TCP traffic through Tor within a context:

```python
import requests
from tor_requests import tor_context

with tor_context():
    r = requests.get("https://check.torproject.org/api/ip")
    print(r.json())  # {"IP": "...", "IsTor": true}
```

### Requests Session

Create a `requests.Session` that routes through Tor:

```python
from tor_requests import create_session

session = create_session()
resp = session.get("https://httpbin.org/ip")
print(resp.json())
session.close()
```

### Raw Socket

Use `TorSocket` as a drop-in `socket.socket` replacement:

```python
from tor_requests import TorConfig, TorSocket
from tor_requests._native import TorTunnel

config = TorConfig()
tunnel = TorTunnel(config.to_native())

sock = TorSocket(tunnel)
sock.connect(("httpbin.org", 80))
sock.sendall(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
print(sock.recv(4096))
sock.close()
tunnel.close()
```

## .onion Services

Access Tor hidden services directly:

```python
from tor_requests import create_session

session = create_session()
resp = session.get("https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/")
print(resp.status_code)
session.close()
```

## Circuit Isolation

Use separate Tor circuits per connection for different exit IPs:

```python
from tor_requests import TorConfig, create_session

config = TorConfig(isolation=True)
session = create_session(config)
# Each request may use a different exit node
resp = session.get("https://check.torproject.org/api/ip")
print(resp.json()["IP"])
session.close()
```

## Bridge Relays

For censored networks, configure bridge relays:

```python
from tor_requests import TorConfig, create_session

config = TorConfig(bridges=[
    "Bridge obfs4 198.51.100.1:443 cert=... iat-mode=0",
])
session = create_session(config)
```

## Async Support

```python
import asyncio
from tor_requests import TorConfig
from tor_requests._native import TorTunnel
from tor_requests.async_socket import AsyncTorSocket

async def main():
    config = TorConfig()
    tunnel = TorTunnel(config.to_native())

    async with AsyncTorSocket(tunnel) as sock:
        await sock.connect(("httpbin.org", 80))
        await sock.send(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
        data = await sock.recv(4096)
        print(data)

    tunnel.close()

asyncio.run(main())
```

## Configuration

`TorConfig` accepts the following options:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `data_dir` | `str \| None` | `None` | Directory for Tor state/cache (uses arti default) |
| `bridges` | `list[str]` | `[]` | Bridge relay lines for censored networks |
| `isolation` | `bool` | `False` | Per-stream circuit isolation for IP diversity |

## Building from Source

Requires Rust toolchain (1.70+) and Python 3.9+:

```bash
git clone https://github.com/bshuler/tor-requests
cd tor-requests
pip install maturin
maturin develop
```

Run tests:

```bash
pip install pytest pytest-asyncio
pytest tests/unit -v
```

## Architecture

- **Rust native extension** (`arti-client` + `tokio`): Handles Tor protocol, circuit building, and async I/O
- **Python wrapper**: Provides `socket.socket`-compatible API, TLS via `ssl.MemoryBIO`, and `requests` integration
- **Async-to-sync bridge**: Background tokio runtime with crossbeam channels for Python↔Rust communication

## License

Apache-2.0
