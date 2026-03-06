"""Requests session example: create_session() usage."""

from tor_requests import create_session

session = create_session()
try:
    # Check our Tor exit IP
    resp = session.get("https://check.torproject.org/api/ip")
    print(f"Tor exit IP: {resp.json()['IP']}")

    # Make HTTPS requests through Tor
    resp = session.get("https://httpbin.org/get")
    print(f"Status: {resp.status_code}")
    print(f"Headers seen by server: {resp.json()['headers']}")
finally:
    session.close()
