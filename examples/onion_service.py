"""Onion service example: accessing .onion addresses."""

from tor_requests import create_session

session = create_session()
try:
    # DuckDuckGo's onion service
    resp = session.get(
        "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/",
        timeout=120,
    )
    print(f"Status: {resp.status_code}")
    print(f"Content length: {len(resp.text)} bytes")
finally:
    session.close()
