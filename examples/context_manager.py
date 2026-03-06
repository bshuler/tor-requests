"""Context manager example: transparent Tor routing."""

import requests
from tor_requests import tor_context

with tor_context() as tunnel:
    # All TCP traffic now goes through Tor
    r = requests.get("https://check.torproject.org/api/ip")
    data = r.json()
    print(f"Your Tor exit IP: {data['IP']}")
    print(f"Using Tor: {data.get('IsTor', 'unknown')}")
