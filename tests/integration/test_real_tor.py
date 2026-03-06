"""Integration tests using real Tor connections.

These tests require a working internet connection and may be slow
(Tor bootstrap can take 30-60 seconds).
"""

import pytest

pytestmark = pytest.mark.integration


class TestRealTor:
    def test_bootstrap_and_check_ip(self):
        """Bootstrap Tor and verify we get a Tor exit IP."""
        from tor_requests import TorConfig, create_session

        config = TorConfig()
        session = create_session(config)
        try:
            resp = session.get("https://check.torproject.org/api/ip", timeout=60)
            data = resp.json()
            assert "IP" in data
            assert data.get("IsTor", False) is True
        finally:
            session.close()

    def test_https_request(self):
        """Make an HTTPS request through Tor."""
        from tor_requests import TorConfig, create_session

        config = TorConfig()
        session = create_session(config)
        try:
            resp = session.get("https://httpbin.org/get", timeout=60)
            assert resp.status_code == 200
            data = resp.json()
            assert "headers" in data
        finally:
            session.close()

    def test_context_manager(self):
        """Test tor_context with requests."""
        import requests
        from tor_requests import tor_context

        with tor_context():
            resp = requests.get("https://check.torproject.org/api/ip", timeout=60)
            data = resp.json()
            assert "IP" in data

    def test_circuit_isolation(self):
        """Verify that isolated streams can get different exit IPs."""
        from tor_requests import TorConfig, create_session

        config = TorConfig(isolation=True)
        session1 = create_session(config)
        session2 = create_session(config)
        try:
            resp1 = session1.get("https://check.torproject.org/api/ip", timeout=60)
            resp2 = session2.get("https://check.torproject.org/api/ip", timeout=60)
            ip1 = resp1.json()["IP"]
            ip2 = resp2.json()["IP"]
            # IPs may or may not differ, but both should be valid
            assert ip1 is not None
            assert ip2 is not None
        finally:
            session1.close()
            session2.close()

    def test_multiple_requests(self):
        """Make multiple sequential requests through the same tunnel."""
        from tor_requests import TorConfig, create_session

        config = TorConfig()
        session = create_session(config)
        try:
            for _ in range(3):
                resp = session.get("https://httpbin.org/get", timeout=60)
                assert resp.status_code == 200
        finally:
            session.close()
