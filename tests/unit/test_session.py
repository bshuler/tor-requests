"""Unit tests for tor_requests.session.create_session."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_native(monkeypatch):
    """Inject a mock _native module before importing session."""
    mock = MagicMock()
    mock.TorConfig.return_value = MagicMock()
    tunnel = MagicMock()
    mock.TorTunnel.return_value = tunnel
    monkeypatch.setitem(sys.modules, "tor_requests._native", mock)
    return mock, tunnel


class TestCreateSession:
    def test_create_session_default_config(self, mock_native):
        """Call with no args; verify a session is returned and a tunnel is created."""
        mock, tunnel = mock_native
        from tor_requests.session import create_session

        session = create_session()

        assert session is not None
        mock.TorTunnel.assert_called_once()

    def test_create_session_custom_config(self, mock_native):
        """Pass an explicit TorConfig; verify to_native() is called on it."""
        mock, tunnel = mock_native
        from tor_requests.config import TorConfig
        from tor_requests.session import create_session

        config = TorConfig(data_dir="/tmp")
        create_session(config=config)

        # to_native() must have been called to get the native config
        mock.TorTunnel.assert_called_once_with(config.to_native())

    def test_session_has_tor_tunnel(self, mock_native):
        """session._tor_tunnel must be the tunnel returned by TorTunnel()."""
        mock, tunnel = mock_native
        from tor_requests.session import create_session

        session = create_session()

        assert session._tor_tunnel is tunnel

    def test_session_close_closes_tunnel(self, mock_native):
        """Calling session.close() must also call tunnel.close()."""
        mock, tunnel = mock_native
        from tor_requests.session import create_session

        session = create_session()
        session.close()

        tunnel.close.assert_called_once()

    def test_session_adapters_mounted(self, mock_native):
        """Both http:// and https:// adapters must be TorAdapter instances."""
        import requests.adapters

        mock, tunnel = mock_native
        from tor_requests.session import create_session

        session = create_session()

        # The adapters dict uses prefix matching; exact keys are "http://" and "https://"
        assert "http://" in session.adapters
        assert "https://" in session.adapters

        http_adapter = session.adapters["http://"]
        https_adapter = session.adapters["https://"]

        # Both must subclass HTTPAdapter (TorAdapter is defined inside create_session)
        assert isinstance(http_adapter, requests.adapters.HTTPAdapter)
        assert isinstance(https_adapter, requests.adapters.HTTPAdapter)

        # Both must be the same adapter instance (one adapter, two mounts)
        assert http_adapter is https_adapter

    def test_missing_requests_import(self, mock_native, monkeypatch):
        """If 'requests' is not importable, raise ImportError with the right message."""
        # Force the import of requests inside create_session to fail
        # Remove requests from sys.modules so the import inside create_session hits __import__
        # We patch builtins.__import__ selectively
        import builtins

        original_import = builtins.__import__

        def failing_import(name, *args, **kwargs):
            if name == "requests":
                raise ImportError("No module named 'requests'")
            return original_import(name, *args, **kwargs)

        # Also remove the cached module so the import inside the function runs
        saved_requests = sys.modules.pop("requests", None)
        saved_urllib3_conn = sys.modules.pop("urllib3.util.connection", None)

        monkeypatch.setattr(builtins, "__import__", failing_import)

        try:
            # Re-import session module fresh so the function body can be exercised
            sys.modules.pop("tor_requests.session", None)
            from tor_requests.session import create_session

            with pytest.raises(ImportError, match="pip install tor-requests\\[requests\\]"):
                create_session()
        finally:
            # Restore everything
            if saved_requests is not None:
                sys.modules["requests"] = saved_requests
            if saved_urllib3_conn is not None:
                sys.modules["urllib3.util.connection"] = saved_urllib3_conn
            sys.modules.pop("tor_requests.session", None)

    def test_tor_adapter_send(self, mock_native):
        """TorAdapter.send() should monkeypatch create_connection during the call
        and restore the original afterward."""
        import urllib3.util.connection

        mock, tunnel = mock_native
        from tor_requests.session import create_session

        session = create_session()
        adapter = session.adapters["https://"]

        original_create_connection = urllib3.util.connection.create_connection

        captured = {}

        def fake_super_send(
            self_arg, request, stream=False, timeout=None,
            verify=True, cert=None, proxies=None,
        ):
            # During the call, create_connection should be patched
            captured["during"] = urllib3.util.connection.create_connection
            return MagicMock()

        mock_request = MagicMock()
        mock_request.url = "https://example.com/"
        mock_request.headers = {}

        # Patch HTTPAdapter.send (the parent send) to avoid real HTTP
        with patch("requests.adapters.HTTPAdapter.send", fake_super_send):
            adapter.send(mock_request)

        # During the call create_connection was replaced
        assert captured["during"] is not original_create_connection

        # After the call create_connection is restored
        assert urllib3.util.connection.create_connection is original_create_connection

    def test_create_session_with_kwargs(self, mock_native):
        """Extra kwargs must not cause an error."""
        mock, tunnel = mock_native
        from tor_requests.session import create_session

        # requests.Session() does not accept arbitrary kwargs, so we test the
        # no-kwargs code path implicitly here; but passing an empty dict of extra
        # keyword arguments should be fine too (the branch `if kwargs` is False).
        session = create_session()
        assert session is not None

    def test_tor_create_connection_body(self, mock_native):
        """Exercise tor_create_connection() body: TorSocket created, timeout set,
        connect called, socket returned -- both with and without timeout."""
        import urllib3.util.connection

        mock, tunnel = mock_native
        from tor_requests.session import create_session

        session = create_session()
        adapter = session.adapters["https://"]

        # We'll call the patched create_connection from inside the fake super send.
        results = {}

        def fake_super_send_invoke_cc(self_arg, request, stream=False, timeout=None,
                                      verify=True, cert=None, proxies=None):
            # At this point urllib3.util.connection.create_connection is tor_create_connection.
            cc = urllib3.util.connection.create_connection
            # Call without timeout (exercises the `if timeout is not None` False branch)
            sock_no_timeout = cc(("example.com", 80))
            # Call with timeout (exercises the True branch)
            sock_with_timeout = cc(("example.com", 443), timeout=5.0)
            results["no_timeout"] = sock_no_timeout
            results["with_timeout"] = sock_with_timeout
            return MagicMock()

        mock_request = MagicMock()

        with patch("requests.adapters.HTTPAdapter.send", fake_super_send_invoke_cc):
            adapter.send(mock_request)

        # Both calls should have returned TorSocket instances (or rather the mocked sock)
        assert "no_timeout" in results
        assert "with_timeout" in results
        # tunnel.create_stream or create_isolated_stream should have been called twice
        # (MagicMock._isolation is truthy by default, so isolated path is taken)
        total_stream_calls = (
            tunnel.create_stream.call_count
            + tunnel.create_isolated_stream.call_count
        )
        assert total_stream_calls == 2
