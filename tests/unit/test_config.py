"""Unit tests for Tor configuration."""

from tor_requests.config import TorConfig


class TestTorConfig:
    def test_default_config(self):
        config = TorConfig()
        assert config.data_dir is None
        assert config.bridges == []
        assert config.isolation is False

    def test_custom_data_dir(self):
        config = TorConfig(data_dir="/tmp/tor-data")
        assert config.data_dir == "/tmp/tor-data"

    def test_bridges(self):
        bridges = ["Bridge obfs4 198.51.100.1:443 cert=... iat-mode=0"]
        config = TorConfig(bridges=bridges)
        assert config.bridges == bridges
        assert len(config.bridges) == 1

    def test_isolation(self):
        config = TorConfig(isolation=True)
        assert config.isolation is True

    def test_full_config(self):
        config = TorConfig(
            data_dir="/tmp/arti",
            bridges=["bridge1", "bridge2"],
            isolation=True,
        )
        assert config.data_dir == "/tmp/arti"
        assert len(config.bridges) == 2
        assert config.isolation is True

    def test_empty_bridges_default(self):
        config = TorConfig()
        assert isinstance(config.bridges, list)
        assert len(config.bridges) == 0
