"""Tor configuration management."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class TorConfig:
    """Configuration for the Tor tunnel.

    Args:
        data_dir: Directory for arti state/cache. Defaults to arti's default (~/.local/share/arti).
        bridges: List of bridge relay lines for censored networks (not yet supported).
        isolation: If True, each stream uses a separate circuit for IP isolation.

    Examples:
        # Default configuration:
        config = TorConfig()

        # With circuit isolation (each connection gets a different exit IP):
        config = TorConfig(isolation=True)
    """

    data_dir: Optional[str] = None
    bridges: List[str] = field(default_factory=list)
    isolation: bool = False

    def to_native(self):
        """Convert to the Rust-side TorConfig object.

        Returns:
            Native TorConfig instance for use with TorTunnel.
        """
        from . import _native

        return _native.TorConfig(
            data_dir=self.data_dir,
            bridges=self.bridges,
            isolation=self.isolation,
        )
