"""Integration test configuration."""

import pytest


def pytest_collection_modifyitems(config, items):
    """Auto-mark tests in the integration directory."""
    for item in items:
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
