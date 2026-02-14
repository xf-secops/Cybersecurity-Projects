"""
©AngelaMos | 2026
conftest.py
"""

import pytest

from app.config import Settings


@pytest.fixture
def test_settings() -> Settings:
    """
    Override settings for test environment.
    """
    return Settings(
        env="testing",
        debug=False,
        database_url="sqlite+aiosqlite:///test.db",
        redis_url="redis://localhost:6379/1",
        nginx_log_path="/tmp/test-access.log",
        geoip_db_path="/tmp/nonexistent.mmdb",
    )
