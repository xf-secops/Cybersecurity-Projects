"""
©AngelaMos | 2026
test_api.py
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.mark.asyncio
async def test_health_returns_200() -> None:
    """
    Health endpoint returns 200 with status and uptime.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "uptime_seconds" in data
    assert isinstance(data["uptime_seconds"], (int, float))
    assert "pipeline_running" in data


@pytest.mark.asyncio
async def test_health_returns_pipeline_status() -> None:
    """
    Health response includes pipeline_running boolean.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")

    data = response.json()
    assert isinstance(data["pipeline_running"], bool)


@pytest.mark.asyncio
async def test_ready_returns_check_structure() -> None:
    """
    Readiness endpoint returns structured component checks.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/ready")

    assert response.status_code in (200, 503)
    data = response.json()
    assert "status" in data
    assert "checks" in data
    assert "database" in data["checks"]
    assert "redis" in data["checks"]
    assert "models_loaded" in data["checks"]
