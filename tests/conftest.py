"""
Pytest configuration and fixtures for MistMind tests
"""
import pytest
from unittest.mock import AsyncMock

from mistmind.config import ServerConfig
from mistmind.client import MistAPIClient
from mistmind.context import SessionContext


@pytest.fixture
def mock_config():
    """Mock server configuration"""
    return ServerConfig(
        api_token="test-token-12345",
        api_host="https://api.mist.com",
        debug=True,
        enable_writes=False,
        max_response_items=50,
        request_timeout=30,
    )


@pytest.fixture
def mock_client(mock_config):
    """Mock API client"""
    client = MistAPIClient(mock_config)
    # Mock the HTTP methods
    client.get = AsyncMock(return_value={})
    client.post = AsyncMock(return_value={})
    client.put = AsyncMock(return_value={})
    client.delete = AsyncMock(return_value={})
    return client


@pytest.fixture
def mock_context(mock_client):
    """Mock session context"""
    context = SessionContext(mock_client)
    return context


@pytest.fixture
def mock_user_info():
    """Mock user info response from /api/v1/self"""
    return {
        "email": "test@example.com",
        "first_name": "Test",
        "last_name": "User",
        "privileges": [
            {
                "org_id": "test-org-123",
                "org_name": "Test Organization",
                "role": "admin",
            }
        ],
    }


@pytest.fixture
def mock_devices():
    """Mock device list"""
    return [
        {
            "id": "device-1",
            "name": "AP-1",
            "type": "ap",
            "status": "connected",
            "site_id": "site-1",
            "site_name": "HQ",
            "model": "AP43",
            "mac": "aa:bb:cc:dd:ee:01",
        },
        {
            "id": "device-2",
            "name": "AP-2",
            "type": "ap",
            "status": "disconnected",
            "site_id": "site-1",
            "site_name": "HQ",
            "model": "AP43",
            "mac": "aa:bb:cc:dd:ee:02",
        },
        {
            "id": "device-3",
            "name": "Switch-1",
            "type": "switch",
            "status": "connected",
            "site_id": "site-2",
            "site_name": "Branch",
            "model": "EX4300",
            "mac": "aa:bb:cc:dd:ee:03",
        },
    ]


@pytest.fixture
def mock_sites():
    """Mock site list"""
    return [
        {
            "id": "site-1",
            "name": "HQ",
            "address": "123 Main St",
            "timezone": "America/Los_Angeles",
        },
        {
            "id": "site-2",
            "name": "Branch",
            "address": "456 Oak Ave",
            "timezone": "America/New_York",
        },
    ]


@pytest.fixture
def mock_clients():
    """Mock client list"""
    return [
        {
            "mac": "11:22:33:44:55:01",
            "hostname": "laptop-1",
            "is_wireless": True,
            "tx_bytes": 1000000000,  # 1 GB
            "rx_bytes": 500000000,   # 500 MB
        },
        {
            "mac": "11:22:33:44:55:02",
            "hostname": "desktop-1",
            "is_wireless": False,
            "tx_bytes": 2000000000,  # 2 GB
            "rx_bytes": 1500000000,  # 1.5 GB
        },
    ]
