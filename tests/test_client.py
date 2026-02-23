"""
Tests for the Mist API client
"""
import pytest
from unittest.mock import AsyncMock, patch

from mistmind.client import MistAPIClient, MistAPIError
from mistmind.config import ServerConfig


@pytest.mark.asyncio
async def test_client_initialization(mock_config):
    """Test client initializes correctly"""
    client = MistAPIClient(mock_config)
    assert client.base_url == "https://api.mist.com"
    assert client.config == mock_config


@pytest.mark.asyncio
async def test_client_context_manager(mock_config):
    """Test client works as async context manager"""
    async with MistAPIClient(mock_config) as client:
        assert client._client is not None
    
    # Client should be closed after context
    assert client._client is None


@pytest.mark.asyncio
async def test_build_url(mock_config):
    """Test URL building"""
    client = MistAPIClient(mock_config)
    
    # Test with leading slash
    url = client._build_url("/api/v1/self")
    assert url == "https://api.mist.com/api/v1/self"
    
    # Test without leading slash
    url = client._build_url("api/v1/self")
    assert url == "https://api.mist.com/api/v1/self"


@pytest.mark.asyncio
async def test_error_handling(mock_config):
    """Test API error handling"""
    client = MistAPIClient(mock_config)
    await client._ensure_client()
    
    # Mock a 401 response
    mock_response = AsyncMock()
    mock_response.status_code = 401
    client._client.request = AsyncMock(return_value=mock_response)
    
    with pytest.raises(MistAPIError) as exc_info:
        await client._request("GET", "/api/v1/self")
    
    assert exc_info.value.status_code == 401
    assert "Unauthorized" in str(exc_info.value)
    
    await client.close()


@pytest.mark.asyncio
async def test_pagination_disabled(mock_config):
    """Test GET without pagination"""
    client = MistAPIClient(mock_config)
    
    mock_response = {
        "results": [{"id": "1"}, {"id": "2"}],
        "next": "http://api.mist.com/next-page"
    }
    
    with patch.object(client, '_request', return_value=mock_response):
        result = await client.get("/api/v1/test", follow_pagination=False)
        
        # Should not follow pagination
        assert "next" in result
        assert len(result["results"]) == 2
