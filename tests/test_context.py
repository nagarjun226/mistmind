"""
Tests for session context and caching
"""
import pytest

from mistmind.context import SessionContext


@pytest.mark.asyncio
async def test_get_org_id_caching(mock_client, mock_user_info):
    """Test that org_id is cached after first fetch"""
    context = SessionContext(mock_client)
    
    # Mock the get() call to return user info
    mock_client.get.return_value = mock_user_info
    
    # First call should hit the API
    org_id = await context.get_org_id()
    assert org_id == "test-org-123"
    assert mock_client.get.call_count == 1
    
    # Second call should use cache
    org_id_2 = await context.get_org_id()
    assert org_id_2 == "test-org-123"
    assert mock_client.get.call_count == 1  # No additional call


@pytest.mark.asyncio
async def test_get_org_name(mock_client, mock_user_info):
    """Test getting organization name"""
    context = SessionContext(mock_client)
    mock_client.get.return_value = mock_user_info
    
    org_name = await context.get_org_name()
    assert org_name == "Test Organization"


@pytest.mark.asyncio
async def test_resolve_site_uuid(mock_client):
    """Test that UUID-like site IDs are returned as-is"""
    context = SessionContext(mock_client)
    
    site_id = "12345678-1234-1234-1234-123456789abc"
    result = await context.resolve_site(site_id)
    
    # Should return the UUID without API call
    assert result == site_id
    assert mock_client.get.call_count == 0


@pytest.mark.asyncio
async def test_resolve_site_by_name(mock_client, mock_user_info, mock_sites):
    """Test resolving site by name"""
    context = SessionContext(mock_client)
    
    # Mock API responses
    def mock_get(path, **kwargs):
        if "/self" in path:
            return mock_user_info
        else:
            return mock_sites
    
    mock_client.get.side_effect = mock_get
    
    # Resolve site by name
    site_id = await context.resolve_site("HQ")
    assert site_id == "site-1"
    
    # Should be cached now
    site_id_2 = await context.resolve_site("HQ")
    assert site_id_2 == "site-1"


@pytest.mark.asyncio
async def test_clear_cache(mock_client, mock_user_info):
    """Test cache clearing"""
    context = SessionContext(mock_client)
    mock_client.get.return_value = mock_user_info
    
    # Populate cache
    await context.get_org_id()
    assert context._org_id is not None
    
    # Clear cache
    context.clear_cache()
    assert context._org_id is None
    assert len(context._site_cache) == 0


@pytest.mark.asyncio
async def test_looks_like_uuid():
    """Test UUID detection"""
    assert SessionContext._looks_like_uuid("12345678-1234-1234-1234-123456789abc")
    assert SessionContext._looks_like_uuid("12345678123412341234123456789abc")
    assert not SessionContext._looks_like_uuid("HQ-Office")
    assert not SessionContext._looks_like_uuid("123")
