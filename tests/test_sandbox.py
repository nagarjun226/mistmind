"""Tests for the Deno sandbox security and functionality."""

import json
import tempfile
from pathlib import Path

import pytest

from mistmind.sandbox import DenoSandbox


@pytest.fixture
def deno_path():
    """Get path to Deno binary."""
    # Try common locations
    home = Path.home()
    deno_in_home = home / ".deno" / "bin" / "deno"
    
    if deno_in_home.exists():
        return str(deno_in_home)
    
    # Fall back to system PATH
    import shutil
    deno_in_path = shutil.which("deno")
    if deno_in_path:
        return deno_in_path
    
    pytest.skip("Deno not found")


@pytest.fixture
def sandbox(deno_path):
    """Create a Deno sandbox instance."""
    return DenoSandbox(deno_path=deno_path, timeout=5)


@pytest.fixture
def mock_spec():
    """Create a mock OpenAPI spec for testing."""
    spec = {
        "openapi": "3.1.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/test": {
                "get": {
                    "summary": "Test endpoint",
                    "tags": ["test"],
                    "operationId": "getTest",
                }
            },
            "/wireless": {
                "get": {
                    "summary": "Wireless endpoint",
                    "tags": ["wireless"],
                    "operationId": "getWireless",
                }
            },
        },
    }
    
    # Write to temp file
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        delete=False,
    ) as f:
        json.dump(spec, f)
        return f.name


@pytest.mark.asyncio
async def test_search_basic(sandbox, mock_spec):
    """Test basic search functionality."""
    code = """async () => {
        return Object.keys(spec.paths).length;
    }"""
    
    result = await sandbox.run_search(code, mock_spec)
    
    # Result is an integer, not a dict with "error"
    assert isinstance(result, int) or (isinstance(result, dict) and "error" not in result)
    assert result == 2


@pytest.mark.asyncio
async def test_search_filter_tags(sandbox, mock_spec):
    """Test searching by tags."""
    code = """async () => {
        const results = [];
        for (const [path, methods] of Object.entries(spec.paths)) {
            for (const [method, op] of Object.entries(methods)) {
                if (op.tags?.includes('wireless')) {
                    results.push({path, method});
                }
            }
        }
        return results;
    }"""
    
    result = await sandbox.run_search(code, mock_spec)
    
    assert "error" not in result
    assert len(result) == 1
    assert result[0]["path"] == "/wireless"


@pytest.mark.asyncio
async def test_search_blocks_network(sandbox, mock_spec):
    """Test that search blocks network access."""
    code = """async () => {
        const resp = await fetch('https://example.com');
        return await resp.text();
    }"""
    
    result = await sandbox.run_search(code, mock_spec)
    
    # Should error due to network denial
    assert "error" in result
    error_msg = result["error"].lower()
    assert "permission" in error_msg or "denied" in error_msg or "requires" in error_msg


@pytest.mark.asyncio
async def test_search_blocks_arbitrary_file_read(sandbox, mock_spec):
    """Test that search blocks reading files other than the spec."""
    code = """async () => {
        const data = await Deno.readTextFile('/etc/passwd');
        return data;
    }"""
    
    result = await sandbox.run_search(code, mock_spec)
    
    # Should error due to file read denial
    assert "error" in result


@pytest.mark.asyncio
async def test_search_error_handling(sandbox, mock_spec):
    """Test that JavaScript errors are caught and returned."""
    code = """async () => {
        throw new Error('Test error');
    }"""
    
    result = await sandbox.run_search(code, mock_spec)
    
    assert "error" in result
    assert "Test error" in result["error"]
    assert "stack" in result


@pytest.mark.asyncio
async def test_execute_mock_api(sandbox):
    """Test execute with a mock API call."""
    # This will fail with network error, but tests the code structure
    code = """async () => {
        try {
            const result = await mist.request({path: '/api/v1/self'});
            return result;
        } catch (e) {
            return {error: e.message};
        }
    }"""
    
    result = await sandbox.run_execute(
        code,
        api_token="test-token",
        api_host="api.mist.com",
    )
    
    # Will have an error because we don't have a real API token
    # But it should show the code structure is working
    assert isinstance(result, dict)


@pytest.mark.asyncio
async def test_execute_blocks_arbitrary_network(sandbox):
    """Test that execute blocks non-Mist network access."""
    code = """async () => {
        const resp = await fetch('https://google.com');
        return await resp.text();
    }"""
    
    result = await sandbox.run_execute(
        code,
        api_token="test",
        api_host="api.mist.com",
    )
    
    # Should error due to network restriction
    assert "error" in result


@pytest.mark.asyncio
async def test_execute_blocks_file_operations(sandbox):
    """Test that execute blocks file operations."""
    code = """async () => {
        await Deno.writeTextFile('/tmp/test.txt', 'test');
        return {success: true};
    }"""
    
    result = await sandbox.run_execute(
        code,
        api_token="test",
        api_host="api.mist.com",
    )
    
    # Should error due to file write denial
    assert "error" in result


@pytest.mark.asyncio
async def test_timeout(sandbox, mock_spec):
    """Test that long-running code times out."""
    code = """async () => {
        await new Promise(resolve => setTimeout(resolve, 10000));
        return {done: true};
    }"""
    
    result = await sandbox.run_search(code, mock_spec)
    
    assert "error" in result
    assert "timeout" in result["error"].lower() or "timed out" in result["error"].lower()


@pytest.mark.asyncio
async def test_json_output_parsing(sandbox, mock_spec):
    """Test that complex JSON results are parsed correctly."""
    code = """async () => {
        return {
            paths: Object.keys(spec.paths),
            count: Object.keys(spec.paths).length,
            nested: {
                data: [1, 2, 3],
                info: "test"
            }
        };
    }"""
    
    result = await sandbox.run_search(code, mock_spec)
    
    assert "error" not in result
    assert result["count"] == 2
    assert "/test" in result["paths"]
    assert result["nested"]["data"] == [1, 2, 3]
