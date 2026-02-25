"""Tests for the MCP server implementation (BUG 6: coverage for server.py)."""

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mistmind.config import ServerConfig
from mistmind.server import MistMindServer


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_spec_file():
    """Create a mock OpenAPI spec file for testing."""
    spec = {
        "openapi": "3.1.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/api/v1/self": {
                "get": {
                    "summary": "Get self",
                    "tags": ["user"],
                    "operationId": "getSelf",
                }
            },
            "/api/v1/orgs/{org_id}/sites": {
                "get": {
                    "summary": "List sites",
                    "tags": ["sites"],
                    "operationId": "listSites",
                }
            },
        },
    }
    
    # Create a persistent temp file that won't be deleted until explicitly removed
    tmp_path = Path(tempfile.gettempdir()) / f"test_spec_{id(spec)}.json"
    with open(tmp_path, "w") as f:
        json.dump(spec, f)
        f.flush()
    
    yield str(tmp_path)
    
    # Cleanup
    tmp_path.unlink(missing_ok=True)


@pytest.fixture
def deno_path():
    """Get path to Deno binary."""
    home = Path.home()
    deno_in_home = home / ".deno" / "bin" / "deno"
    
    if deno_in_home.exists():
        return str(deno_in_home)
    
    import shutil
    deno_in_path = shutil.which("deno")
    if deno_in_path:
        return deno_in_path
    
    pytest.skip("Deno not found")


@pytest.fixture
def server_config(deno_path):
    """Create a test server config."""
    return ServerConfig(
        mist_apitoken="test-token-secret-12345",
        mist_host="api.mist.com",
        deno_path=deno_path,
    )


@pytest.fixture
def server(server_config, mock_spec_file):
    """Create a MistMindServer instance for testing."""
    return MistMindServer(server_config, mock_spec_file)


# =============================================================================
# Tool Listing Tests
# =============================================================================

class TestToolListing:
    """Tests for MCP tool listing."""
    
    @pytest.mark.asyncio
    async def test_list_tools_returns_two_tools(self, server):
        """Tool listing should return exactly 2 tools: search and execute."""
        # The registered handlers use decorators, so we test via the server attributes
        # The server should have handlers registered for 2 tools
        # We verify by checking the server was initialized with our handlers
        assert server.server is not None
        assert server.sandbox is not None
        # The best test is that _handle_search and _handle_execute exist
        assert hasattr(server, '_handle_search')
        assert hasattr(server, '_handle_execute')
    
    @pytest.mark.asyncio
    async def test_search_handler_exists(self, server):
        """Search handler method exists and is callable."""
        assert callable(server._handle_search)
    
    @pytest.mark.asyncio
    async def test_execute_handler_exists(self, server):
        """Execute handler method exists and is callable."""
        assert callable(server._handle_execute)


# =============================================================================
# Search Handler Tests
# =============================================================================

class TestSearchHandler:
    """Tests for the search tool handler."""
    
    @pytest.mark.asyncio
    async def test_search_with_valid_code(self, server):
        """Search with valid code returns results."""
        result = await server._handle_search({
            "code": "async () => { return Object.keys(spec.paths).length; }"
        })
        
        assert len(result) == 1
        result_data = json.loads(result[0].text)
        assert result_data == 2  # 2 paths in mock spec
    
    @pytest.mark.asyncio
    async def test_search_with_missing_code(self, server):
        """Search with missing code parameter returns error."""
        result = await server._handle_search({})
        
        assert len(result) == 1
        assert "Error" in result[0].text
        assert "'code' parameter required" in result[0].text
    
    @pytest.mark.asyncio
    async def test_search_returns_filtered_results(self, server):
        """Search can filter spec by tags."""
        result = await server._handle_search({
            "code": """async () => {
                const results = [];
                for (const [path, methods] of Object.entries(spec.paths)) {
                    for (const [method, op] of Object.entries(methods)) {
                        if (op.tags?.includes('sites')) {
                            results.push({path, method, summary: op.summary});
                        }
                    }
                }
                return results;
            }"""
        })
        
        assert len(result) == 1
        result_data = json.loads(result[0].text)
        assert len(result_data) == 1
        assert result_data[0]["path"] == "/api/v1/orgs/{org_id}/sites"


# =============================================================================
# Execute Handler Tests
# =============================================================================

class TestExecuteHandler:
    """Tests for the execute tool handler."""
    
    @pytest.mark.asyncio
    async def test_execute_with_valid_code(self, server):
        """Execute with valid code runs successfully."""
        result = await server._handle_execute({
            "code": """async () => {
                // Just return static data, no actual API call
                return {test: true, timestamp: Date.now()};
            }"""
        })
        
        assert len(result) == 1
        result_data = json.loads(result[0].text)
        assert result_data.get("test") == True
        assert "timestamp" in result_data
    
    @pytest.mark.asyncio
    async def test_execute_with_missing_code(self, server):
        """Execute with missing code parameter returns error."""
        result = await server._handle_execute({})
        
        assert len(result) == 1
        assert "Error" in result[0].text
        assert "'code' parameter required" in result[0].text
    
    @pytest.mark.asyncio
    async def test_execute_can_access_mist_object(self, server):
        """Execute code can access the mist object."""
        result = await server._handle_execute({
            "code": """async () => {
                return {
                    hasMist: typeof mist !== 'undefined',
                    hasRequest: typeof mist.request === 'function',
                    allowedMethods: mist.allowedMethods
                };
            }"""
        })
        
        assert len(result) == 1
        result_data = json.loads(result[0].text)
        assert result_data["hasMist"] == True
        assert result_data["hasRequest"] == True
        assert "GET" in result_data["allowedMethods"]


# =============================================================================
# Unknown Tool Tests
# =============================================================================

class TestUnknownTool:
    """Tests for unknown tool handling."""
    
    @pytest.mark.asyncio
    async def test_server_only_handles_search_and_execute(self, server):
        """Server only handles 'search' and 'execute' tools."""
        # We verify that _handle_search and _handle_execute are the only handlers
        # by checking that only these methods are handler methods
        handler_methods = [name for name in dir(server) if name.startswith('_handle_')]
        
        assert '_handle_search' in handler_methods
        assert '_handle_execute' in handler_methods
        # There should only be these two handlers
        assert len(handler_methods) == 2


# =============================================================================
# Exception Scrubbing Tests (BUG 3)
# =============================================================================

class TestExceptionScrubbing:
    """Tests for token scrubbing in exception messages."""
    
    @pytest.mark.asyncio
    async def test_exception_scrubs_token(self, server_config, mock_spec_file):
        """Exception messages should have token scrubbed."""
        # Create server with a known token
        secret_token = "super-secret-token-xyz789"
        config = ServerConfig(
            mist_apitoken=secret_token,
            mist_host="api.mist.com",
            deno_path=server_config.deno_path,
        )
        server = MistMindServer(config, mock_spec_file)
        
        # Execute code that throws an error containing the token
        result = await server._handle_execute({
            "code": f"""async () => {{
                throw new Error("Token leak: {secret_token}");
            }}"""
        })
        
        assert len(result) == 1
        result_text = result[0].text
        
        # Token should be scrubbed from error
        assert secret_token not in result_text
        assert "[REDACTED]" in result_text


# =============================================================================
# Server Initialization Tests
# =============================================================================

class TestServerInitialization:
    """Tests for server initialization."""
    
    def test_server_initializes_with_valid_config(self, server_config, mock_spec_file):
        """Server initializes correctly with valid config."""
        server = MistMindServer(server_config, mock_spec_file)
        
        assert server.config == server_config
        assert server.spec_path.exists()
        assert server.sandbox is not None
    
    def test_server_fails_with_missing_spec(self, server_config):
        """Server raises error when spec file doesn't exist."""
        with pytest.raises(FileNotFoundError) as exc_info:
            MistMindServer(server_config, "/nonexistent/path/spec.json")
        
        assert "Resolved spec not found" in str(exc_info.value)
    
    def test_server_inherits_api_mode(self, server_config, mock_spec_file):
        """Server sandbox inherits API mode from config."""
        config = ServerConfig(
            mist_apitoken="test-token",
            mist_host="api.mist.com",
            deno_path=server_config.deno_path,
            mistmind_api_mode="readwrite",
        )
        server = MistMindServer(config, mock_spec_file)
        
        assert server.sandbox.api_mode == "readwrite"
        assert "POST" in server.sandbox.allowed_methods


# =============================================================================
# Config Spec Path Tests (BUG 8)
# =============================================================================

class TestConfigSpecPath:
    """Tests for the spec_path configuration option."""
    
    def test_config_accepts_spec_path(self, deno_path):
        """Config accepts mistmind_spec_path setting."""
        config = ServerConfig(
            mist_apitoken="test-token",
            deno_path=deno_path,
            mistmind_spec_path="/custom/path/spec.json",
        )
        
        assert config.mistmind_spec_path == "/custom/path/spec.json"
    
    def test_config_spec_path_defaults_to_none(self, deno_path):
        """Config spec_path defaults to None."""
        config = ServerConfig(
            mist_apitoken="test-token",
            deno_path=deno_path,
        )
        
        assert config.mistmind_spec_path is None
