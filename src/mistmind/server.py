"""
MCP Server setup and tool registration
"""
import logging
from typing import Any

from mcp.server import Server
from mcp.types import Tool, TextContent

from mistmind.client import MistAPIClient, MistAPIError
from mistmind.config import ServerConfig
from mistmind.context import SessionContext
from mistmind.formatter import format_error

logger = logging.getLogger(__name__)

# Global server instance
_server: Server = None
_config: ServerConfig = None
_client: MistAPIClient = None
_context: SessionContext = None


def get_server() -> Server:
    """Get the global server instance"""
    return _server


def get_config() -> ServerConfig:
    """Get the global config instance"""
    return _config


def get_client() -> MistAPIClient:
    """Get the global API client instance"""
    return _client


def get_context() -> SessionContext:
    """Get the global session context instance"""
    return _context


def create_server(config: ServerConfig) -> Server:
    """
    Create and configure the MCP server with all tools
    """
    global _server, _config, _client, _context
    
    _config = config
    _client = MistAPIClient(config)
    _context = SessionContext(_client)
    
    # Create server instance
    _server = Server("mistmind")
    
    # Server instructions for LLMs
    instructions = """
MistMind provides intelligent access to the Juniper Mist API for network management.

You are a network engineer using Mist to manage Wi-Fi, LAN, WAN, and NAC infrastructure.

KEY PRINCIPLES:
1. Start with mist_self to understand the organization context
2. Use mist_sites to explore available sites
3. Use mist_query for most data retrieval (devices, clients, stats)
4. Use mist_devices for device-specific operations (firmware, inventory)
5. Use mist_search for flexible, universal search across all object types

WORKFLOW EXAMPLES:

Get network overview:
  1. mist_self → understand org and permissions
  2. mist_sites (action=list) → see all locations
  3. mist_query (type=devices) → device inventory
  4. mist_query (type=clients) → active clients

Troubleshoot connectivity:
  1. mist_query (type=devices, filters={status: "disconnected"}) → find offline devices
  2. mist_sites (action=stats, site_id=...) → check site health
  3. mist_query (type=device_stats, device_id=...) → detailed device metrics

Firmware management:
  1. mist_devices (action=inventory) → current versions
  2. mist_devices (action=available_versions) → what's available
  3. mist_devices (action=upgrades, device_id=...) → check upgrade status

IMPORTANT:
- Responses include _summary fields with human-readable overviews
- Results are auto-truncated to 50 items by default
- The context automatically caches org_id, site_id, and device lookups
- Write operations are disabled by default for safety
"""
    
    # Register all tools
    from mistmind.tools import register_all_tools
    register_all_tools(_server)
    
    logger.info(f"MCP server created with {len(_server.list_tools())} tools")
    
    return _server


def handle_tool_error(e: Exception) -> list[TextContent]:
    """
    Handle tool errors consistently across all tools
    
    Returns a properly formatted MCP TextContent response
    """
    if isinstance(e, MistAPIError):
        error_response = format_error(e.status_code, e.message)
    else:
        error_response = format_error(500, str(e))
    
    logger.error(f"Tool error: {error_response}")
    
    import json
    return [TextContent(
        type="text",
        text=json.dumps(error_response, indent=2)
    )]
