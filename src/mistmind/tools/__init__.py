"""
Tool registry for MistMind MCP server
"""
import logging

from mcp.server import Server

logger = logging.getLogger(__name__)


def register_all_tools(server: Server):
    """Register all available tools with the MCP server"""
    
    # Import tool modules (this triggers their @server.tool() decorators)
    from mistmind.tools import self_info
    from mistmind.tools import sites
    from mistmind.tools import query
    from mistmind.tools import devices
    from mistmind.tools import search
    
    logger.info("All tools registered successfully")
