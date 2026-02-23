"""MCP server implementation with search and execute tools."""

import logging
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .config import ServerConfig
from .sandbox import DenoSandbox

logger = logging.getLogger(__name__)


class MistMindServer:
    """MistMind MCP server with Code Mode pattern."""

    def __init__(self, config: ServerConfig, spec_path: str):
        """Initialize server with config and resolved spec path."""
        self.config = config
        self.spec_path = Path(spec_path)
        self.sandbox = DenoSandbox(
            deno_path=config.deno_path,
            timeout=30,
        )
        self.server = Server("mistmind")
        
        # Verify spec exists
        if not self.spec_path.exists():
            raise FileNotFoundError(
                f"Resolved spec not found at {self.spec_path}. "
                f"Please run: python -m mistmind.spec_resolver "
                f"spec/mist.openapi.json spec/mist.resolved.json"
            )
        
        self._register_handlers()

    def _register_handlers(self):
        """Register MCP tool handlers."""
        
        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """List available tools."""
            return [
                Tool(
                    name="search",
                    description=(
                        "Search the Juniper Mist OpenAPI spec. Write a JavaScript async arrow "
                        "function that receives `spec` (the full OpenAPI 3.1 spec with paths, "
                        "schemas, etc). All $refs are pre-resolved inline. Use spec.paths to "
                        "find endpoints, spec.components.schemas for data models."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "code": {
                                "type": "string",
                                "description": (
                                    "JavaScript async arrow function to search the OpenAPI spec. "
                                    "Example: async () => { const results = []; for (const [path, methods] "
                                    "of Object.entries(spec.paths)) { for (const [method, op] of "
                                    "Object.entries(methods)) { if (op.tags?.some(t => "
                                    't.toLowerCase().includes("wireless"))) results.push({method: '
                                    "method.toUpperCase(), path, summary: op.summary}); } } return results; }"
                                ),
                            }
                        },
                        "required": ["code"],
                    },
                ),
                Tool(
                    name="execute",
                    description=(
                        "Execute JavaScript code against the Juniper Mist API. Write a JavaScript "
                        "async arrow function. Use `mist.request({method, path, body, params})` to "
                        "make authenticated API calls. Chain multiple calls, filter results, handle "
                        "pagination."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "code": {
                                "type": "string",
                                "description": (
                                    "JavaScript async arrow function to execute. "
                                    'Example: async () => { const self = await mist.request({path: "/api/v1/self"}); '
                                    "const org_id = self.privileges[0].org_id; const sites = await "
                                    "mist.request({path: `/api/v1/orgs/${org_id}/sites/search`}); return "
                                    "{org_id, sites: sites.results?.map(s => ({name: s.name, id: s.id}))}; }"
                                ),
                            }
                        },
                        "required": ["code"],
                    },
                ),
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: Any) -> list[TextContent]:
            """Handle tool calls."""
            try:
                if name == "search":
                    return await self._handle_search(arguments)
                elif name == "execute":
                    return await self._handle_execute(arguments)
                else:
                    return [
                        TextContent(
                            type="text",
                            text=f"Unknown tool: {name}",
                        )
                    ]
            except Exception as e:
                logger.error(f"Tool call error: {e}", exc_info=True)
                return [
                    TextContent(
                        type="text",
                        text=f"Error: {str(e)}",
                    )
                ]

    async def _handle_search(self, arguments: dict) -> list[TextContent]:
        """Handle search tool call."""
        code = arguments.get("code")
        if not code:
            return [TextContent(type="text", text="Error: 'code' parameter required")]
        
        logger.info(f"Executing search with code length: {len(code)}")
        
        result = await self.sandbox.run_search(
            code=code,
            spec_path=str(self.spec_path),
        )
        
        # Format result as text
        import json
        result_text = json.dumps(result, indent=2)
        
        return [TextContent(type="text", text=result_text)]

    async def _handle_execute(self, arguments: dict) -> list[TextContent]:
        """Handle execute tool call."""
        code = arguments.get("code")
        if not code:
            return [TextContent(type="text", text="Error: 'code' parameter required")]
        
        logger.info(f"Executing API call with code length: {len(code)}")
        
        result = await self.sandbox.run_execute(
            code=code,
            api_token=self.config.mist_apitoken,
            api_host=self.config.mist_host,
        )
        
        # Format result as text
        import json
        result_text = json.dumps(result, indent=2)
        
        return [TextContent(type="text", text=result_text)]

    async def run(self):
        """Run the MCP server."""
        logger.info("Starting MistMind MCP server...")
        logger.info(f"Spec path: {self.spec_path}")
        logger.info(f"Deno path: {self.config.deno_path}")
        logger.info(f"API host: {self.config.mist_host}")
        
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options(),
            )
