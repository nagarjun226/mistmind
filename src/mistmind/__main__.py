"""
MistMind CLI entry point
"""
import argparse
import asyncio
import logging
import sys
from pathlib import Path

from dotenv import load_dotenv

from mistmind.config import ServerConfig
from mistmind.server import create_server


def setup_logging(debug: bool = False):
    """Configure logging for the server"""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],
    )


def parse_args():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description="MistMind - Intelligent MCP Server for Juniper Mist API"
    )
    
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport mode (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to for SSE transport (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind to for SSE transport (default: 8000)",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=None,
        help="Path to .env file (default: .env in current directory)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--enable-writes",
        action="store_true",
        help="Enable write operations (caution: modifies network config)",
    )
    
    return parser.parse_args()


async def main():
    """Main entry point"""
    args = parse_args()
    
    # Load environment variables
    env_file = args.env_file or Path.cwd() / ".env"
    if env_file.exists():
        load_dotenv(env_file)
    
    # Setup logging
    setup_logging(args.debug)
    logger = logging.getLogger(__name__)
    
    # Load configuration
    config = ServerConfig.from_env()
    config.debug = args.debug or config.debug
    config.enable_writes = args.enable_writes or config.enable_writes
    
    if not config.api_token:
        logger.error("MIST_APITOKEN environment variable is required")
        sys.exit(1)
    
    logger.info("Starting MistMind MCP Server")
    logger.info(f"Transport: {args.transport}")
    logger.info(f"API Host: {config.api_host}")
    logger.info(f"Write operations: {'enabled' if config.enable_writes else 'disabled'}")
    
    # Create and run server
    server = create_server(config)
    
    if args.transport == "stdio":
        from mcp.server.stdio import stdio_server
        
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options()
            )
    else:
        # SSE transport
        from mcp.server.sse import SseServerTransport
        from starlette.applications import Starlette
        from starlette.routing import Route
        
        sse = SseServerTransport("/messages")
        
        async def handle_sse(request):
            async with sse.connect_sse(
                request.scope, request.receive, request._send
            ) as streams:
                await server.run(
                    streams[0], streams[1], server.create_initialization_options()
                )
        
        async def handle_messages(request):
            await sse.handle_post_message(request.scope, request.receive, request._send)
        
        app = Starlette(
            routes=[
                Route("/sse", endpoint=handle_sse),
                Route("/messages", endpoint=handle_messages, methods=["POST"]),
            ]
        )
        
        import uvicorn
        uvicorn.run(app, host=args.host, port=args.port)


def main_sync():
    """Synchronous entry point for console script"""
    asyncio.run(main())


if __name__ == "__main__":
    main_sync()
