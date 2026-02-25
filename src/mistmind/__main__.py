"""CLI entry point for MistMind MCP server."""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from dotenv import load_dotenv

from . import __version__
from .config import ServerConfig
from .server import MistMindServer


def setup_logging(debug: bool = False):
    """Configure logging."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


async def main(args: argparse.Namespace):
    """Main async entry point."""
    # Load env file if specified
    if args.env_file:
        env_path = Path(args.env_file)
        if not env_path.exists():
            print(f"Error: env file not found: {args.env_file}", file=sys.stderr)
            sys.exit(1)
        load_dotenv(env_path)
        config = ServerConfig()
    else:
        # Load from default .env or environment
        load_dotenv()
        config = ServerConfig()
    
    # Override debug setting from CLI
    if args.debug:
        config.mistmind_debug = True
    
    setup_logging(config.mistmind_debug)
    
    # BUG 8 FIX: Use config spec path if set, otherwise fall back to project root detection
    if config.mistmind_spec_path:
        spec_path = Path(config.mistmind_spec_path)
    else:
        # Default: resolved spec in spec/ directory relative to project root
        project_root = Path(__file__).parent.parent.parent
        spec_path = project_root / "spec" / "mist.resolved.json"
    
    if not spec_path.exists():
        print(
            f"Error: Resolved spec not found at {spec_path}",
            file=sys.stderr,
        )
        print(
            "\nPlease run the spec resolver first:",
            file=sys.stderr,
        )
        print(
            "  python -m mistmind.spec_resolver "
            "spec/mist.openapi.json spec/mist.resolved.json",
            file=sys.stderr,
        )
        sys.exit(1)
    
    # Create and run server
    try:
        server = MistMindServer(config, str(spec_path))
        await server.run()
    except KeyboardInterrupt:
        logging.info("Server stopped by user")
    except Exception as e:
        logging.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)


def main_sync():
    """Synchronous entry point for setup.py console_scripts."""
    parser = argparse.ArgumentParser(
        description="MistMind - Code Mode MCP Server for Juniper Mist API",
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"mistmind {__version__}",
    )
    
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport type (default: stdio)",
    )
    
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host for SSE transport (default: 127.0.0.1)",
    )
    
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for SSE transport (default: 8000)",
    )
    
    parser.add_argument(
        "--env-file",
        help="Path to .env file to load",
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    
    args = parser.parse_args()
    
    # For now, only stdio is implemented
    if args.transport != "stdio":
        print("Error: Only stdio transport is currently supported", file=sys.stderr)
        sys.exit(1)
    
    # Run async main
    asyncio.run(main(args))


if __name__ == "__main__":
    main_sync()
