# MistMind

**Intelligent MCP Server for Juniper Mist API**

MistMind provides semantic, LLM-friendly tools for network management via the Mist API. Unlike auto-generated MCP servers, MistMind uses intelligent tool design with intent-based routing, response summarization, and session context awareness.

## Key Features

- **Semantic Tool Design**: 5 high-level tools (vs. 40+ auto-generated tools) with natural language descriptions
- **Intelligent Routing**: Tools automatically route to the right API endpoints based on intent
- **Response Intelligence**: Summarized responses with human-readable overviews, not raw JSON dumps
- **Session Context**: Caches org_id, site_id, device lookups to reduce API calls
- **Direct REST**: Uses `httpx` for transparent API calls, no heavy SDK dependency
- **Pagination Handling**: Automatically follows pagination for complete results

## Tools Overview

| Tool | Purpose | API Coverage |
|------|---------|--------------|
| `mist_self` | Account and org information | User info, org details, licenses, constants |
| `mist_sites` | Site management and insights | List sites, stats, SLEs, RRM, rogues |
| `mist_query` | Network data retrieval (the powerhouse) | Devices, clients, stats, ports, BGP/OSPF, WAN |
| `mist_devices` | Device inventory and firmware | Inventory, search, firmware versions, upgrades |
| `mist_search` | Universal search | Devices, clients, events, alarms |

## Installation

### Prerequisites
- Python 3.12+
- Mist API token (get from [Mist dashboard](https://manage.mist.com))

### Setup

```bash
# Clone the repo
git clone https://github.com/cheenu1092-oss/mistmind.git
cd mistmind

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Configure environment
cp .env.example .env
# Edit .env and add your MIST_APITOKEN
```

## Configuration

Create a `.env` file with:

```bash
# Required
MIST_APITOKEN=your-api-token-here

# Optional
MIST_HOST=https://api.mist.com          # Default: https://api.mist.com
MISTMIND_DEBUG=false                     # Enable debug logging
MISTMIND_ENABLE_WRITES=false             # Enable write operations (caution!)
MISTMIND_MAX_ITEMS=50                    # Max items in responses
MISTMIND_TIMEOUT=30                      # API request timeout (seconds)
```

## Usage

### As MCP Server (Claude Desktop, etc.)

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "mistmind": {
      "command": "mistmind",
      "args": ["--transport", "stdio"],
      "env": {
        "MIST_APITOKEN": "your-token-here"
      }
    }
  }
}
```

### Command Line

```bash
# Stdio transport (for MCP clients)
mistmind --transport stdio

# SSE transport (HTTP server)
mistmind --transport sse --host 0.0.0.0 --port 8000

# Enable debug logging
mistmind --debug

# Load env from custom file
mistmind --env-file /path/to/.env
```

## Example Workflows

### Network Overview
```
1. mist_self → understand org context
2. mist_sites (action=list) → see all locations
3. mist_query (type=devices) → device inventory
4. mist_query (type=clients) → active clients
```

### Troubleshooting
```
1. mist_query (type=devices, filters={"status": "disconnected"}) → offline devices
2. mist_sites (action=stats, site_id=...) → site health
3. mist_query (type=device_stats, device_id=...) → detailed metrics
```

### Firmware Management
```
1. mist_devices (action=inventory) → current versions
2. mist_devices (action=available_versions) → what's available
3. mist_devices (action=upgrades) → check upgrade status
```

## Development

### Run Tests

```bash
pytest
pytest --cov=src/mistmind  # With coverage
```

### Code Quality

```bash
ruff check src/
ruff format src/
```

## Architecture

MistMind differs from auto-generated MCP servers:

- **Fewer, smarter tools**: 5 tools vs. 40+, with rich natural-language descriptions
- **Intent-based routing**: "what do you want to know?" vs. "pick from 40 API endpoints"
- **Summarized responses**: Human-readable overviews, not 500-line JSON dumps
- **Context awareness**: Caches org/site/device lookups within a session
- **Direct REST**: Uses `httpx` + OpenAPI spec, no heavy SDK dependency

See [PLAN.md](PLAN.md) for detailed architecture and design decisions.

## Roadmap

### Phase 1 (Current)
- ✅ Core MCP server infrastructure
- ✅ 5 essential tools (self, sites, query, devices, search)
- ✅ Response formatting and summarization
- ✅ Session context caching

### Phase 2 (Next)
- [ ] Troubleshooting tools (Marvis, events, SLEs)
- [ ] Configuration management (read + write)
- [ ] Client analytics (wireless, wired, WAN, NAC)

### Phase 3 (Future)
- [ ] Maps and location services
- [ ] Network utilities (ping, trace, pcap)
- [ ] Webhook management
- [ ] Audit and compliance tools

## Contributing

This is a private project, but suggestions and bug reports are welcome via issues.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Credits

Built by [Cheenu](https://github.com/cheenu1092-oss) as an intelligent alternative to auto-generated Mist MCP servers.

Inspired by [tmunzer/mistmcp](https://github.com/tmunzer/mistmcp) but designed from scratch for better LLM interaction.
