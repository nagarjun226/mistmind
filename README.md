# MistMind 🧠

**Code Mode MCP Server for Juniper Mist API**

MistMind is a Model Context Protocol (MCP) server that implements Cloudflare's "Code Mode" pattern for the Juniper Mist API. Instead of exposing hundreds of individual tools, MistMind provides just **2 powerful tools** that let LLMs write JavaScript code to search the API spec and make API calls.

## 🎯 The Code Mode Pattern

Traditional MCP servers create one tool per API endpoint, leading to:
- 🔴 1000+ tools in the tool list
- 🔴 Massive context window usage (100K+ tokens just for tool definitions)
- 🔴 Poor LLM performance due to overwhelming choice

Code Mode solves this by providing:
- ✅ **2 tools total** (~1000 tokens for tool definitions)
- ✅ LLM writes JavaScript code to interact with the API
- ✅ Full API flexibility without context pollution
- ✅ Secure Deno sandbox with strict permissions

## 🚀 Quick Start

### Prerequisites

- Python 3.12+
- [Deno](https://deno.land/) 2.6.10+ installed at `~/.deno/bin/deno` or in PATH
- Mist API token from [Mist Dashboard](https://manage.mist.com/)

### Installation

```bash
# Clone or navigate to the project
cd /path/to/mist-mcp-code

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install package
pip install -e ".[dev]"

# Create .env file from example
cp .env.example .env
# Edit .env and add your MIST_APITOKEN

# Pre-resolve the OpenAPI spec (one-time setup)
python -m mistmind.spec_resolver spec/mist.openapi.json spec/mist.resolved.json
```

### Configuration

Edit `.env`:

```bash
MIST_APITOKEN=your-mist-api-token-here
MIST_HOST=api.mist.com
MISTMIND_DEBUG=false
```

### Running the Server

```bash
# Activate venv if not already active
source venv/bin/activate

# Run the server
mistmind --debug
```

The server runs in stdio mode and communicates via stdin/stdout following the MCP protocol.

## 🛠️ The Two Tools

### 1. `search` - Search the OpenAPI Spec

Search through 1011 Mist API operations by writing JavaScript code.

**Input**: JavaScript async arrow function that receives `spec`

**Example**:
```javascript
async () => {
  const results = [];
  for (const [path, methods] of Object.entries(spec.paths)) {
    for (const [method, op] of Object.entries(methods)) {
      if (op.tags?.some(t => t.toLowerCase().includes('wireless'))) {
        results.push({
          method: method.toUpperCase(),
          path,
          summary: op.summary
        });
      }
    }
  }
  return results;
}
```

**What you get**: The full OpenAPI 3.1 spec with all `$refs` pre-resolved inline.

**Deno permissions**: `--deny-net --allow-read=<spec_path> --deny-write --deny-env --deny-run`

### 2. `execute` - Call the Mist API

Execute API calls by writing JavaScript code. Chain calls, handle pagination, process results.

**Input**: JavaScript async arrow function that receives `mist` client

**Example**:
```javascript
async () => {
  // Get current user info
  const self = await mist.request({path: '/api/v1/self'});
  const org_id = self.privileges[0].org_id;
  
  // Search sites in organization
  const sites = await mist.request({
    path: `/api/v1/orgs/${org_id}/sites/search`
  });
  
  return {
    org_id,
    sites: sites.results?.map(s => ({
      name: s.name,
      id: s.id
    }))
  };
}
```

**The `mist` client**:
```javascript
mist.request({
  method: 'GET',      // HTTP method (default: GET)
  path: '/api/...',   // API path (required)
  body: {...},        // Request body (for POST/PUT/PATCH)
  params: {...}       // Query parameters
})
```

**Deno permissions**: `--allow-net=<mist_hosts> --deny-read --deny-write --deny-env --deny-run`

**Allowed hosts**: api.mist.com, api.eu.mist.com, api.gc*.mist.com, api.ac*.mist.com

## 🔒 Security

- **Deno Sandbox**: All JavaScript code runs in a restricted Deno process
- **No File Access**: Search tool can only read the spec file; execute tool has no file access
- **Network Isolation**: Execute tool can only connect to official Mist API hosts
- **No Environment Access**: Code cannot read environment variables
- **No Subprocesses**: Code cannot spawn other processes
- **30s Timeout**: All executions automatically terminate after 30 seconds

## 🎓 Usage with Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "mistmind": {
      "command": "/path/to/mist-mcp-code/venv/bin/python",
      "args": ["-m", "mistmind"],
      "env": {
        "MIST_APITOKEN": "your-token-here",
        "MIST_HOST": "api.mist.com"
      }
    }
  }
}
```

Or use an env file:

```json
{
  "mcpServers": {
    "mistmind": {
      "command": "/path/to/mist-mcp-code/venv/bin/python",
      "args": ["-m", "mistmind", "--env-file", "/path/to/.env"]
    }
  }
}
```

## 📊 Architecture

```
┌─────────────────────────────────────────┐
│  LLM (Claude, GPT-4, etc.)              │
│  - Sees 2 tools                         │
│  - Writes JavaScript code               │
└────────────┬────────────────────────────┘
             │ MCP Protocol
┌────────────▼────────────────────────────┐
│  MistMind MCP Server                    │
│  - Validates input                      │
│  - Wraps code in JS template            │
└────────────┬────────────────────────────┘
             │ Subprocess
┌────────────▼────────────────────────────┐
│  Deno Sandbox                           │
│  - Restricted permissions               │
│  - 30s timeout                          │
│  - Returns JSON result                  │
└─────────────────────────────────────────┘
```

## 🧪 Testing

```bash
# Run tests
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=src/mistmind --cov-report=html
```

## 📦 Project Structure

```
mist-mcp-code/
├── src/mistmind/
│   ├── __init__.py          # Version info
│   ├── __main__.py          # CLI entry point
│   ├── config.py            # Configuration management
│   ├── sandbox.py           # Deno sandbox (THE CORE)
│   ├── server.py            # MCP server implementation
│   └── spec_resolver.py     # $ref resolver
├── spec/
│   ├── mist.openapi.json    # Original Mist OpenAPI spec (2.6MB)
│   └── mist.resolved.json   # Pre-resolved spec (generated)
├── tests/
│   └── test_sandbox.py      # Sandbox security tests
├── pyproject.toml           # Package configuration
├── .env.example             # Environment template
└── README.md                # This file
```

## 🔍 Why Pre-resolve $refs?

The Mist OpenAPI spec has **13,846 $ref occurrences**. Pre-resolving them:
- Simplifies LLM code (no need to chase references)
- Improves search performance
- Reduces cognitive load in the sandbox

Circular references are replaced with `{$circular: "SchemaName"}`.

## 💡 Example Prompts

**"Show me all wireless endpoints"**
```javascript
// Uses search tool
async () => {
  const results = [];
  for (const [path, methods] of Object.entries(spec.paths)) {
    for (const [method, op] of Object.entries(methods)) {
      if (op.tags?.some(t => t.toLowerCase().includes('wireless'))) {
        results.push({method: method.toUpperCase(), path, summary: op.summary});
      }
    }
  }
  return results;
}
```

**"Get my organization's sites"**
```javascript
// Uses execute tool
async () => {
  const self = await mist.request({path: '/api/v1/self'});
  const org_id = self.privileges[0].org_id;
  const sites = await mist.request({path: `/api/v1/orgs/${org_id}/sites`});
  return sites;
}
```

## 📝 License

MIT License - see LICENSE file for details

## 🤝 Contributing

Contributions welcome! Please open an issue or PR.

## 🔗 Links

- [MCP Documentation](https://modelcontextprotocol.io/)
- [Juniper Mist API Docs](https://api.mist.com/api/v1/docs/)
- [Deno Security](https://deno.land/manual/basics/permissions)
- [Code Mode Pattern (Cloudflare)](https://developers.cloudflare.com/ai-gateway/mcp/)
