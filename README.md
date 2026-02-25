# MistMind MCP Server

**Code Mode MCP** for the Juniper Mist API — **1,011 endpoints** in **~800 tokens**.

MistMind makes massive APIs accessible to LLMs without training data. Instead of hardcoding every endpoint, it gives the LLM:
1. A dynamic index of the API hierarchy (~800 tokens)
2. A hardened Deno sandbox to search & execute against the full OpenAPI spec
3. Zero pre-training on the API required

## Why MistMind?

Traditional MCP servers face a brutal tradeoff:
- **Document everything** → Token explosion, context limits
- **Document nothing** → LLM can't discover what's available

MistMind solves this with **progressive disclosure**:
- **Initial:** ~800 tokens for API hierarchy (scopes, categories, counts)
- **Search:** LLM writes JS to explore the 84MB resolved spec
- **Execute:** LLM chains API calls with full OpenAPI context

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Claude Desktop / MCP Client                                │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  LLM (Claude, GPT-4, etc.)                           │  │
│  │  • Sees: "Search API (1011 endpoints) + hierarchy"   │  │
│  │  • Writes: JS code to search/execute                 │  │
│  └──────────────────────────────────────────────────────┘  │
└──────────────────────┬──────────────────────────────────────┘
                       │ MCP Protocol (stdio)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  MistMind MCP Server (Python)                               │
│  ┌─────────────────┐  ┌──────────────────────────────────┐ │
│  │  Spec Indexer   │  │  Deno Sandbox                    │ │
│  │  • Analyzes     │  │  • --deny-net (search mode)      │ │
│  │    OpenAPI      │  │  • --allow-net=api.mist.com      │ │
│  │  • Generates    │  │  • Rate limiting                 │ │
│  │    hierarchy    │  │  • Token scrubbing               │ │
│  │  • ~800 tokens  │  │  • Timeout enforcement           │ │
│  └─────────────────┘  └──────────────────────────────────┘ │
└──────────────┬──────────────────────┬───────────────────────┘
               │                      │
               ▼                      ▼
    spec/mist.resolved.json    api.mist.com
         (84MB, local)         (REST API)
```

## How It Works

### 1. **Index Generation** (Initialization)
```python
from mistmind.spec_indexer import generate_index_from_file

index = generate_index_from_file("spec/mist.resolved.json")
# → ~800 token summary: scopes, categories, auth, pagination
```

The indexer auto-detects:
- **API Hierarchy:** Path prefixes + tag patterns → scopes (Orgs, Sites, MSPs, etc.)
- **Auth Pattern:** Finds `/self` or `/me` endpoints
- **Pagination:** Detects `limit`, `page`, `start`, `end` params
- **Response Patterns:** Array vs paginated vs single object

### 2. **Search** (Discovery)
LLM writes JavaScript to explore the spec:
```javascript
async () => {
  const results = [];
  for (const [path, methods] of Object.entries(spec.paths)) {
    if (path.includes('/devices') && methods.get) {
      results.push({
        method: 'GET',
        path,
        summary: methods.get.summary,
        params: methods.get.parameters
      });
    }
  }
  return results;
}
```

Runs in hardened Deno sandbox:
- **No network access** (only reads local spec file)
- **30s timeout**
- Returns discovered endpoints with full OpenAPI metadata

### 3. **Execute** (Action)
LLM chains API calls:
```javascript
async () => {
  // Get current user context
  const self = await mist.request({path: '/api/v1/self'});
  const org_id = self.privileges[0].org_id;
  
  // List devices in that org
  const devices = await mist.request({
    path: `/api/v1/orgs/${org_id}/devices/search`,
    params: {limit: 100}
  });
  
  return {
    org_id,
    device_count: devices.results.length,
    devices: devices.results.map(d => ({
      name: d.name,
      model: d.model,
      status: d.status
    }))
  };
}
```

Sandbox features:
- **Network restricted to `api.mist.com`** (or configured host)
- **Rate limiting:** 30 requests/min, max 5 concurrent
- **API mode:** `readonly` (GET only) or `full` (GET/POST/PUT/DELETE/PATCH)
- **Token scrubbing:** Removes API token from all error messages

## Quick Start

### 1. Clone & Install
```bash
git clone https://github.com/your-org/mist-mcp.git
cd mist-mcp
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
```

### 2. Configure
Set environment variables:
```bash
export MIST_APITOKEN="your-mist-api-token"
export MIST_HOST="api.mist.com"
export MISTMIND_API_MODE="readonly"  # or "full"
```

Or create a `.env` file:
```
MIST_APITOKEN=your-mist-api-token
MIST_HOST=api.mist.com
MISTMIND_API_MODE=readonly
```

### 3. Add to Claude Desktop
Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "mistmind": {
      "command": "python",
      "args": ["-m", "mistmind"],
      "env": {
        "MIST_APITOKEN": "your-token-here",
        "MIST_HOST": "api.mist.com",
        "MISTMIND_API_MODE": "readonly"
      }
    }
  }
}
```

Restart Claude Desktop. You should see "MistMind" in the MCP servers list.

## Comparison: MistMind vs Traditional MCP

| Aspect | Traditional MCP | MistMind |
|--------|----------------|----------|
| **Initial tokens** | ~5,000-20,000 (all endpoints) | ~800 (hierarchy only) |
| **API coverage** | Partial (popular endpoints) | Complete (all 1,011 endpoints) |
| **Round trips** | 1 (direct call) | 2-3 (search → execute) |
| **Maintenance** | Manual (sync with API changes) | Auto (regenerates from spec) |
| **Private APIs** | Requires training data | Works with any OpenAPI spec |
| **Discovery** | Pre-documented only | LLM explores full spec |

**Key insight:** The 1-2 extra round trips are worth it for 10-25x token savings and complete API coverage.

## Security Model

### Deno Sandbox
- **Isolated execution:** Each JS function runs in a fresh Deno process
- **Principle of least privilege:**
  - Search mode: `--deny-net` (no network)
  - Execute mode: `--allow-net=api.mist.com` (only Mist API)
- **Temp file permissions:** `0o600` (owner read/write only)
- **Atomic file operations:** Prevents TOCTOU races

### API Protection
- **Rate limiting:** 30 req/min default (configurable)
- **Concurrency limits:** Max 5 parallel requests
- **Timeout enforcement:** 30s per execution
- **Token scrubbing:** API token removed from all error messages
- **API mode enforcement:** `readonly` blocks POST/PUT/DELETE/PATCH

### Trust Model
- **User code is untrusted:** LLM-generated JS runs in sandbox
- **Spec file is trusted:** Read-only, local file
- **API token is secret:** Never exposed in logs or errors
- **Network access is restricted:** Explicit allow-list only

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `MIST_APITOKEN` | Mist API token | None | Yes |
| `MIST_HOST` | Mist API host | `api.mist.com` | No |
| `MISTMIND_API_MODE` | `readonly` or `full` | `readonly` | No |
| `MISTMIND_RATE_LIMIT` | Requests per minute | `30` | No |
| `MISTMIND_MAX_CONCURRENT` | Max parallel requests | `5` | No |
| `MISTMIND_SPEC_PATH` | Custom spec path | `spec/mist.resolved.json` | No |

### API Modes

**`readonly` (recommended for exploration):**
- Allows: `GET`, `HEAD`, `OPTIONS`
- Blocks: `POST`, `PUT`, `DELETE`, `PATCH`
- Use case: Exploring the API, dashboards, analytics

**`full` (use with caution):**
- Allows: All HTTP methods
- Use case: Automation, configuration management
- **Risk:** LLM can modify/delete resources

## The "Private API" Story

**Problem:** Most MCP servers only work on well-known APIs (GitHub, Jira, etc.) because they're trained on those APIs.

**MistMind's approach:** Generic OpenAPI analysis. The spec_indexer has **zero Mist-specific knowledge**. It:
1. Analyzes path prefixes to detect scopes
2. Groups tags by common patterns
3. Detects auth/pagination from structure
4. Works on **any** OpenAPI 3.x spec

**Proof:** The obfuscation test (`tests/test_obfuscation.py`) renames everything:
- `orgs` → `entities`
- `sites` → `locations`
- `devices` → `nodes`
- `wlans` → `wireless_networks`

MistMind still discovers and searches the API correctly. This proves it works on **private/unknown APIs without training data**.

### Using MistMind for Your API

1. Get your OpenAPI spec (3.0 or 3.1)
2. Resolve `$refs` with `python -m mistmind.spec_resolver`
3. Update `MIST_HOST` and `MIST_APITOKEN` to your API
4. Done! MistMind auto-generates the index

## Development

### Run Tests
```bash
source venv/bin/activate
python -m pytest tests/ -v
```

**Test coverage:**
- `test_sandbox.py` — Deno sandbox security (43 tests)
- `test_server.py` — MCP server handlers (25 tests)
- `test_security.py` — Security hardening (8 tests)
- `test_obfuscation.py` — Private API proof (8 tests)

### Run Obfuscation Demo
```bash
python tests/test_obfuscation.py
# Generates obfuscated spec, prints index, runs search queries
```

### Code Style
```bash
ruff check src/ tests/
ruff format src/ tests/
```

## Contributing

We welcome contributions! Areas of interest:
- **New OpenAPI patterns:** auth schemes, pagination styles, response formats
- **Performance:** Faster spec parsing, caching strategies
- **Security:** Additional sandbox hardening, threat modeling
- **Integrations:** Support for AsyncAPI, GraphQL introspection

Please:
1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-thing`)
3. Write tests (we're at 61% coverage, aim for 80%+)
4. Run tests (`pytest tests/ -v`)
5. Submit a PR

## License

MIT License - see LICENSE file for details.

## Credits

Built by the OpenClaw team. Inspired by:
- **Code Mode MCP pattern** — Progressive disclosure for massive APIs
- **Deno sandbox** — Secure JavaScript execution without Docker
- **OpenAPI 3.1** — Machine-readable API specs

## Support

- **Issues:** [GitHub Issues](https://github.com/your-org/mist-mcp/issues)
- **Discord:** [OpenClaw Community](https://discord.gg/openclaw)
- **Email:** support@openclaw.io
