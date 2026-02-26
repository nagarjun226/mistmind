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
│  │  • Generates    │  │  • Rate limiting (30/min)        │ │
│  │    hierarchy    │  │  • Token isolation (IIFE)        │ │
│  │  • ~800 tokens  │  │  • Output scrubbing              │ │
│  └─────────────────┘  └──────────────────────────────────┘ │
└──────────────┬──────────────────────┬───────────────────────┘
               │                      │
               ▼                      ▼
    spec/mist.resolved.json    api.mist.com
         (84MB, local)         (REST API)
```

## How It Works

### 1. Index Generation (Initialization)
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

### 2. Search (Discovery)
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

Runs in hardened Deno sandbox with **no network access** — only reads the local spec file.

### 3. Execute (Action)
LLM chains API calls:
```javascript
async () => {
  const self = await mist.request({path: '/api/v1/self'});
  const org_id = self.privileges[0].org_id;
  
  const devices = await mist.request({
    path: `/api/v1/orgs/${org_id}/inventory`
  });
  
  return {
    org_id,
    device_count: devices.length,
    devices: devices.map(d => ({name: d.name, model: d.model, type: d.type}))
  };
}
```

## Quick Start

### 1. Prerequisites
- Python 3.11+
- [Deno](https://deno.land/) runtime
- Mist API token

### 2. Install
```bash
git clone https://github.com/nagarjun226/mistmind.git
cd mistmind
python -m venv venv
source venv/bin/activate
pip install -e .
```

### 3. Configure
```bash
cp .env.example .env
# Edit .env with your Mist API token
```

### 4. Add to Claude Desktop
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

See `claude_desktop_config.example.json` for a full example.

## Comparison: MistMind vs Traditional MCP

| Aspect | Traditional MCP | MistMind |
|--------|----------------|----------|
| **Initial tokens** | ~5,000-20,000 | ~800 |
| **API coverage** | Partial (popular endpoints) | Complete (1,011 endpoints) |
| **Round trips** | 1 (direct call) | 2-3 (search → execute) |
| **Maintenance** | Manual sync with API | Auto-generates from spec |
| **Private APIs** | Requires training data | Works with any OpenAPI spec |

## Security

MistMind is built with defense-in-depth:

- **Deno sandbox isolation** — Each execution is a fresh process
- **IIFE token closure** — API token lives in closure scope, unreachable by user code
- **stdin token passing** — Token never written to disk or source files
- **Network allowlist** — Execute mode only reaches `api.mist.com`
- **API mode enforcement** — `readonly` blocks all writes (server-side, not bypassable)
- **Rate limiting** — 30 req/min, max 5 concurrent (configurable)
- **Output scrubbing** — Token removed from all stdout/stderr/errors
- **Temp file hardening** — `0o600` permissions, atomic writes

**191 security tests** including red team attack vectors: token exfiltration, sandbox escape, timing side-channels, DNS rebinding, Unicode normalization, regex DoS, and more. See `docs/security/` for audit reports.

## The "Private API" Proof

The spec indexer has **zero Mist-specific knowledge**. It works on any OpenAPI 3.x spec.

**Proof:** The obfuscation test (`tests/test_obfuscation.py`) renames all Mist-specific terms:
- `orgs` → `entities`, `sites` → `locations`, `devices` → `nodes`

MistMind still discovers and searches correctly. This proves it works on **private/unknown APIs without training data**.

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `MIST_APITOKEN` | Mist API token | (required) |
| `MIST_HOST` | Mist API host | `api.mist.com` |
| `MISTMIND_API_MODE` | `readonly` / `readwrite` / `all` | `readonly` |
| `MISTMIND_RATE_LIMIT` | Requests per minute (0=unlimited) | `30` |
| `MISTMIND_MAX_CONCURRENT` | Max parallel sandbox processes | `5` |
| `MISTMIND_SPEC_PATH` | Custom OpenAPI spec path | `spec/mist.resolved.json` |

## Development

```bash
source venv/bin/activate
python -m pytest tests/ -v --cov     # Run tests with coverage
ruff check src/ tests/               # Lint
ruff format src/ tests/              # Format
```

## Project Structure

```
mistmind/
├── src/mistmind/          # Source code
│   ├── __main__.py        # CLI entry point
│   ├── config.py          # Pydantic settings
│   ├── sandbox.py         # Deno sandbox (search + execute)
│   ├── server.py          # MCP server handlers
│   ├── spec_indexer.py    # OpenAPI → ~800 token index
│   └── spec_resolver.py   # $ref resolver
├── tests/                 # 191 tests (86% coverage)
├── spec/                  # OpenAPI spec + resolver
├── docs/                  # Architecture, benchmarks, security audits
├── pyproject.toml
└── README.md
```

## License

MIT

## Credits

Built by [Nagarjun Srinivasan](https://github.com/nagarjun226). Inspired by the Code Mode MCP pattern for progressive API disclosure.
