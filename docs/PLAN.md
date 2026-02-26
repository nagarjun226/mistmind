# MistMind MCP Server — Build Plan

## Why We Can Do Better

### Reference Analysis (the reference MistMCP implementation)
- **40 tools** covering ~60-70 of 1011 API operations (~6% coverage)
- Auto-generated from OpenAPI spec — tool descriptions are API docs, not LLM-friendly
- Depends on `mistapi` Python SDK (heavy, opaque)
- **No intelligent tool selection** — all 40+ tools exposed simultaneously, LLM must pick
- **No response intelligence** — dumps raw JSON, wastes tokens
- **No context/session awareness** — every call is stateless, no caching
- **No composite workflows** — can't do "show me network health" in one call
- **Missing huge chunks** of the API: maps, PCaps, utilities, webhooks, location, zones, etc.
- **Excluded 100+ tags** including all site-level clients, utilities, maps, beacons, zones

### Our Edge: "Intelligent Tool Selection"
The key insight: **fewer, smarter tools > many dumb tools**.

LLMs perform better with:
1. **Fewer tools** with rich, natural-language descriptions
2. **Intent-based routing** — "what do you want to know?" vs "pick from 40 API endpoints"
3. **Summarized responses** — don't dump 500-line JSON, summarize with key metrics
4. **Context memory** — remember org_id, site_id, previous results within a session

## Architecture

### Core Principles
1. **Direct REST API** — No `mistapi` SDK. Just `httpx` + OpenAPI spec. Lighter, transparent, debuggable.
2. **Semantic Tool Design** — 10-12 high-level tools that internally route to 200+ API endpoints
3. **Response Intelligence** — Summarize, highlight anomalies, paginate smartly
4. **Session Context** — Cache org/site/device lookups, track conversation state
5. **MCP SDK** — Use official `mcp` Python SDK (not fastmcp)

### Tool Design (10 Tools → 200+ API Endpoints)

| Tool | Description | Internal API Coverage |
|------|-------------|---------------------|
| `mist_query` | Natural language query about network state | Stats, devices, clients, ports, BGP/OSPF |
| `mist_troubleshoot` | Diagnose issues with Marvis + events | Marvis troubleshoot, events, alarms, SLEs |
| `mist_configure` | Read/write configuration objects | All config endpoints (templates, WLANs, policies, etc.) |
| `mist_devices` | Device inventory, status, firmware | Inventory, device stats, upgrades, synthetic tests |
| `mist_clients` | Client analytics (wireless, wired, WAN, NAC) | All client search/stats endpoints |
| `mist_sites` | Site management and insights | Site CRUD, settings, SLEs, RRM, rogues |
| `mist_search` | Universal search across all objects | All search endpoints unified |
| `mist_audit` | Security, compliance, audit trail | Audit logs, rogues, NAC, alarms |
| `mist_maps` | Floor plans, zones, location | Maps, zones, beacons, location services |
| `mist_utilities` | Network utilities (ping, trace, pcap, etc.) | All utility endpoints |
| `mist_self` | Account info, org, licensing | Self, org info, licenses, constants |
| `mist_webhooks` | Webhook management | Webhook CRUD, delivery search |

### Key Differentiators

#### 1. Intelligent Intent Routing
```
User: "Show me all APs that are down"
→ mist_query routes to: searchDevices(status="disconnected", type="ap")
→ Enriches with: site names, last seen times
→ Returns: Summary table, not raw JSON
```

#### 2. Response Summarization
```
Raw API: 500-line JSON with every device field
Our response: "12 of 847 APs are offline across 3 sites:
  - SF-Office: 5 down (AP41, AP43-crit, AP45, AP47, AP49)
  - NYC-HQ: 4 down
  - Denver: 3 down
  Most recent: AP43 went down 12min ago (was up for 47 days)"
```

#### 3. Context Memory
```
Call 1: mist_self → caches org_id
Call 2: mist_sites("SF Office") → caches site_id
Call 3: mist_clients() → automatically uses cached site_id
```

#### 4. Coverage Comparison
- Reference: ~40 tools, ~70 API calls, 6% of API
- Ours: 12 tools, ~200+ API calls, 20%+ of API
- Critical missing areas we cover: Maps, Utilities, Location, Webhooks, full Client spectrum

## Tech Stack
- **Python 3.12+**
- **`mcp` SDK** (official, maintained by Anthropic)
- **`httpx`** for async HTTP (no SDK dependency)
- **`pydantic`** for request/response models
- **OpenAPI spec** bundled for reference (but we write smarter wrappers)

## Project Structure
```
mist-mcp-code/
├── pyproject.toml
├── README.md
├── PLAN.md
├── src/
│   └── mistmind/
│       ├── __init__.py
│       ├── __main__.py          # Entry point
│       ├── server.py            # MCP server setup
│       ├── config.py            # Configuration (env vars, CLI args)
│       ├── client.py            # Mist API HTTP client (httpx)
│       ├── context.py           # Session context (cached IDs, state)
│       ├── formatter.py         # Response summarization & formatting
│       ├── tools/
│       │   ├── __init__.py
│       │   ├── query.py         # mist_query
│       │   ├── troubleshoot.py  # mist_troubleshoot
│       │   ├── configure.py     # mist_configure
│       │   ├── devices.py       # mist_devices
│       │   ├── clients.py       # mist_clients
│       │   ├── sites.py         # mist_sites
│       │   ├── search.py        # mist_search
│       │   ├── audit.py         # mist_audit
│       │   ├── maps.py          # mist_maps
│       │   ├── utilities.py     # mist_utilities
│       │   ├── self_info.py     # mist_self
│       │   └── webhooks.py      # mist_webhooks
│       └── api/
│           ├── __init__.py
│           ├── endpoints.py     # API endpoint definitions
│           └── models.py        # Pydantic models for common types
├── tests/
│   ├── conftest.py
│   ├── test_server.py
│   ├── test_client.py
│   ├── test_tools/
│   │   └── ...
│   └── fixtures/
│       └── ...
└── .env.example
```

## Build Phases

### Phase 1: Core (Today)
- Project scaffolding + git init
- Config, HTTP client, context manager
- `mist_self` tool (simplest, validates auth)
- `mist_query` tool (stats + devices — the most-used)
- `mist_sites` tool
- Basic response formatting

### Phase 2: Coverage (Next)
- `mist_troubleshoot` (Marvis, events, SLEs)
- `mist_devices` (inventory, firmware, synthetic tests)
- `mist_clients` (wireless, wired, WAN, NAC)
- `mist_configure` (read + write with confirmation)
- `mist_search` (universal search)

### Phase 3: Advanced
- `mist_audit` (security, rogues, compliance)
- `mist_maps` (floor plans, zones, location)
- `mist_utilities` (ping, trace, pcap)
- `mist_webhooks` (CRUD + delivery tracking)

### Phase 4: Polish
- Comprehensive tests
- Response summarization tuning
- Documentation
- GitHub private repo publish
