# MistMind Quick Start Guide

Get up and running with MistMind in 5 minutes.

---

## Prerequisites

✅ Python 3.12+ installed  
✅ Deno 2.6.10+ installed at `~/.deno/bin/deno`  
✅ Mist API token from [Mist Dashboard](https://manage.mist.com/)

---

## Step 1: Environment Setup

The project is already set up at `/Users/cheenu/clawd/projects/mist-mcp-code`.

```bash
cd /Users/cheenu/clawd/projects/mist-mcp-code
source venv/bin/activate
```

**Verify installation:**
```bash
mistmind --version
# Expected output: mistmind 0.1.0
```

---

## Step 2: Configure API Token

Copy the example environment file:
```bash
cp .env.example .env
```

Edit `.env` and add your Mist API token:
```bash
MIST_APITOKEN=your-actual-mist-api-token-here
MIST_HOST=api.mist.com
MISTMIND_DEBUG=false
```

**Get your token:**
1. Log in to [Mist Dashboard](https://manage.mist.com/)
2. Go to Organization Settings → API Tokens
3. Create a new token with appropriate permissions
4. Copy the token to your `.env` file

---

## Step 3: Test the Server Standalone

Run the server in debug mode to verify it works:

```bash
mistmind --debug
```

**Expected output:**
```
2026-02-23 08:45:00 [INFO] mistmind.server: Starting MistMind MCP server...
2026-02-23 08:45:00 [INFO] mistmind.server: Spec path: /Users/cheenu/clawd/projects/mist-mcp-code/spec/mist.resolved.json
2026-02-23 08:45:00 [INFO] mistmind.server: Deno path: /Users/cheenu/.deno/bin/deno
2026-02-23 08:45:00 [INFO] mistmind.server: API host: api.mist.com
```

The server is now waiting for MCP protocol messages on stdin.

Press `Ctrl+C` to stop.

---

## Step 4: Add to Claude Desktop

### Find Claude Desktop Config

Location: `~/Library/Application Support/Claude/claude_desktop_config.json`

### Add MistMind Server

Edit the config file and add:

```json
{
  "mcpServers": {
    "mistmind": {
      "command": "/Users/cheenu/clawd/projects/mist-mcp-code/venv/bin/python",
      "args": ["-m", "mistmind"],
      "env": {
        "MIST_APITOKEN": "your-actual-mist-token-here",
        "MIST_HOST": "api.mist.com"
      }
    }
  }
}
```

**Important:** Replace `your-actual-mist-token-here` with your real token.

### Restart Claude Desktop

1. Quit Claude Desktop completely
2. Relaunch Claude Desktop
3. Look for MistMind in the available tools

---

## Step 5: Test with Claude

### Example Prompt 1: Explore the API

```
Using the search tool, show me how many total API endpoints are available in the Mist API, 
and give me the top 10 most common path parameters.
```

Claude will write JavaScript code like:
```javascript
async () => {
  let total = 0;
  const params = new Set();
  
  for (const [path, methods] of Object.entries(spec.paths)) {
    total += Object.keys(methods).length;
    const matches = path.match(/\{([^}]+)\}/g);
    if (matches) matches.forEach(m => params.add(m));
  }
  
  return {
    total_operations: total,
    total_paths: Object.keys(spec.paths).length,
    top_params: Array.from(params).sort().slice(0, 10)
  };
}
```

### Example Prompt 2: Find Specific Endpoints

```
Search the Mist API spec for all endpoints related to "wireless clients" 
and show me their HTTP methods, paths, and summaries.
```

Claude will write:
```javascript
async () => {
  const results = [];
  for (const [path, methods] of Object.entries(spec.paths)) {
    for (const [method, op] of Object.entries(methods)) {
      if (op.summary?.toLowerCase().includes('wireless') && 
          op.summary?.toLowerCase().includes('client')) {
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

### Example Prompt 3: Call the API (with real token)

```
Get my Mist account info, then list all sites in my organization.
```

Claude will write:
```javascript
async () => {
  // Get current user info
  const self = await mist.request({path: '/api/v1/self'});
  const org_id = self.privileges[0].org_id;
  
  // Get organization details
  const org = await mist.request({path: `/api/v1/orgs/${org_id}`});
  
  // Get sites
  const sites = await mist.request({path: `/api/v1/orgs/${org_id}/sites`});
  
  return {
    user: {
      email: self.email,
      name: self.first_name + ' ' + self.last_name
    },
    organization: {
      id: org.id,
      name: org.name
    },
    sites: sites.map(s => ({
      id: s.id,
      name: s.name,
      timezone: s.timezone
    }))
  };
}
```

---

## Understanding the Two Tools

### 🔍 `search` Tool

**What it does:** Search the OpenAPI spec  
**Input:** JavaScript async arrow function  
**Available:** `spec` object (full OpenAPI 3.1 spec)  
**Use for:**
- Finding endpoints by tag, path, summary
- Analyzing API structure (parameters, schemas)
- Understanding available operations
- Exploring data models

**Example spec structure:**
```javascript
spec.paths['/api/v1/orgs/{org_id}/sites'] = {
  get: {
    summary: 'listOrgSites',
    tags: ['Sites'],
    parameters: [...],
    responses: {...}
  },
  post: {
    summary: 'createOrgSite',
    tags: ['Sites'],
    ...
  }
}

spec.components.schemas['Site'] = {
  type: 'object',
  properties: {
    id: {type: 'string'},
    name: {type: 'string'},
    ...
  }
}
```

### ⚡ `execute` Tool

**What it does:** Make Mist API calls  
**Input:** JavaScript async arrow function  
**Available:** `mist.request()` method  
**Use for:**
- Getting account/org info
- Listing/searching sites, devices, clients
- Creating/updating resources
- Chaining multiple API calls
- Processing paginated results

**mist.request() signature:**
```javascript
await mist.request({
  method: 'GET',      // Optional, default: GET
  path: '/api/v1/...',  // Required
  body: {...},        // Optional, for POST/PUT/PATCH
  params: {           // Optional, query parameters
    limit: 100,
    offset: 0
  }
})
```

---

## Common Patterns

### Pattern 1: Progressive Discovery

1. Use `search` to find relevant endpoints
2. Use `search` to inspect request/response schemas
3. Use `execute` to call the API
4. Iterate based on results

### Pattern 2: Chain API Calls

```javascript
async () => {
  // Get org ID
  const self = await mist.request({path: '/api/v1/self'});
  const org_id = self.privileges[0].org_id;
  
  // Use org ID in subsequent calls
  const sites = await mist.request({
    path: `/api/v1/orgs/${org_id}/sites/search`,
    params: {limit: 100}
  });
  
  // Process results
  return {
    org_id,
    site_count: sites.total,
    sites: sites.results
  };
}
```

### Pattern 3: Pagination

```javascript
async () => {
  const allResults = [];
  let offset = 0;
  const limit = 100;
  
  while (true) {
    const response = await mist.request({
      path: '/api/v1/orgs/${org_id}/devices',
      params: {limit, offset}
    });
    
    allResults.push(...response.results);
    
    if (response.results.length < limit) break;
    offset += limit;
  }
  
  return {total: allResults.length, devices: allResults};
}
```

---

## Troubleshooting

### Server won't start

**Error:** `Deno not found`  
**Fix:** Install Deno or set `DENO_PATH` in `.env`

**Error:** `Spec file not found`  
**Fix:** Run `python -m mistmind.spec_resolver spec/mist.openapi.json spec/mist.resolved.json`

**Error:** `MIST_APITOKEN required`  
**Fix:** Set `MIST_APITOKEN` in `.env` or environment

### Tools not appearing in Claude

1. Check config file syntax (valid JSON)
2. Verify paths are absolute
3. Restart Claude Desktop completely
4. Check Claude's logs: `~/Library/Logs/Claude/`

### API calls failing

**Error:** `401 Unauthorized`  
**Fix:** Verify your `MIST_APITOKEN` is correct and active

**Error:** `403 Forbidden`  
**Fix:** Check token has required permissions in Mist Dashboard

**Error:** `Network timeout`  
**Fix:** Increase timeout in sandbox.py (default: 30s)

---

## Advanced Configuration

### Custom Deno Path

If Deno is installed elsewhere:

```bash
# .env
DENO_PATH=/custom/path/to/deno
```

### Enable Debug Logging

```bash
# .env
MISTMIND_DEBUG=true
```

Or via command line:
```bash
mistmind --debug
```

### Use Different Mist Region

```bash
# .env
MIST_HOST=api.eu.mist.com  # Europe
MIST_HOST=api.gc1.mist.com # GovCloud
```

---

## Next Steps

1. ✅ **Start using it!** Try the example prompts above
2. 📊 **Monitor usage:** See what patterns LLMs discover
3. 🎓 **Learn the API:** Use `search` to explore available endpoints
4. 🔧 **Build workflows:** Chain multiple calls for complex tasks
5. 📝 **Share patterns:** Document useful code snippets

---

## Resources

- **Mist API Docs:** https://api.mist.com/api/v1/docs/
- **MCP Specification:** https://modelcontextprotocol.io/
- **Deno Permissions:** https://deno.land/manual/basics/permissions
- **Project README:** See README.md in this directory

---

**Ready to go!** The server is production-ready and fully tested. Happy coding! 🚀
