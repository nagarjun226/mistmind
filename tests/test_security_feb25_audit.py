"""New red team attack vectors - Feb 25, 2026 Audit."""

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


class TestFeb25AuditAttacks:
    """Creative attack vectors from Feb 25, 2026 security audit."""
    
    @pytest.mark.asyncio
    async def test_attack_promise_rejection_handler_hijack(self, sandbox):
        """Attack: Install global unhandledrejection handler to capture token from failed requests.
        
        If mist.request() fails and throws an error that contains the token (e.g., in headers),
        we might be able to capture it via a global rejection handler.
        """
        code = '''async () => {
            let captured = null;
            
            // Install global unhandled rejection handler
            globalThis.addEventListener('unhandledrejection', (event) => {
                captured = {
                    reason: String(event.reason),
                    promise: String(event.promise)
                };
            });
            
            // Try to trigger a request that might fail and leak token
            try {
                // Make a request to an invalid endpoint that should fail
                await mist.request({
                    method: "GET",
                    path: "/api/v1/definitely-not-a-real-endpoint-12345"
                });
            } catch(e) {
                // Expected to fail
            }
            
            // Wait a bit for rejection handler to fire
            await new Promise(resolve => setTimeout(resolve, 100));
            
            return {
                captured,
                // Try to also return the error directly
                directError: "checked"
            };
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        
        # Token should be scrubbed from rejection handler output
        assert SECRET_TOKEN not in result_str
        assert "[REDACTED]" in result_str or "captured" not in result or result.get("captured") is None
    
    @pytest.mark.asyncio
    async def test_attack_function_toString_injection(self, sandbox):
        """Attack: Override Function.prototype.toString to capture token when functions are stringified.
        
        If the sandbox code ever stringifies the mist.request function or any closure that contains
        the token, we might be able to capture it.
        """
        code = '''async () => {
            let captured = [];
            
            // Override Function.prototype.toString to capture function source
            const originalToString = Function.prototype.toString;
            Function.prototype.toString = function() {
                const source = originalToString.call(this);
                captured.push(source.substring(0, 500));
                return source;
            };
            
            // Try to trigger function stringification
            try {
                // Convert mist.request to string
                const mistRequestStr = String(mist.request);
                captured.push(mistRequestStr.substring(0, 500));
                
                // Try to stringify the entire mist object
                const mistStr = String(mist);
                captured.push(mistStr.substring(0, 500));
                
                // Try JSON.stringify with custom replacer
                JSON.stringify(mist, (key, value) => {
                    if (typeof value === 'function') {
                        captured.push(String(value).substring(0, 500));
                    }
                    return value;
                });
            } catch(e) {
                captured.push("error: " + e.message);
            }
            
            return {
                captured,
                length: captured.length
            };
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        
        # Token should be scrubbed from captured function sources
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_fetch_options_inspection(self, sandbox):
        """Attack: Try to intercept fetch() calls by monkey-patching or inspecting Request objects.
        
        The mist.request() function internally uses fetch(). If we can intercept the
        fetch call or inspect the Request object before it's sent, we might capture the
        Authorization header containing the token.
        """
        code = '''async () => {
            let captured = [];
            
            // Monkey-patch fetch to capture all calls
            const originalFetch = globalThis.fetch;
            globalThis.fetch = async function(url, options = {}) {
                // Try to capture the Authorization header
                captured.push({
                    url: String(url),
                    headers: options.headers ? {...options.headers} : {},
                    method: options.method || 'GET'
                });
                
                // Call original fetch
                return originalFetch(url, options);
            };
            
            // Make a request that should trigger our patched fetch
            try {
                await mist.request({path: "/api/v1/self"});
            } catch(e) {
                captured.push({error: e.message});
            }
            
            return {
                captured,
                interceptedCalls: captured.length
            };
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        
        # Token should be scrubbed from captured headers
        assert SECRET_TOKEN not in result_str
        # But we should see [REDACTED] in the Authorization header if it was captured
        if "captured" in result and result["captured"]:
            # Verify that if headers were captured, token is redacted
            for item in result.get("captured", []):
                if isinstance(item, dict) and "headers" in item:
                    auth_header = item["headers"].get("Authorization", "")
                    if "Token" in auth_header or "Bearer" in auth_header:
                        assert SECRET_TOKEN not in auth_header


class TestResourceExhaustion:
    """Test resource exhaustion attacks that might bypass timeout."""
    
    @pytest.mark.asyncio
    async def test_attack_memory_bomb(self, sandbox):
        """Attack: Try to allocate huge amounts of memory to crash the sandbox.
        
        This tests whether the sandbox properly limits memory usage.
        """
        code = '''async () => {
            try {
                // Try to allocate a huge array
                const bomb = new Array(1000000000).fill("A".repeat(1000));
                return {size: bomb.length};
            } catch(e) {
                return {error: e.message, caught: true};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        
        # Should either handle gracefully or timeout
        assert "error" in result or "caught" in result
        # Token should never leak even in OOM conditions
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_infinite_promise_chain(self, sandbox):
        """Attack: Create an infinite promise chain that might bypass timeout detection.
        
        This tests whether async operations properly respect the timeout.
        """
        code = '''async () => {
            // Create a never-resolving promise chain
            const createChain = (depth) => {
                if (depth > 10000) {
                    return new Promise(() => {}); // Never resolves
                }
                return Promise.resolve().then(() => createChain(depth + 1));
            };
            
            await createChain(0);
            return {completed: true};
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        
        # Should fail with error (either timeout or "promise never resolved")
        assert "error" in result
        error_msg = result.get("error", "").lower()
        # Accept either timeout error or Deno's "promise never resolved" or "no valid json" (all indicate failure)
        assert ("timed out" in error_msg or 
                "timeout" in error_msg or 
                "promise never resolved" in result.get("stderr", "").lower() or
                "no valid json" in error_msg)
        
        # Token should never leak
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
