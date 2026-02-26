"""
Security red team tests - February 26, 2026 Morning Audit by Cheenu

New attack vectors:
1. Error.captureStackTrace manipulation to extract token from closure
2. Proxy trap on Response to intercept headers/body after fetch
3. Custom Symbol.hasInstance to probe for token presence
"""

import shutil
from pathlib import Path

import pytest

from mistmind.sandbox import DenoSandbox


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def deno_path():
    """Get path to Deno binary."""
    home = Path.home()
    deno_in_home = home / ".deno" / "bin" / "deno"
    
    if deno_in_home.exists():
        return str(deno_in_home)
    
    deno_in_path = shutil.which("deno")
    if deno_in_path:
        return deno_in_path
    
    pytest.skip("Deno not found")


@pytest.fixture
def sandbox(deno_path):
    """Create a Deno sandbox instance."""
    return DenoSandbox(deno_path=deno_path, timeout=5)


@pytest.mark.asyncio
class TestFeb26MorningCheenuAttacks:
    """Red team attacks attempting token extraction via advanced JS features."""
    
    async def test_attack_error_capturestacktrace_closure_leak(self, sandbox):
        """
        ATTACK: Use Error.captureStackTrace to capture stack from within closure.
        Try to inspect stack frames to find variables in parent scopes.
        
        DEFENSE: IIFE pattern ensures token is in closure scope.
        Error.captureStackTrace can capture stack but not access closure variables.
        Token will be scrubbed from any stack trace output.
        """
        code = """async () => {
            // Try to capture stack trace from within a function that might have access to token
            let capturedStack = null;
            try {
                // Override Error.captureStackTrace if available
                if (Error.captureStackTrace) {
                    const originalCapture = Error.captureStackTrace;
                    Error.captureStackTrace = function(targetObject, constructorOpt) {
                        // Capture the Error object to inspect later
                        capturedStack = targetObject;
                        return originalCapture.call(this, targetObject, constructorOpt);
                    };
                }
                
                // Trigger an error within mist.request to capture stack
                await mist.request({path: "/invalid/path/to/trigger/error"});
            } catch (e) {
                // Try to extract token from error or captured stack
                if (capturedStack) {
                    return {
                        message: "Captured stack",
                        stack: capturedStack.stack,
                        props: Object.getOwnPropertyNames(capturedStack)
                    };
                }
                return {message: e.message, stack: e.stack};
            }
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test_secret_token_12345",
            api_host="api.mist.com",
        )
        
        # Should NOT contain the actual token
        result_str = str(result)
        assert "test_secret_token_12345" not in result_str
        # The attack should fail with an error, not leak the token
        assert "error" in result or "message" in result or "stack" in result
    
    async def test_attack_response_proxy_intercept_headers(self, sandbox):
        """
        ATTACK: Create a Proxy around Response.prototype to intercept and log headers.
        Try to access Authorization header with token after fetch completes.
        
        DEFENSE: Deno's fetch implementation doesn't expose request headers in response.
        The token is in the request headers (Authorization), not response.
        """
        code = """async () => {
            let capturedHeaders = [];
            
            // Proxy Response.prototype.headers getter
            const originalHeadersDescriptor = Object.getOwnPropertyDescriptor(Response.prototype, 'headers');
            if (originalHeadersDescriptor) {
                Object.defineProperty(Response.prototype, 'headers', {
                    get: function() {
                        const headers = originalHeadersDescriptor.get.call(this);
                        // Try to capture headers
                        capturedHeaders.push({
                            url: this.url,
                            headers: Array.from(headers.entries())
                        });
                        return headers;
                    }
                });
            }
            
            // Make a request
            try {
                const result = await mist.request({path: "/api/v1/self"});
                return {
                    result: "success",
                    capturedHeaders: capturedHeaders
                };
            } catch (e) {
                return {
                    error: e.message,
                    capturedHeaders: capturedHeaders
                };
            }
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test_secret_token_67890",
            api_host="api.mist.com",
        )
        
        # Should NOT contain the actual token
        result_str = str(result)
        assert "test_secret_token_67890" not in result_str
        # Headers in Response are response headers, not request headers (no Authorization)
        # Token should not be leaked even if headers were captured
    
    async def test_attack_symbol_hasinstance_probe(self, sandbox):
        """
        ATTACK: Override Symbol.hasInstance on String/Object to detect when token is checked.
        Use custom instanceof behavior to probe for token presence.
        
        DEFENSE: Token comparison happens in Deno's native fetch (Rust code).
        User code cannot intercept native string operations on the token.
        """
        code = """async () => {
            let probeResults = [];
            
            // Override Symbol.hasInstance on String constructor
            const originalHasInstance = String[Symbol.hasInstance];
            String[Symbol.hasInstance] = function(instance) {
                probeResults.push({
                    type: "String.hasInstance",
                    value: String(instance).substring(0, 20) // Try to capture first 20 chars
                });
                return originalHasInstance.call(this, instance);
            };
            
            // Try to trigger instanceof checks
            try {
                const result = await mist.request({path: "/api/v1/self"});
                return {
                    result: "success", 
                    probeResults: probeResults
                };
            } catch (e) {
                return {
                    error: e.message,
                    probeResults: probeResults
                };
            }
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test_secret_probe_token",
            api_host="api.mist.com",
        )
        
        # Should NOT contain the actual token
        result_str = str(result)
        assert "test_secret_probe_token" not in result_str
        assert "[REDACTED]" in result_str or "error" in result


@pytest.mark.asyncio  
class TestResourceTimingAttacks:
    """Timing-based side channel attacks on network requests."""
    
    async def test_attack_performance_resource_timing_token_probe(self, sandbox):
        """
        ATTACK: Use PerformanceResourceTiming to measure timing differences.
        Try to infer token length or validity based on API response timing.
        
        DEFENSE: Timing information doesn't reveal the token itself.
        All timing measurements are post-authentication (token already used).
        """
        code = """async () => {
            let timings = [];
            
            // Measure timing for API request
            const start = performance.now();
            try {
                const result = await mist.request({path: "/api/v1/self"});
                const end = performance.now();
                timings.push({
                    endpoint: "/api/v1/self",
                    duration: end - start,
                    success: true
                });
            } catch (e) {
                const end = performance.now();
                timings.push({
                    endpoint: "/api/v1/self",
                    duration: end - start,
                    success: false,
                    error: e.message
                });
            }
            
            // Try to access PerformanceResourceTiming entries
            const entries = performance.getEntriesByType('resource');
            
            return {
                timings: timings,
                resourceEntries: entries.map(e => ({
                    name: e.name,
                    duration: e.duration,
                    transferSize: e.transferSize
                }))
            };
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test_timing_token_abc",
            api_host="api.mist.com",
        )
        
        # Timing data is allowed but should not reveal token
        result_str = str(result)
        assert "test_timing_token_abc" not in result_str
        # This is more of an information gathering attack than token leak


@pytest.mark.asyncio
class TestAdvancedCoercionAttacks:
    """Attacks using type coercion and conversion hooks."""
    
    async def test_attack_valueof_tostring_hijack_on_globalthis(self, sandbox):
        """
        ATTACK: Override valueOf/toString on globalThis to intercept coercions.
        Try to capture any value that gets coerced to string/primitive.
        
        DEFENSE: Token lives in IIFE closure, never assigned to global scope.
        Even if globalThis had valueOf/toString overrides, token won't trigger them.
        """
        code = """async () => {
            let coercionLog = [];
            
            // Override valueOf and toString on globalThis
            const originalValueOf = Object.prototype.valueOf;
            const originalToString = Object.prototype.toString;
            
            Object.prototype.valueOf = function() {
                coercionLog.push({
                    type: "valueOf",
                    this: String(this).substring(0, 30)
                });
                return originalValueOf.call(this);
            };
            
            Object.prototype.toString = function() {
                const result = originalToString.call(this);
                coercionLog.push({
                    type: "toString",
                    result: result
                });
                return result;
            };
            
            try {
                const result = await mist.request({path: "/api/v1/self"});
                return {
                    result: "success",
                    coercionLog: coercionLog
                };
            } catch (e) {
                return {
                    error: e.message,
                    coercionLog: coercionLog
                };
            }
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test_coercion_token_xyz",
            api_host="api.mist.com",
        )
        
        # Should NOT contain the actual token
        result_str = str(result)
        assert "test_coercion_token_xyz" not in result_str
        assert "[REDACTED]" in result_str or "error" in result
