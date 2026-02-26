"""Red Team Security Audit - Feb 26 Cron Run - New Attack Vectors."""

import asyncio
from pathlib import Path
import pytest

from mistmind.sandbox import DenoSandbox


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
    return DenoSandbox(deno_path=deno_path, timeout=5, api_mode="all")


SECRET_TOKEN = "super-secret-api-token-12345"


class TestFetchResponseHeaderInspection:
    """Test if we can extract token from Response headers after fetch."""
    
    @pytest.mark.asyncio
    async def test_attack_response_headers_request_inspection(self, sandbox):
        """Try to inspect the Request object's headers from Response."""
        code = """async () => {
            // Attempt to inspect request headers from response
            try {
                const resp = await mist.request({path: "/api/v1/self"});
                return {error: "Should have failed - no mock server"};
            } catch (e) {
                // In a real scenario, try to extract from error context
                // Check if error message leaks authorization
                return {
                    caught: e.message,
                    constructor: e.constructor.name,
                    hasAuth: e.message.includes("Token") || e.message.includes("Authorization")
                };
            }
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # Token should NOT appear in any output
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked in response header inspection"
        assert "[REDACTED]" in result_str or "caught" in result, "Should handle gracefully"
    
    @pytest.mark.asyncio
    async def test_attack_response_clone_header_leak(self, sandbox):
        """Try to clone a Response and extract headers."""
        code = """async () => {
            // Create a mock Response with Authorization header
            const mockResp = new Response('{"test": true}', {
                headers: {
                    'Authorization': 'Token should-not-see-real-token',
                    'Content-Type': 'application/json'
                }
            });
            
            const cloned = mockResp.clone();
            const authHeader = cloned.headers.get('Authorization');
            
            // Try to leak via return
            return {authHeader: authHeader};
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # Real token should never appear
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked in cloned response"


class TestStackTraceClosureAdvanced:
    """Advanced stack trace manipulation attacks."""
    
    @pytest.mark.asyncio
    async def test_attack_error_prepareStackTrace_during_iife(self, sandbox):
        """Try to hijack Error.prepareStackTrace during IIFE execution."""
        code = """async () => {
            // Install prepareStackTrace hook BEFORE any mist calls
            let captured = [];
            Error.prepareStackTrace = (err, stack) => {
                captured.push({
                    err: err.message,
                    stack: stack.map(s => ({
                        func: s.getFunctionName(),
                        file: s.getFileName(),
                        line: s.getLineNumber()
                    }))
                });
                return "hooked";
            };
            
            // Now trigger an error
            try {
                throw new Error("probe");
            } catch(e) {
                const _ = e.stack; // Force stack trace preparation
            }
            
            return {captured: captured, capturedCount: captured.length};
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via prepareStackTrace hook"
        assert "captured" in result or "error" in result, "Should execute without token leak"
    
    @pytest.mark.asyncio
    async def test_attack_async_stack_trace_capture(self, sandbox):
        """Try to capture async stack traces that might include closure context."""
        code = """async () => {
            const traces = [];
            
            // Override Error constructor to capture all errors
            const OrigError = Error;
            globalThis.Error = function(...args) {
                const err = new OrigError(...args);
                traces.push({
                    message: err.message,
                    stack: err.stack
                });
                return err;
            };
            
            // Trigger some errors in mist.request context
            try {
                await mist.request({method: "INVALID_METHOD", path: "/test"});
            } catch(e) {
                // Ignore
            }
            
            return {
                tracesCount: traces.length,
                firstTrace: traces[0] || null
            };
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via async stack trace"


class TestConcurrentRaceConditions:
    """Test race conditions in concurrent request handling."""
    
    @pytest.mark.asyncio
    async def test_attack_parallel_requests_scrubbing_race(self, sandbox):
        """Fire many parallel requests to test if scrubbing has race conditions."""
        code = """async () => {
            const promises = [];
            
            // Fire 20 concurrent requests
            for (let i = 0; i < 20; i++) {
                promises.push(
                    mist.request({path: "/api/v1/self"})
                        .catch(e => ({error: e.message, index: i}))
                );
            }
            
            const results = await Promise.all(promises);
            
            // Check if any result contains anything suspicious
            const suspicious = results.filter(r => 
                JSON.stringify(r).toLowerCase().includes('token') ||
                JSON.stringify(r).toLowerCase().includes('auth')
            );
            
            return {
                totalResults: results.length,
                suspiciousCount: suspicious.length,
                firstResult: results[0]
            };
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked in parallel request race"
        assert "[REDACTED]" in result_str or "error" in result or "totalResults" in result
    
    @pytest.mark.asyncio
    async def test_attack_promise_allSettled_timeout_race(self, sandbox):
        """Use Promise.allSettled with timeouts to create race conditions."""
        code = """async () => {
            const promises = [];
            
            // Create promises with varying delays
            for (let i = 0; i < 10; i++) {
                promises.push(
                    new Promise((resolve) => {
                        setTimeout(() => {
                            // Try to access mist in a race condition
                            try {
                                resolve({
                                    index: i,
                                    mistType: typeof mist,
                                    mistKeys: Object.keys(mist || {})
                                });
                            } catch(e) {
                                resolve({error: e.message});
                            }
                        }, i * 10);
                    })
                );
            }
            
            const results = await Promise.allSettled(promises);
            return {
                resultsCount: results.length,
                firstFulfilled: results.find(r => r.status === 'fulfilled')?.value
            };
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked in allSettled race"


class TestMemoryPressureAttacks:
    """Test memory-based attacks to try to expose token."""
    
    @pytest.mark.asyncio
    async def test_attack_arraybuffer_memory_fill(self, sandbox):
        """Fill memory with ArrayBuffers and try to trigger GC to expose token."""
        code = """async () => {
            const buffers = [];
            
            // Allocate many small buffers (within V8 limit)
            for (let i = 0; i < 100; i++) {
                buffers.push(new ArrayBuffer(1024 * 100)); // 100KB each = 10MB total
            }
            
            // Force some GC hints
            buffers.length = 0;
            
            // Now try to access mist
            return {
                mistType: typeof mist,
                allowedMethods: mist.allowedMethods
            };
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via memory pressure"
        assert "mistType" in result or "error" in result
    
    @pytest.mark.asyncio
    async def test_attack_typed_array_view_token_search(self, sandbox):
        """Create typed array views and try to search memory for token patterns."""
        code = """async () => {
            // Create a large buffer and view it as Uint8Array
            const buffer = new ArrayBuffer(1024 * 256); // 256KB
            const view = new Uint8Array(buffer);
            
            // Fill with pattern
            for (let i = 0; i < view.length; i++) {
                view[i] = i % 256;
            }
            
            // Try to detect token-like patterns (just testing the concept)
            const searchResults = [];
            for (let i = 0; i < view.length - 10; i++) {
                // Look for ASCII 'T', 'o', 'k', 'e', 'n' pattern
                if (view[i] === 84 && view[i+1] === 111 && view[i+2] === 107) {
                    searchResults.push(i);
                }
            }
            
            return {
                bufferSize: view.length,
                patternsFound: searchResults.length,
                mistWorks: typeof mist.request === 'function'
            };
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via typed array memory search"
