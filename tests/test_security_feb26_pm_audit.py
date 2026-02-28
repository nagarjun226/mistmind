"""Red Team security audit - Feb 26, 2026 1:51 PM - Cheenu's new attack vectors."""

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
    """Create a Deno sandbox with readwrite mode for execute tests."""
    return DenoSandbox(deno_path=deno_path, timeout=5, api_mode="readwrite")


SECRET_TOKEN = "super-secret-api-token-12345"


class TestFeb26PMCheenuAttacks:
    """New attack vectors from Feb 26 PM audit by Cheenu."""
    
    @pytest.mark.asyncio
    async def test_attack_fetch_response_stream_chunk_leak(self, sandbox):
        """
        ATTACK: Try to leak Authorization header by reading response stream chunks.
        
        Strategy: Instead of resp.json(), read response body.getReader() chunk by chunk
        and try to leak headers through the stream or Response object inspection.
        """
        code = '''async () => {
            // Try to capture Response object before parsing JSON
            const resp = await mist.request({
                method: "GET", 
                path: "/api/v1/self"
            });
            
            // Attempt 1: Try to access headers from return value
            // (mist.request returns parsed JSON, not Response object)
            const attempt1 = {
                hasHeaders: typeof resp?.headers !== 'undefined',
                constructor: resp?.constructor?.name
            };
            
            // Attempt 2: Try to intercept fetch and capture Response
            const originalFetch = globalThis.fetch;
            let capturedResponse = null;
            globalThis.fetch = async (...args) => {
                const response = await originalFetch(...args);
                capturedResponse = response;
                return response;
            };
            
            // Make another request
            await mist.request({method: "GET", path: "/api/v1/self"});
            
            // Try to read headers from captured Response
            const attempt2 = {
                hasCapturedResponse: capturedResponse !== null,
                headers: capturedResponse ? Object.fromEntries(capturedResponse.headers) : null
            };
            
            return {attempt1, attempt2};
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # EXPECT: Token should NOT appear in any form
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via fetch response stream inspection!"
        assert "Authorization" not in result_str, "Authorization header leaked!"
        
    @pytest.mark.asyncio
    async def test_attack_deno_permissions_query_fingerprint(self, sandbox):
        """
        ATTACK: Use Deno.permissions.query() to fingerprint sandbox configuration.
        
        Strategy: Query which permissions are granted/denied to understand the
        security boundary and find potential weak points.
        """
        code = '''async () => {
            const permissions = {};
            
            // Try to query various permissions
            const permsToCheck = [
                'read', 'write', 'net', 'env', 'run', 
                'ffi', 'hrtime', 'sys'
            ];
            
            for (const perm of permsToCheck) {
                try {
                    const status = await Deno.permissions.query({name: perm});
                    permissions[perm] = {
                        state: status.state,
                        onchange: status.onchange !== null
                    };
                } catch (e) {
                    permissions[perm] = {error: e.message};
                }
            }
            
            // Try specific net permission query for api.mist.com
            try {
                const netStatus = await Deno.permissions.query({
                    name: 'net',
                    host: 'api.mist.com'
                });
                permissions.net_mist = netStatus.state;
            } catch (e) {
                permissions.net_mist = {error: e.message};
            }
            
            return permissions;
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # EXPECT: Permission queries should either be denied or not reveal sensitive info
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via permissions query!"
        
        # Permissions API might work but shouldn't leak token
        # The attack succeeds in fingerprinting but that's informational, not a security breach
        
    @pytest.mark.asyncio
    async def test_attack_symbol_for_global_registry_persistence(self, sandbox):
        """
        ATTACK: Use Symbol.for() to persist data across executions.
        
        Strategy: Symbol.for() creates symbols in a global registry that might
        persist across Deno subprocess calls. Try to leak token by storing it
        in a Symbol.for() and retrieving in a second execution.
        """
        # First execution: try to store token in Symbol.for()
        code1 = '''async () => {
            // Try to access token from various sources
            const sources = {
                globalThis_keys: Object.keys(globalThis).filter(k => k.includes('token')),
                symbol_registry_attempt: (() => {
                    try {
                        // Try to store a marker in Symbol.for()
                        const marker = Symbol.for('__mistmind_token_leak__');
                        globalThis[marker] = 'first_execution_marker';
                        return 'stored';
                    } catch (e) {
                        return e.message;
                    }
                })()
            };
            
            return sources;
        }'''
        
        result1 = await sandbox.run_execute(
            code=code1,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # Second execution: try to retrieve stored data
        code2 = '''async () => {
            try {
                const marker = Symbol.for('__mistmind_token_leak__');
                const retrieved = globalThis[marker];
                
                return {
                    marker_found: retrieved !== undefined,
                    marker_value: retrieved,
                    symbol_type: typeof marker
                };
            } catch (e) {
                return {error: e.message};
            }
        }'''
        
        result2 = await sandbox.run_execute(
            code=code2,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # EXPECT: Symbol.for() registry should NOT persist across executions
        # (each Deno subprocess is isolated)
        result2_str = str(result2)
        assert SECRET_TOKEN not in result2_str, "Token leaked via Symbol.for()!"
        
        # Also check that marker didn't persist
        if 'marker_value' in result2_str:
            assert result2.get('marker_value') != 'first_execution_marker', \
                "Data persisted across executions via Symbol.for()!"


class TestDenoSubprocessIsolation:
    """Verify that each Deno execution is truly isolated."""
    
    @pytest.mark.asyncio
    async def test_attack_globalthis_pollution_persistence(self, sandbox):
        """
        ATTACK: Try to pollute globalThis and see if it persists.
        
        Strategy: Modify globalThis in one execution and check if the
        modification persists in the next execution.
        """
        # First execution: pollute globalThis
        code1 = '''async () => {
            globalThis.__mistmind_pollution__ = 'leaked_data';
            globalThis.Array.prototype.leak = function() { return 'polluted'; };
            
            return {
                pollution_set: true,
                test_leak: [].leak ? [].leak() : 'not_polluted'
            };
        }'''
        
        result1 = await sandbox.run_execute(
            code=code1,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # Second execution: check if pollution persists
        code2 = '''async () => {
            return {
                pollution_exists: typeof globalThis.__mistmind_pollution__ !== 'undefined',
                pollution_value: globalThis.__mistmind_pollution__,
                array_polluted: typeof [].leak !== 'undefined'
            };
        }'''
        
        result2 = await sandbox.run_execute(
            code=code2,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # EXPECT: Pollution should NOT persist (fresh Deno process each time)
        assert result2.get('pollution_exists') is False, "globalThis pollution persisted!"
        assert result2.get('array_polluted') is False, "Prototype pollution persisted!"


class TestResponseObjectLeakage:
    """Test potential leaks through Response object manipulation."""
    
    @pytest.mark.asyncio
    async def test_attack_response_clone_infinite_reads(self, sandbox):
        """
        ATTACK: Clone Response object multiple times and try to leak via clone inspection.
        
        Strategy: Response.clone() creates independent readable streams. Try to
        intercept and read headers/body from cloned responses.
        """
        code = '''async () => {
            // Intercept fetch to capture Response before it's consumed
            let capturedResponses = [];
            const originalFetch = globalThis.fetch;
            
            globalThis.fetch = async (...args) => {
                const response = await originalFetch(...args);
                // Try to clone before returning
                try {
                    const clone1 = response.clone();
                    const clone2 = response.clone();
                    capturedResponses.push({
                        url: response.url,
                        status: response.status,
                        headers: Array.from(response.headers.entries()),
                        clone1_headers: Array.from(clone1.headers.entries()),
                        clone2_headers: Array.from(clone2.headers.entries())
                    });
                } catch (e) {
                    capturedResponses.push({error: e.message});
                }
                return response;
            };
            
            // Make request
            await mist.request({method: "GET", path: "/api/v1/self"});
            
            return {captured: capturedResponses};
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # EXPECT: Token should be scrubbed even if headers are captured
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via Response.clone()!"
        
        # Check if Authorization header is present but redacted
        if 'headers' in result_str:
            # Header might be visible but value should be scrubbed
            assert '[REDACTED]' in result_str or SECRET_TOKEN not in result_str, \
                "Token not properly scrubbed in captured headers!"
