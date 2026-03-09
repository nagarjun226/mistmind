"""Security tests for Mar 09 2026 red team audit - NEW ATTACK VECTORS."""

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


class TestMar09CronCheenuAttacks:
    """Novel attack vectors discovered during March 9, 2026 audit."""
    
    @pytest.mark.asyncio
    async def test_attack_json_import_timing_side_channel(self, deno_path):
        """
        ATTACK: Use performance.measure() to time the JSON import of the spec file.
        The import timing correlates with spec file size and might leak information
        about which spec is loaded (obfuscated vs real, or different API versions).
        
        DEFENSE: This is a side-channel but doesn't leak the token. The spec is
        intentionally accessible to user code. Timing variations are acceptable.
        """
        from mistmind.sandbox import DenoSandbox
        
        sandbox = DenoSandbox(deno_path=deno_path)
        
        code = """async () => {
            // Try to measure import timing to fingerprint which spec is loaded
            const measurements = [];
            for (let i = 0; i < 3; i++) {
                const start = performance.now();
                // Force spec access
                const pathCount = Object.keys(spec.paths).length;
                const end = performance.now();
                measurements.push({
                    iteration: i,
                    pathCount,
                    durationMs: end - start
                });
            }
            return measurements;
        }"""
        
        result = await sandbox.run_search(
            code=code,
            spec_path="spec/mist.resolved.json"
        )
        
        # Should succeed - timing info doesn't leak the token
        assert "error" not in result
        assert isinstance(result, list)
        assert len(result) == 3
        assert all("durationMs" in m for m in result)
    
    @pytest.mark.asyncio
    async def test_attack_async_generator_state_machine_probe(self, deno_path):
        """
        ATTACK: Use an async generator to probe the state machine of the IIFE
        during its execution. Try to yield control back and forth to capture
        references to _token before the closure is sealed.
        
        DEFENSE: The IIFE pattern ensures _token is in closure scope before
        user code begins execution. The state machine is sealed.
        """
        from mistmind.sandbox import DenoSandbox
        
        sandbox = DenoSandbox(deno_path=deno_path)
        
        code = """async () => {
            // Try to use async generator to interleave with IIFE execution
            async function* probe() {
                // Attempt to access _token during generator execution
                try {
                    // Check if _token exists in any accessible scope
                    if (typeof _token !== 'undefined') {
                        yield {leaked: true, token: _token};
                    }
                } catch (e) {
                    yield {leaked: false, error: e.message};
                }
                
                // Try to access via globalThis
                for (const key of Object.keys(globalThis)) {
                    if (key.includes('token') || key.startsWith('_')) {
                        yield {suspicious: key, value: globalThis[key]};
                    }
                }
                
                // Try to enumerate mist object internals
                const mistKeys = Object.keys(mist);
                const mistSymbols = Object.getOwnPropertySymbols(mist);
                yield {mistKeys, mistSymbols: mistSymbols.map(s => s.toString())};
            }
            
            const probes = [];
            for await (const result of probe()) {
                probes.push(result);
            }
            return probes;
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test_secret_token_12345",
            api_host="api.mist.com"
        )
        
        # Should not leak token
        result_str = json.dumps(result)
        assert "test_secret_token_12345" not in result_str
        assert "[REDACTED]" not in result_str or "error" in result
    
    @pytest.mark.asyncio
    async def test_attack_object_hasown_proxy_trap_bypass(self, deno_path):
        """
        ATTACK: Use Object.hasOwn() (ES2022) combined with Proxy trap to try to
        bypass frozen object checks. Object.hasOwn is distinct from 'in' operator
        and might expose internal slots.
        
        DEFENSE: Object.freeze() prevents all modifications regardless of how
        properties are checked. hasOwn only checks own properties, not internal slots.
        """
        from mistmind.sandbox import DenoSandbox
        
        sandbox = DenoSandbox(deno_path=deno_path)
        
        code = """async () => {
            const results = [];
            
            // Try to use Object.hasOwn to probe mist internals
            const hasToken = Object.hasOwn(mist, '_token');
            const hasApiToken = Object.hasOwn(mist, 'apiToken');
            const hasAuth = Object.hasOwn(mist, 'auth');
            
            results.push({
                hasToken,
                hasApiToken,
                hasAuth,
                mistType: typeof mist
            });
            
            // Try to create a Proxy handler that intercepts hasOwn
            let capturedKeys = [];
            try {
                const handler = {
                    has(target, key) {
                        capturedKeys.push(key);
                        return Reflect.has(target, key);
                    },
                    getOwnPropertyDescriptor(target, key) {
                        capturedKeys.push(`desc:${String(key)}`);
                        return Reflect.getOwnPropertyDescriptor(target, key);
                    }
                };
                
                const proxiedMist = new Proxy(mist, handler);
                
                // Try various property checks
                'request' in proxiedMist;
                'allowedMethods' in proxiedMist;
                '_token' in proxiedMist;
                
                Object.hasOwn(proxiedMist, 'request');
                Object.hasOwn(proxiedMist, '_token');
                
            } catch (e) {
                results.push({proxyError: e.message});
            }
            
            results.push({capturedKeys});
            
            return results;
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test_secret_token_67890",
            api_host="api.mist.com"
        )
        
        # Should not leak token
        result_str = json.dumps(result)
        assert "test_secret_token_67890" not in result_str
        assert "[REDACTED]" not in result_str or "error" in result


class TestIteratorHelpersExploitation:
    """Test attacks using ES2023 Iterator Helper methods."""
    
    @pytest.mark.asyncio
    async def test_attack_iterator_helpers_internal_state_leak(self, deno_path):
        """
        ATTACK: Use Iterator Helper methods (.map(), .filter(), .take(), .drop())
        to try to expose internal state or references during iteration.
        
        DEFENSE: Even if iterator helpers exist in Deno, they operate on values,
        not references to internal closures. The token remains inaccessible.
        """
        from mistmind.sandbox import DenoSandbox
        
        sandbox = DenoSandbox(deno_path=deno_path)
        
        code = """async () => {
            const results = [];
            
            // Check if iterator helpers are available
            const hasIteratorHelpers = typeof Iterator !== 'undefined' &&
                                      typeof Iterator.prototype?.map === 'function';
            
            results.push({hasIteratorHelpers});
            
            if (hasIteratorHelpers) {
                // Try to use iterator helpers to probe object internals
                try {
                    const keys = Object.keys(globalThis);
                    const iterator = keys[Symbol.iterator]();
                    
                    // Try to map over iterator and capture state
                    const mapped = iterator.map(key => {
                        try {
                            const value = globalThis[key];
                            if (typeof value === 'string' && value.length > 10) {
                                return {key, preview: value.substring(0, 20)};
                            }
                        } catch (e) {
                            return {key, error: e.message};
                        }
                        return null;
                    });
                    
                    const captured = Array.from(mapped).filter(x => x !== null);
                    results.push({captured});
                    
                } catch (e) {
                    results.push({iteratorError: e.message});
                }
            }
            
            return results;
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test_secret_token_iterator_99",
            api_host="api.mist.com"
        )
        
        # Should not leak token
        result_str = json.dumps(result)
        assert "test_secret_token_iterator_99" not in result_str
        assert "[REDACTED]" not in result_str or "error" in result


class TestModuleNamespaceExoticObjects:
    """Test attacks using module namespace exotic objects."""
    
    @pytest.mark.asyncio
    async def test_attack_import_meta_url_manipulation(self, deno_path):
        """
        ATTACK: Try to manipulate import.meta.url to load spec from a different
        location or leak filesystem information.
        
        DEFENSE: Deno permissions restrict file access. Even if import.meta is
        accessible, it can't bypass --allow-read restrictions.
        """
        from mistmind.sandbox import DenoSandbox
        
        sandbox = DenoSandbox(deno_path=deno_path)
        
        code = """async () => {
            const results = [];
            
            // Try to access import.meta
            try {
                // import.meta is only available in module context
                // This code runs in eval context via stdin, so it should fail
                const meta = import.meta;
                results.push({
                    hasImportMeta: true,
                    url: meta?.url,
                    main: meta?.main
                });
            } catch (e) {
                results.push({
                    hasImportMeta: false,
                    error: e.message
                });
            }
            
            // Try to probe spec import
            try {
                // The spec is imported with: import spec from "file://..." with { type: "json" }
                // Try to re-import it with different URL
                const specKeys = Object.keys(spec);
                results.push({
                    specAccessible: true,
                    topLevelKeys: specKeys.slice(0, 5)
                });
            } catch (e) {
                results.push({
                    specError: e.message
                });
            }
            
            return results;
        }"""
        
        result = await sandbox.run_search(
            code=code,
            spec_path="spec/mist.resolved.json"
        )
        
        # Should succeed - spec is intentionally accessible
        assert "error" not in result or result.get("error", "").startswith("No valid JSON")
        # Should not leak sensitive paths
        result_str = json.dumps(result)
        assert "/Users/" not in result_str  # No absolute paths leaked
