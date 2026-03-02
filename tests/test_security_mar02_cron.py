"""Security audit for Mar 2, 2026 5AM cron - Advanced attack vectors."""

import pytest
from pathlib import Path
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


class TestMar02CronCheenuAttacks:
    """New red team attacks discovered during Mar 2 5AM audit."""
    
    @pytest.mark.asyncio
    async def test_attack_deno_core_api_access(self, sandbox):
        """
        ATTACK: Access Deno.core internals to bypass sandbox restrictions.
        
        Deno.core.opAsync and Deno.core.ops expose low-level operations.
        Try to use them to read process memory or bypass network restrictions.
        """
        code = """async () => {
            try {
                // Try to access Deno.core API
                if (typeof Deno.core !== 'undefined') {
                    const ops = Deno.core.ops;
                    const opNames = Object.keys(ops);
                    
                    // Try to read stdin again via core ops
                    if (ops.op_stdin_read) {
                        const buf = new Uint8Array(1024);
                        const n = await Deno.core.opAsync("op_stdin_read", buf);
                        return {leaked: "token via Deno.core", length: n};
                    }
                    
                    return {available_ops: opNames};
                }
                
                return {success: false, message: "Deno.core undefined"};
            } catch(e) {
                return {error: e.message};
            }
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com"
        )
        
        # Should NOT leak token or provide core API access
        assert SECRET_TOKEN not in str(result), "Token leaked via Deno.core!"
        assert "leaked" not in result, "Token leaked via core ops!"
        
        # Verify Deno.core is undefined or ops are restricted
        if "available_ops" in result:
            pytest.fail("Deno.core.ops exposed to user code - major security risk!")
    
    @pytest.mark.asyncio
    async def test_attack_object_prototype_poisoning_before_iife(self, sandbox):
        """
        ATTACK: Poison Object.prototype with getters that execute during IIFE.
        
        If we define Object.prototype.toString or Object.prototype.valueOf
        with side effects, they might execute when the IIFE processes the token.
        """
        code = """async () => {
            let captured = null;
            
            // Poison Object.prototype before mist object is accessed
            Object.defineProperty(Object.prototype, 'leaked_via_proto', {
                get() {
                    // This getter fires when any object is converted to string
                    const stack = new Error().stack;
                    if (stack && stack.includes('token') || stack.includes('Token')) {
                        captured = stack;
                    }
                    return 'poisoned';
                },
                configurable: true
            });
            
            // Now try to trigger the getter via mist operations
            try {
                const str = String(mist);
                const json = JSON.stringify(mist);
            } catch(e) {}
            
            // Clean up
            delete Object.prototype.leaked_via_proto;
            
            if (captured) {
                return {leaked: "via prototype pollution", stack: captured};
            }
            
            return {success: false};
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com"
        )
        
        # Should NOT leak token via prototype poisoning
        assert SECRET_TOKEN not in str(result), "Token leaked via prototype poisoning!"
        assert "leaked" not in result, "Prototype poisoning successful!"
    
    @pytest.mark.asyncio
    async def test_attack_dynamic_import_with_assertions_leak(self, sandbox):
        """
        ATTACK: Use dynamic import() with import assertions to probe for token.
        
        Import assertions might trigger different code paths that expose
        internal state or allow reading arbitrary modules.
        """
        code = """async () => {
            try {
                // Try to dynamically import stdin or process modules
                const imports = [
                    'data:text/javascript,export default Deno.stdin',
                    'data:text/javascript,export default globalThis',
                ];
                
                const results = [];
                for (const url of imports) {
                    try {
                        const mod = await import(url);
                        results.push({url, keys: Object.keys(mod.default || mod)});
                    } catch(e) {
                        results.push({url, error: e.message});
                    }
                }
                
                return {import_results: results};
            } catch(e) {
                return {error: e.message};
            }
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com"
        )
        
        # Should NOT leak token via dynamic imports
        assert SECRET_TOKEN not in str(result), "Token leaked via dynamic import!"
        
        # Dynamic imports to stdin/globalThis should be blocked or sanitized
        if "import_results" in result:
            for item in result["import_results"]:
                if "keys" in item:
                    # Should not reveal sensitive keys
                    assert "_token" not in str(item["keys"]), "Token variable exposed!"


class TestDenoPermissionsExfiltration:
    """Test if we can leak information via Deno permissions API."""
    
    @pytest.mark.asyncio
    async def test_attack_permissions_query_timing_oracle(self, sandbox):
        """
        ATTACK: Use Deno.permissions.query timing to infer network allowlist.
        
        If permission checks take different amounts of time for allowed
        vs denied hosts, we can infer the allowlist and potentially
        discover internal network topology.
        """
        code = """async () => {
            const hosts = [
                'api.mist.com',
                'evil.com',
                'internal.mist.com',
                'localhost'
            ];
            
            const timings = [];
            
            for (const host of hosts) {
                try {
                    const start = performance.now();
                    
                    // Query if we have permission to access this host
                    const status = await Deno.permissions.query({
                        name: 'net',
                        host: host
                    });
                    
                    const duration = performance.now() - start;
                    
                    timings.push({
                        host,
                        granted: status.state === 'granted',
                        duration_ms: duration
                    });
                } catch(e) {
                    timings.push({host, error: e.message});
                }
            }
            
            return {permission_timings: timings};
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com"
        )
        
        # Even if we can query permissions, timing should not leak allowlist
        if "permission_timings" in result:
            # This is informational - Deno.permissions might be accessible
            # but shouldn't leak the token
            assert SECRET_TOKEN not in str(result), "Token in permissions response!"


class TestMemoryForensicsV3:
    """Advanced memory inspection techniques."""
    
    @pytest.mark.asyncio
    async def test_attack_webassembly_linear_memory_scan(self, sandbox):
        """
        ATTACK: Use WebAssembly linear memory to scan for token in heap.
        
        WASM memory is a raw ArrayBuffer. If we allocate enough WASM memory,
        we might be able to scan adjacent heap regions for the token string.
        """
        code = """async () => {
            try {
                // Create a WASM module with large linear memory
                const wasmCode = new Uint8Array([
                    0x00, 0x61, 0x73, 0x6d, // WASM magic
                    0x01, 0x00, 0x00, 0x00, // version 1
                    0x05,                   // memory section
                    0x03,                   // section size
                    0x01,                   // 1 memory
                    0x00, 0x10              // min 16 pages (1MB)
                ]);
                
                const module = await WebAssembly.compile(wasmCode);
                const instance = await WebAssembly.instantiate(module);
                
                // Access linear memory
                const memory = instance.exports.memory || 
                              (instance.exports.mem ? instance.exports.mem : null);
                
                if (memory && memory.buffer) {
                    const buf = new Uint8Array(memory.buffer);
                    
                    // Scan for ASCII patterns that look like tokens
                    const patterns = [];
                    for (let i = 0; i < Math.min(buf.length, 10000); i++) {
                        if (buf[i] >= 32 && buf[i] < 127) {
                            // Found ASCII character
                            let str = '';
                            let j = i;
                            while (j < buf.length && buf[j] >= 32 && buf[j] < 127 && str.length < 50) {
                                str += String.fromCharCode(buf[j]);
                                j++;
                            }
                            if (str.length > 10) {
                                patterns.push(str.substring(0, 30));
                                i = j;
                            }
                        }
                    }
                    
                    return {
                        wasm_memory_scanned: true,
                        patterns_found: patterns.slice(0, 5)
                    };
                }
                
                return {wasm_memory: "no memory export"};
            } catch(e) {
                return {error: e.message};
            }
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com"
        )
        
        # Should NOT find token in WASM linear memory
        assert SECRET_TOKEN not in str(result), "Token found in WASM memory scan!"
        
        if "patterns_found" in result:
            for pattern in result["patterns_found"]:
                # Partial match detection
                for i in range(len(SECRET_TOKEN) - 3):
                    substr = SECRET_TOKEN[i:i+4]
                    assert substr not in pattern, f"Token substring '{substr}' found in WASM memory!"
