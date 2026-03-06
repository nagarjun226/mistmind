"""Security tests for Mar 6 2026 Red Team Audit - New Attack Vectors."""

import asyncio
import pytest
from pathlib import Path

from mistmind.sandbox import DenoSandbox


# Secret token used in all tests
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


class TestMar06CronCheenuAttacks:
    """New attack vectors discovered during Mar 6 audit."""
    
    @pytest.mark.asyncio
    async def test_attack_deno_cache_poisoning_attempt(self, sandbox):
        """
        ATTACK: Attempt to poison Deno's HTTP cache with malicious responses
        that could be served to future requests.
        
        VECTOR: Try to cache a response with the token in headers, then
        retrieve it via cache inspection.
        
        MITIGATION: Deno's --deny-net prevents network access in search mode,
        and allowed hosts restrict execute mode. Cache poisoning requires
        write access to cache directory (denied).
        """
        code = """async () => {
            // Try to access Deno's cache directory
            try {
                const cacheDir = Deno.env.get("DENO_DIR") || 
                    (Deno.build.os === "darwin" 
                        ? Deno.env.get("HOME") + "/Library/Caches/deno"
                        : Deno.env.get("HOME") + "/.cache/deno");
                
                // Attempt to read cache
                const files = [];
                for await (const entry of Deno.readDir(cacheDir)) {
                    files.push(entry.name);
                }
                
                return { attack: "cache_poisoning", files };
            } catch (e) {
                return { error: e.message, blocked: true };
            }
        }"""
        
        # Run in search mode (no API token)
        result = await sandbox.run_search(
            code,
            spec_path="spec/mist.resolved.json"
        )
        
        # Should be blocked by --deny-env and --deny-read
        assert "error" in result
        assert "blocked" not in result or result.get("blocked") == True
        
        # Token should never appear
        result_str = str(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_concurrent_stdin_race_token_double_read(self, sandbox):
        """
        ATTACK: Launch multiple concurrent stdin reads to race-condition
        the token read and potentially read it multiple times or leak it
        into a shared buffer.
        
        VECTOR: Spawn multiple promises that all try to read stdin, hoping
        one completes before the IIFE closure locks the token.
        
        MITIGATION: Stdin is read once in the IIFE before user code runs.
        Subsequent reads will get EOF. Token is in closure scope only.
        """
        code = """async () => {
            const attempts = [];
            
            // Try to read stdin multiple times concurrently
            for (let i = 0; i < 10; i++) {
                attempts.push(
                    (async () => {
                        try {
                            const reader = Deno.stdin.readable.getReader();
                            const chunks = [];
                            while (true) {
                                const {done, value} = await reader.read();
                                if (done) break;
                                chunks.push(value);
                            }
                            reader.releaseLock();
                            
                            const text = new TextDecoder().decode(
                                new Uint8Array(chunks.flat())
                            );
                            return {attempt: i, success: true, length: text.length};
                        } catch (e) {
                            return {attempt: i, error: e.message};
                        }
                    })()
                );
            }
            
            const results = await Promise.allSettled(attempts);
            return {
                attack: "concurrent_stdin_race",
                results: results.map(r => r.value || r.reason)
            };
        }"""
        
        result = await sandbox.run_execute(
            code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com"
        )
        
        # All concurrent reads should fail or get EOF since token was consumed
        # No attempt should successfully read the token
        assert "error" in result or "results" in result
        
        # Token must be scrubbed from output
        result_str = str(result)
        assert SECRET_TOKEN not in result_str
        assert "[REDACTED]" not in result_str or "error" in result
    
    @pytest.mark.asyncio
    async def test_attack_v8_heap_snapshot_serialization(self, sandbox):
        """
        ATTACK: Use V8's heap snapshot API to serialize all objects in memory,
        then search the serialized snapshot for the token string.
        
        VECTOR: Deno exposes some V8 internals. Try to trigger a heap snapshot
        or serialize all objects to find the token in memory.
        
        MITIGATION: Deno's v8 module is not exposed in the sandbox (no --unstable).
        Even if exposed, token is in IIFE closure and should not be enumerable.
        """
        code = """async () => {
            try {
                // Attempt to access V8 internals
                const v8 = globalThis.Deno?.core?.ops || globalThis.v8 || null;
                
                if (v8) {
                    // Try to serialize heap
                    const snapshot = v8.writeHeapSnapshot?.() || 
                                   v8.heapSnapshot?.() ||
                                   "V8 API not accessible";
                    return { attack: "heap_snapshot", snapshot };
                }
                
                // Try alternative: serialize all reachable objects
                const seen = new WeakSet();
                const serialized = [];
                
                function traverse(obj, depth = 0) {
                    if (depth > 5 || !obj || typeof obj !== 'object') return;
                    if (seen.has(obj)) return;
                    seen.add(obj);
                    
                    try {
                        serialized.push({
                            type: obj.constructor?.name,
                            keys: Object.keys(obj),
                            ownKeys: Reflect.ownKeys(obj).map(String)
                        });
                        
                        for (const key of Object.keys(obj)) {
                            traverse(obj[key], depth + 1);
                        }
                    } catch {}
                }
                
                // Traverse from globalThis
                traverse(globalThis);
                traverse(Error.prototype);
                traverse(Function.prototype);
                
                return { 
                    attack: "heap_serialization", 
                    objects: serialized.length,
                    sample: serialized.slice(0, 5)
                };
                
            } catch (e) {
                return { error: e.message, blocked: true };
            }
        }"""
        
        result = await sandbox.run_execute(
            code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com"
        )
        
        # Should either fail or not find the token
        result_str = str(result)
        assert SECRET_TOKEN not in result_str
        
        # If successful, verify no token in serialized data
        if "objects" in result:
            assert SECRET_TOKEN not in result_str


class TestDenoModuleResolutionSideChannel:
    """Test if module resolution can leak filesystem information."""
    
    @pytest.mark.asyncio
    async def test_attack_import_probe_filesystem_structure(self, sandbox):
        """
        ATTACK: Use dynamic import errors to probe filesystem structure
        and potentially discover location of temp files with tokens.
        
        VECTOR: Attempt imports of various paths and measure timing/error
        messages to infer filesystem layout.
        
        MITIGATION: --deny-read restricts file access. Import errors should
        not leak sensitive paths, and timing should not reveal file existence.
        """
        code = """async () => {
            const probes = [
                "/tmp/",
                "/tmp/deno-",
                "/etc/passwd",
                "/proc/self/environ",
                "file:///tmp/",
            ];
            
            const results = [];
            
            for (const path of probes) {
                const start = performance.now();
                try {
                    await import(path);
                    results.push({ 
                        path, 
                        status: "success",
                        time: performance.now() - start
                    });
                } catch (e) {
                    results.push({ 
                        path, 
                        error: e.message.substring(0, 100),
                        time: performance.now() - start
                    });
                }
            }
            
            return { attack: "import_probe", results };
        }"""
        
        result = await sandbox.run_search(
            code,
            spec_path="spec/mist.resolved.json"
        )
        
        # All imports should fail due to --deny-read
        assert "error" in result or "results" in result
        
        # Should not reveal sensitive paths
        result_str = str(result)
        assert "/tmp/mistmind" not in result_str
        assert ".js" not in result_str or "error" in result


class TestProcessSignalManipulation:
    """Test if user code can interfere with process signal handling."""
    
    @pytest.mark.asyncio
    async def test_attack_override_signal_handlers(self, sandbox):
        """
        ATTACK: Override Deno's signal handlers to prevent SIGTERM/SIGKILL
        from terminating the process on timeout.
        
        VECTOR: Set up signal handlers that ignore TERM signals, potentially
        allowing the process to continue running past timeout and leak data.
        
        MITIGATION: SIGKILL cannot be caught. Python sends SIGTERM first,
        then SIGKILL after 0.5s. User code cannot prevent SIGKILL.
        """
        code = """async () => {
            try {
                // Try to install signal handlers
                if (Deno.addSignalListener) {
                    Deno.addSignalListener("SIGTERM", () => {
                        console.log("SIGTERM ignored");
                    });
                    
                    Deno.addSignalListener("SIGINT", () => {
                        console.log("SIGINT ignored");
                    });
                }
                
                // Try to run forever
                let counter = 0;
                while (true) {
                    counter++;
                    await new Promise(resolve => setTimeout(resolve, 100));
                    if (counter > 100) break;  // Safety limit
                }
                
                return { attack: "signal_override", ran: counter };
            } catch (e) {
                return { error: e.message, blocked: true };
            }
        }"""
        
        result = await sandbox.run_search(
            code,
            spec_path="spec/mist.resolved.json"
        )
        
        # Should timeout (5 seconds) and be killed
        # If it completes, counter should not reach 100 (would take 10s)
        assert "error" in result or ("ran" in result and result["ran"] < 100)
        
        # Error should mention timeout
        if "error" in result:
            assert "timeout" in result["error"].lower() or "timed out" in result["error"].lower()
