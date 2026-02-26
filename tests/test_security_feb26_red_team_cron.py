"""Feb 26 Morning Cron Red Team - Creative Attack Vectors

Focus areas:
1. V8 heap/GC manipulation to expose token in memory
2. Fetch timing side channels to infer token validity
3. Promise microtask queue manipulation during IIFE initialization
"""

import pytest
from mistmind.sandbox import DenoSandbox
from pathlib import Path

SECRET_TOKEN = "super-secret-api-token-feb26-cron"


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
    """Create a Deno sandbox for execute mode."""
    return DenoSandbox(deno_path=deno_path, timeout=10, api_mode="readonly")


class TestV8HeapManipulation:
    """Attack: Trigger GC and inspect heap to find token remnants."""
    
    @pytest.mark.asyncio
    async def test_attack_force_gc_heap_inspection(self, sandbox):
        """Try to trigger V8 GC and inspect heap for token strings.
        
        Strategy: Allocate huge objects to force GC, then try to find
        token in heap via various inspection techniques.
        """
        code = '''async () => {
            // Force memory pressure to trigger GC
            let arrays = [];
            for (let i = 0; i < 100; i++) {
                arrays.push(new Array(100000).fill('x'));
            }
            arrays = null; // Force GC
            
            // Try to access GC via v8 module (should be blocked)
            try {
                const v8 = await import('node:v8');
                const heapStats = v8.getHeapStatistics();
                // Try to serialize heap and search for token patterns
                return { attack: "gc_inspection", heap: heapStats };
            } catch (e) {
                // Expected - node:v8 not available in Deno
            }
            
            // Alternative: try to inspect WeakRef registry after GC
            const registry = new FinalizationRegistry((value) => {
                // This callback runs during GC - can we leak data?
                console.error("GC callback triggered:", value);
            });
            
            const obj = { secret: "leaked" };
            registry.register(obj, "marker");
            
            return { attack: "gc_heap_inspection", result: "blocked" };
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com"
        )
        
        # Verify token not leaked
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked in GC inspection!"
        
        # NOTE: node:v8 IS accessible in Deno! But heap stats shouldn't leak token.
        # This is a real finding - we should document this as accepted risk.
        # Heap statistics alone don't leak the token value, but provide memory metadata.
        if result.get("attack") == "gc_inspection" and "heap" in result:
            # Verify heap stats don't contain token-sized strings
            heap = result["heap"]
            # The token isn't directly in heap stats, so this is acceptable
            assert isinstance(heap, dict), "Heap stats should be a dict"
            # This attack vector is valid but doesn't leak the token itself

    @pytest.mark.asyncio
    async def test_attack_arraybuffer_memory_search(self, sandbox):
        """Try to search ArrayBuffer/SharedArrayBuffer for token strings.
        
        Strategy: Create ArrayBuffers, hope token exists in nearby memory,
        scan for byte patterns.
        """
        code = '''async () => {
            // Try to allocate buffers near token memory location
            const buffers = [];
            for (let i = 0; i < 1000; i++) {
                const buf = new ArrayBuffer(1024);
                const view = new Uint8Array(buf);
                
                // Scan for ASCII patterns that might be the token
                let suspicious = "";
                for (let j = 0; j < view.length; j++) {
                    const byte = view[j];
                    if (byte >= 32 && byte <= 126) {
                        suspicious += String.fromCharCode(byte);
                    } else {
                        suspicious = "";
                    }
                    
                    // Look for "token" or "secret" patterns
                    if (suspicious.length > 10 && 
                        (suspicious.includes("token") || suspicious.includes("secret"))) {
                        return { attack: "memory_leak", found: suspicious };
                    }
                }
                buffers.push(buf);
            }
            
            return { attack: "arraybuffer_scan", result: "no_leak" };
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com"
        )
        
        # Verify token not leaked
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via ArrayBuffer scan!"
        
        # Even partial leaks are bad
        token_fragments = [SECRET_TOKEN[i:i+5] for i in range(0, len(SECRET_TOKEN), 5)]
        for fragment in token_fragments:
            if len(fragment) >= 5:  # Only check meaningful fragments
                assert fragment not in result_str, f"Token fragment '{fragment}' leaked!"


class TestFetchTimingSideChannel:
    """Attack: Use fetch timing to infer token validity without seeing token."""
    
    @pytest.mark.asyncio
    async def test_attack_timing_oracle_token_validity(self, sandbox):
        """Measure fetch timing to determine if token is valid.
        
        Strategy: Time how long requests take. Valid tokens might have
        different timing than invalid ones (auth vs auth failure paths).
        """
        code = '''async () => {
            const timings = [];
            
            // Measure multiple requests to detect timing differences
            for (let i = 0; i < 5; i++) {
                const start = performance.now();
                try {
                    await mist.request({ path: "/api/v1/self" });
                    const elapsed = performance.now() - start;
                    timings.push({ success: true, time: elapsed });
                } catch (e) {
                    const elapsed = performance.now() - start;
                    timings.push({ success: false, time: elapsed, error: e.message });
                }
            }
            
            // Statistical analysis: do success times differ from failures?
            const successTimes = timings.filter(t => t.success).map(t => t.time);
            const failureTimes = timings.filter(t => !t.success).map(t => t.time);
            
            const avgSuccess = successTimes.reduce((a,b) => a+b, 0) / successTimes.length;
            const avgFailure = failureTimes.reduce((a,b) => a+b, 0) / failureTimes.length || 0;
            
            return {
                attack: "timing_oracle",
                timings,
                analysis: {
                    avgSuccess,
                    avgFailure,
                    // If timing differs significantly, token validity is leaked
                    differential: Math.abs(avgSuccess - avgFailure)
                }
            };
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com"
        )
        
        # Verify token not in output
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked in timing attack!"
        
        # This attack is expected to work (timing info is available)
        # but should not leak the token itself
        assert "error" in result or "timings" in result

    @pytest.mark.asyncio
    async def test_attack_cache_timing_side_channel(self, sandbox):
        """Use cache timing to infer token characteristics.
        
        Strategy: Make requests and measure cache behavior.
        Token length or content might affect caching.
        """
        code = '''async () => {
            // Try to exploit HTTP caching timing
            const measurements = [];
            
            for (let i = 0; i < 3; i++) {
                const start = performance.now();
                try {
                    // Request same endpoint multiple times
                    const data = await mist.request({ 
                        path: "/api/v1/self",
                        // Try to force cache behavior
                        params: { _t: Date.now() }
                    });
                    const elapsed = performance.now() - start;
                    measurements.push({ 
                        iteration: i, 
                        time: elapsed,
                        cached: elapsed < 10  // Very fast = likely cached
                    });
                } catch (e) {
                    measurements.push({ iteration: i, error: e.message });
                }
                
                // Small delay between requests
                await new Promise(r => setTimeout(r, 100));
            }
            
            return {
                attack: "cache_timing",
                measurements,
                // If caching behavior varies, might leak token info
                pattern: measurements.map(m => m.cached).join("")
            };
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com"
        )
        
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked in cache timing!"


class TestPromiseMicrotaskInterception:
    """Attack: Intercept Promise microtask queue during IIFE initialization."""
    
    @pytest.mark.asyncio
    async def test_attack_queuemicrotask_hijack_during_iife(self, sandbox):
        """Hijack queueMicrotask to intercept token before IIFE completes.
        
        Strategy: Override queueMicrotask BEFORE the IIFE runs,
        try to capture token during stdin read.
        """
        code = '''async () => {
            // Try to install microtask interceptor early
            const original = globalThis.queueMicrotask;
            const captured = [];
            
            globalThis.queueMicrotask = (fn) => {
                // Wrap the function to inspect its closure
                const wrapped = () => {
                    try {
                        // Try to inspect the function's scope
                        captured.push({
                            source: fn.toString(),
                            name: fn.name
                        });
                    } catch (e) {}
                    return fn();
                };
                return original(wrapped);
            };
            
            // Wait for any microtasks that might be queued
            await new Promise(r => setTimeout(r, 100));
            
            return {
                attack: "queuemicrotask_hijack",
                captured,
                result: "token_should_not_be_here"
            };
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com"
        )
        
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via queueMicrotask!"
        
        # Even if attack "succeeded", token must be scrubbed
        if "captured" in result:
            for item in result.get("captured", []):
                assert SECRET_TOKEN not in str(item), "Token in captured microtasks!"

    @pytest.mark.asyncio
    async def test_attack_promise_then_chain_during_stdin_read(self, sandbox):
        """Chain Promise.then() to intercept async operations during IIFE.
        
        Strategy: Override Promise.prototype.then before IIFE runs,
        try to intercept the stdin read operation.
        """
        code = '''async () => {
            // Intercept all .then() calls to inspect promise chains
            const originalThen = Promise.prototype.then;
            const intercepted = [];
            
            Promise.prototype.then = function(onFulfilled, onRejected) {
                // Wrap callbacks to log their results
                const wrappedFulfill = onFulfilled ? (value) => {
                    // Try to capture the value
                    if (typeof value === 'string' && value.length > 10) {
                        intercepted.push({
                            type: 'then_fulfill',
                            valueType: typeof value,
                            length: value.length,
                            // Don't store actual value - just metadata
                            firstChar: value[0]
                        });
                    }
                    return onFulfilled(value);
                } : onFulfilled;
                
                return originalThen.call(this, wrappedFulfill, onRejected);
            };
            
            // Wait for stdin-related promises to complete
            await new Promise(r => setTimeout(r, 200));
            
            // Restore original
            Promise.prototype.then = originalThen;
            
            return {
                attack: "promise_then_chain",
                intercepted,
                count: intercepted.length
            };
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com"
        )
        
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via Promise.then!"
        
        # Even metadata leaks are concerning
        if "intercepted" in result:
            for item in result.get("intercepted", []):
                # Check that we didn't leak token length
                if "length" in item:
                    # Token length itself is sensitive info
                    assert item["length"] != len(SECRET_TOKEN), \
                        "Token length leaked via Promise interception!"


class TestMemoryForensics:
    """Attack: Memory forensics via JS heap inspection APIs."""
    
    @pytest.mark.asyncio
    async def test_attack_memory_profiler_snapshot(self, sandbox):
        """Try to use Deno's profiling APIs to capture heap snapshots.
        
        Strategy: Access Deno.memoryUsage or performance.memory
        to get memory statistics that might leak token presence.
        """
        code = '''async () => {
            const forensics = {
                attack: "memory_profiler"
            };
            
            // Try Deno.memoryUsage (might be available)
            try {
                forensics.denoMemory = Deno.memoryUsage();
            } catch (e) {
                forensics.denoError = e.message;
            }
            
            // Try performance.memory (Chrome/V8 extension)
            try {
                if (performance.memory) {
                    forensics.perfMemory = {
                        used: performance.memory.usedJSHeapSize,
                        total: performance.memory.totalJSHeapSize,
                        limit: performance.memory.jsHeapSizeLimit
                    };
                }
            } catch (e) {
                forensics.perfError = e.message;
            }
            
            // Try to detect token presence via memory growth
            const before = Deno.memoryUsage?.().heapUsed || 0;
            
            // Allocate similar-sized string
            const dummy = "x".repeat(100);
            
            const after = Deno.memoryUsage?.().heapUsed || 0;
            forensics.memoryGrowth = after - before;
            
            return forensics;
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com"
        )
        
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked in memory forensics!"
        
        # Memory stats themselves are okay, but shouldn't reveal token
        if "denoMemory" in result:
            # Memory size shouldn't exactly match token length
            heap_used = result.get("denoMemory", {}).get("heapUsed", 0)
            # This is a weak check - just ensure no obvious correlation
            assert heap_used != len(SECRET_TOKEN), "Suspicious memory correlation!"
