"""Red Team security audit - Feb 26, 2026 3:51 PM - Cheenu's creative new attacks."""

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


class TestTemporalAPISideChannel:
    """Attack: Use Temporal API for high-precision timing side-channels."""
    
    @pytest.mark.asyncio
    async def test_attack_temporal_instant_timing_oracle(self, sandbox):
        """
        ATTACK: Use Temporal.Instant for nanosecond precision timing attacks.
        
        Strategy: Temporal API provides extremely high-precision timestamps
        (nanosecond level). Try to use this for timing oracle attacks that
        could reveal token properties by measuring fetch timing differences.
        
        Expected defense: Token scrubbing happens before any user code can
        measure timing. Also, timing variations should not leak token content.
        """
        code = '''async () => {
            const results = [];
            
            // Check if Temporal API is available
            const hasTemporal = typeof Temporal !== 'undefined';
            
            if (hasTemporal) {
                // Measure request timing with nanosecond precision
                const measurements = [];
                
                for (let i = 0; i < 5; i++) {
                    const start = Temporal.Now.instant();
                    
                    try {
                        await mist.request({method: "GET", path: "/api/v1/self"});
                    } catch (e) {
                        // Ignore errors, we're measuring timing
                    }
                    
                    const end = Temporal.Now.instant();
                    const duration = start.until(end, {largestUnit: 'nanosecond'});
                    
                    measurements.push({
                        nanoseconds: duration.total('nanoseconds'),
                        microseconds: duration.total('microseconds')
                    });
                }
                
                // Try to infer token properties from timing variance
                const timings = measurements.map(m => m.nanoseconds);
                const avgTime = timings.reduce((a, b) => a + b) / timings.length;
                const variance = timings.map(t => Math.abs(t - avgTime));
                
                results.push({
                    hasTemporal: true,
                    measurements: measurements.length,
                    avgNanoseconds: avgTime,
                    maxVariance: Math.max(...variance),
                    // Try to correlate timing with token length (should fail)
                    suspectedTokenLength: Math.floor(avgTime / 1000000) % 100
                });
            } else {
                results.push({
                    hasTemporal: false,
                    fallback: 'Temporal API not available'
                });
            }
            
            return results;
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # EXPECT: Token should NOT leak via timing oracle
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via Temporal timing oracle!"
        
        # Timing measurements are OK, but should not reveal token
        # The attack might succeed in measuring timing but shouldn't leak the actual token


class TestReadableStreamTeeBypass:
    """Attack: Use ReadableStream.tee() to create duplicate streams."""
    
    @pytest.mark.asyncio
    async def test_attack_response_body_tee_double_read(self, sandbox):
        """
        ATTACK: Intercept fetch, tee() the response body stream, read it twice.
        
        Strategy: ReadableStream.tee() creates two independent branches from
        one stream. If we intercept fetch and tee() the body before mist.request
        consumes it, we might be able to read headers or body twice.
        
        Expected defense: mist.request doesn't expose Response object, so
        tee() can't be applied to something we don't have access to.
        """
        code = '''async () => {
            let interceptedData = null;
            const originalFetch = globalThis.fetch;
            
            globalThis.fetch = async (...args) => {
                const response = await originalFetch(...args);
                
                try {
                    // Try to tee() the response body
                    const [stream1, stream2] = response.body.tee();
                    
                    // Create new response from stream1 to return
                    const response1 = new Response(stream1, {
                        status: response.status,
                        statusText: response.statusText,
                        headers: response.headers
                    });
                    
                    // Try to read stream2 in background
                    (async () => {
                        try {
                            const reader = stream2.getReader();
                            const chunks = [];
                            
                            while (true) {
                                const {done, value} = await reader.read();
                                if (done) break;
                                chunks.push(value);
                            }
                            
                            // Decode the chunks
                            const decoder = new TextDecoder();
                            const text = decoder.decode(
                                new Uint8Array(
                                    chunks.reduce((acc, chunk) => [...acc, ...chunk], [])
                                )
                            );
                            
                            interceptedData = {
                                bodyLength: text.length,
                                bodySample: text.substring(0, 200),
                                headers: Object.fromEntries(response.headers.entries())
                            };
                        } catch (e) {
                            interceptedData = {error: e.message};
                        }
                    })();
                    
                    return response1;
                } catch (e) {
                    return response;
                }
            };
            
            // Make request
            const result = await mist.request({method: "GET", path: "/api/v1/self"});
            
            // Wait a bit for background read to complete
            await new Promise(resolve => setTimeout(resolve, 100));
            
            return {
                requestResult: typeof result === 'object',
                interceptedData: interceptedData
            };
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # EXPECT: Token scrubbed even if stream was tee'd and read twice
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via ReadableStream.tee()!"
        
        # Check headers specifically
        if 'headers' in result_str.lower():
            assert SECRET_TOKEN not in result_str, "Token in intercepted headers!"


class TestMicrotaskInjectionDuringIIFE:
    """Attack: Inject microtasks during IIFE execution to capture token."""
    
    @pytest.mark.asyncio
    async def test_attack_microtask_race_during_stdin_read(self, sandbox):
        """
        ATTACK: Queue microtasks before code execution that might run during
        the IIFE token read, potentially capturing the token from async context.
        
        Strategy: The IIFE reads token from stdin asynchronously. If we can
        queue microtasks that run during or right after that read but before
        the mist object is fully constructed, we might capture intermediate state.
        
        Expected defense: IIFE closure scope is inaccessible from outside.
        Microtasks run in the same context but can't access closure variables.
        """
        code = '''async () => {
            const captured = [];
            
            // Try to install microtask hooks BEFORE mist is used
            // This won't help since mist is already constructed, but try anyway
            const originalQueueMicrotask = globalThis.queueMicrotask;
            
            globalThis.queueMicrotask = function(callback) {
                // Wrap callback to try to inspect state
                const wrappedCallback = () => {
                    try {
                        // Try to capture any token-related state
                        captured.push({
                            globalThisKeys: Object.keys(globalThis).filter(k => 
                                k.toLowerCase().includes('token') || 
                                k.toLowerCase().includes('mist')
                            ),
                            mistExists: typeof mist !== 'undefined',
                            mistKeys: typeof mist !== 'undefined' ? Object.keys(mist) : []
                        });
                    } catch (e) {
                        captured.push({error: e.message});
                    }
                    callback();
                };
                
                return originalQueueMicrotask.call(globalThis, wrappedCallback);
            };
            
            // Now make a request (which will queue microtasks internally)
            const result = await mist.request({method: "GET", path: "/api/v1/self"});
            
            // Also try to directly queue a microtask that inspects mist object
            queueMicrotask(() => {
                try {
                    // Try to access mist internals via toString or valueOf
                    captured.push({
                        mistToString: mist.toString?.(),
                        mistValueOf: mist.valueOf?.(),
                        mistConstructor: mist.constructor?.name,
                        mistPrototype: Object.getPrototypeOf(mist)
                    });
                } catch (e) {
                    captured.push({microtaskError: e.message});
                }
            });
            
            // Wait for microtasks to complete
            await new Promise(resolve => setTimeout(resolve, 10));
            
            return {
                capturedStates: captured,
                requestSucceeded: typeof result === 'object'
            };
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # EXPECT: Token NOT leaked via microtask inspection
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via microtask injection!"
        
        # Microtasks can see mist object but not the token inside the IIFE closure


class TestProxyHandlerTrapLeakage:
    """Attack: Wrap mist object with Proxy to intercept all operations."""
    
    @pytest.mark.asyncio
    async def test_attack_proxy_intercept_all_mist_operations(self, sandbox):
        """
        ATTACK: Wrap mist in a Proxy with extensive traps to capture all
        interactions and potentially leak the token from internal operations.
        
        Strategy: Create a Proxy around mist that logs every property access,
        function call, and internal operation. Try to capture token from
        the Authorization header construction.
        
        Expected defense: Token is in closure scope and never exposed as a
        property or parameter that the Proxy can intercept.
        """
        code = '''async () => {
            const interceptedOps = [];
            
            // Wrap mist in a logging Proxy
            const handler = {
                get(target, prop, receiver) {
                    interceptedOps.push({type: 'get', prop: String(prop)});
                    const value = Reflect.get(target, prop, receiver);
                    
                    // If it's a function, wrap it too
                    if (typeof value === 'function') {
                        return new Proxy(value, {
                            apply(fnTarget, thisArg, args) {
                                interceptedOps.push({
                                    type: 'apply',
                                    fn: String(prop),
                                    argsCount: args.length,
                                    args: args.map(a => 
                                        typeof a === 'object' ? 
                                            JSON.stringify(a).substring(0, 100) : 
                                            String(a).substring(0, 50)
                                    )
                                });
                                return Reflect.apply(fnTarget, thisArg, args);
                            }
                        });
                    }
                    
                    return value;
                },
                has(target, prop) {
                    interceptedOps.push({type: 'has', prop: String(prop)});
                    return Reflect.has(target, prop);
                },
                ownKeys(target) {
                    interceptedOps.push({type: 'ownKeys'});
                    return Reflect.ownKeys(target);
                },
                getOwnPropertyDescriptor(target, prop) {
                    interceptedOps.push({type: 'getOwnPropertyDescriptor', prop: String(prop)});
                    return Reflect.getOwnPropertyDescriptor(target, prop);
                }
            };
            
            const proxiedMist = new Proxy(mist, handler);
            
            // Use the proxied mist
            const result = await proxiedMist.request({
                method: "GET",
                path: "/api/v1/self"
            });
            
            return {
                interceptedOps: interceptedOps,
                requestSucceeded: typeof result === 'object',
                mistKeys: Object.keys(mist)
            };
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # EXPECT: Token NOT leaked through Proxy interception
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via Proxy traps!"
        
        # Proxy can see operations but token is in closure, not in args/props


class TestEnvironmentVariableProbing:
    """Attack: Try to read environment variables that might contain the token."""
    
    @pytest.mark.asyncio
    async def test_attack_deno_env_permission_probe(self, sandbox):
        """
        ATTACK: Try to read environment variables via Deno.env.
        
        Strategy: The server might have MIST_APITOKEN in environment variables.
        Try to read it even though --deny-env is set.
        
        Expected defense: --deny-env blocks all environment variable access.
        """
        code = '''async () => {
            const attempts = [];
            
            // Try to read env vars
            try {
                const envKeys = Object.keys(Deno.env.toObject());
                attempts.push({
                    method: 'Deno.env.toObject',
                    success: true,
                    keys: envKeys
                });
            } catch (e) {
                attempts.push({
                    method: 'Deno.env.toObject',
                    success: false,
                    error: e.message
                });
            }
            
            // Try to read specific keys
            const keysToTry = [
                'MIST_APITOKEN',
                'MISTMIND_APITOKEN',
                'TOKEN',
                'API_TOKEN',
                'PATH',
                'HOME'
            ];
            
            for (const key of keysToTry) {
                try {
                    const value = Deno.env.get(key);
                    attempts.push({
                        method: 'Deno.env.get',
                        key: key,
                        success: value !== undefined,
                        valueLength: value ? value.length : 0
                    });
                } catch (e) {
                    attempts.push({
                        method: 'Deno.env.get',
                        key: key,
                        success: false,
                        error: e.message
                    });
                }
            }
            
            return {attempts: attempts};
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # EXPECT: All env access should be denied
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via environment variables!"
        
        # Check that access was actually denied
        if 'attempts' in str(result):
            for attempt in result.get('attempts', []):
                if attempt.get('success'):
                    # If any succeeded, the key better not be token-related
                    assert 'TOKEN' not in attempt.get('key', '').upper(), \
                        f"Env access succeeded for {attempt.get('key')}!"
