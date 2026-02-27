"""Security tests for Feb 27 5AM cron audit - Fresh attack vectors."""

import asyncio
import json
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
    
    import shutil
    deno_in_path = shutil.which("deno")
    if deno_in_path:
        return deno_in_path
    
    pytest.skip("Deno not found")


@pytest.fixture
def sandbox(deno_path):
    """Create a Deno sandbox instance for execute mode."""
    return DenoSandbox(
        deno_path=deno_path,
        timeout=5,
        api_mode="readwrite",  # Use readwrite to test more surface area
    )


SECRET_TOKEN = "super-secret-api-token-12345"


class TestFeb27CronCheenuAttacks:
    """New red team attacks discovered during Feb 27 5AM audit."""
    
    @pytest.mark.asyncio
    async def test_attack_response_headers_race_condition(self, sandbox):
        """
        ATTACK: Response.headers is a live object that reflects the Request.
        Can we capture headers before they're consumed by the response handler?
        
        GOAL: Extract Authorization header from the fetch Request object
        via the Response.headers property during async iteration.
        """
        code = """async () => {
            // Attempt to intercept headers during response processing
            const capturedHeaders = [];
            
            // Override Headers prototype to capture gets
            const originalGet = Headers.prototype.get;
            Headers.prototype.get = function(name) {
                capturedHeaders.push({name, value: originalGet.call(this, name)});
                return originalGet.call(this, name);
            };
            
            try {
                // Make a request - this should trigger header access
                const result = await mist.request({path: "/api/v1/self"});
                
                // Try to find Authorization in captured headers
                const authHeader = capturedHeaders.find(h => 
                    h.name.toLowerCase() === 'authorization'
                );
                
                if (authHeader) {
                    return {attack: "SUCCESS", leaked: authHeader.value};
                }
            } catch (e) {
                // Expected to fail
            }
            
            return {attack: "FAILED", captured: capturedHeaders.length};
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # Should NOT leak token
        assert SECRET_TOKEN not in json.dumps(result)
        assert "SUCCESS" not in json.dumps(result) or result.get("leaked") == "[REDACTED]"
    
    @pytest.mark.asyncio
    async def test_attack_async_generator_yield_during_iife(self, sandbox):
        """
        ATTACK: Can we create an async generator that yields control
        during the IIFE execution, potentially creating a race condition
        where the token is briefly accessible in the event loop?
        
        GOAL: Use async generators to pause execution during IIFE setup,
        then resume and try to access the token from a different async context.
        """
        code = """async () => {
            let tokenCapture = null;
            
            // Create an async generator that tries to access globals
            async function* tokenSniffer() {
                // Yield control to let IIFE complete
                yield "waiting";
                
                // Try to access anything that might still reference the token
                try {
                    // Check if any globals were polluted
                    const keys = Object.keys(globalThis);
                    const suspiciousKeys = keys.filter(k => 
                        k.includes('token') || k.includes('_') || k.includes('mist')
                    );
                    
                    for (const key of suspiciousKeys) {
                        const val = globalThis[key];
                        if (typeof val === 'string' && val.length > 20) {
                            tokenCapture = val;
                        }
                    }
                } catch (e) {
                    // Expected
                }
                
                yield tokenCapture;
            }
            
            const gen = tokenSniffer();
            await gen.next(); // First yield
            
            // Now make a real request to trigger mist object usage
            try {
                await mist.request({path: "/api/v1/self"});
            } catch (e) {
                // Expected to fail (invalid token)
            }
            
            const final = await gen.next(); // Second yield - try to capture
            
            return {
                attack: tokenCapture ? "SUCCESS" : "FAILED",
                captured: tokenCapture || "none"
            };
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # Should NOT leak token
        assert SECRET_TOKEN not in json.dumps(result)
        assert "SUCCESS" not in json.dumps(result) or result.get("captured") == "[REDACTED]"
    
    @pytest.mark.asyncio
    async def test_attack_symbol_tostringtag_mist_inspection(self, sandbox):
        """
        ATTACK: Override Symbol.toStringTag on Object.prototype to intercept
        string coercion operations on the mist object, potentially leaking
        internal state or closure variables.
        
        GOAL: Hijack Symbol.toStringTag to extract information during toString()
        operations that might happen during error handling or logging.
        """
        code = """async () => {
            const leakedData = [];
            
            // Hijack Symbol.toStringTag getter on Object.prototype
            Object.defineProperty(Object.prototype, Symbol.toStringTag, {
                get: function() {
                    // Try to access 'this' context
                    try {
                        const keys = Object.getOwnPropertyNames(this);
                        const symbols = Object.getOwnPropertySymbols(this);
                        
                        // Look for anything suspicious
                        for (const key of keys) {
                            const val = this[key];
                            if (typeof val === 'string' && val.length > 20) {
                                leakedData.push({key, value: val});
                            }
                        }
                        
                        // Try to walk up the prototype chain
                        let proto = Object.getPrototypeOf(this);
                        while (proto) {
                            const protoKeys = Object.getOwnPropertyNames(proto);
                            for (const key of protoKeys) {
                                try {
                                    const val = proto[key];
                                    if (typeof val === 'string' && val.length > 20) {
                                        leakedData.push({source: 'proto', key, value: val});
                                    }
                                } catch (e) {
                                    // Expected for some properties
                                }
                            }
                            proto = Object.getPrototypeOf(proto);
                        }
                    } catch (e) {
                        // Expected
                    }
                    
                    return 'Object';
                },
                configurable: true
            });
            
            // Trigger string coercion on mist object
            try {
                String(mist);
                Object.prototype.toString.call(mist);
                `${mist}`;
                
                // Also try during a request error
                await mist.request({path: "/invalid"});
            } catch (e) {
                // Expected to fail
            }
            
            return {
                attack: leakedData.length > 0 ? "PARTIAL" : "FAILED",
                leaked: leakedData
            };
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # Should NOT leak token
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
        
        # If any data was leaked, it should be scrubbed
        if result.get("leaked"):
            for item in result["leaked"]:
                assert SECRET_TOKEN not in str(item.get("value", ""))


class TestAsyncContextManipulation:
    """Advanced async context manipulation attacks."""
    
    @pytest.mark.asyncio
    async def test_attack_promise_finally_token_snapshot(self, sandbox):
        """
        ATTACK: Use Promise.finally to capture the execution context
        at the moment the IIFE completes, potentially accessing variables
        that are about to go out of scope.
        
        GOAL: Snapshot the execution context during promise resolution.
        """
        code = """async () => {
            let contextSnapshot = null;
            
            // Hijack Promise.prototype.finally
            const originalFinally = Promise.prototype.finally;
            Promise.prototype.finally = function(onFinally) {
                // Capture the promise's internal state
                try {
                    contextSnapshot = {
                        keys: Object.keys(this),
                        symbols: Object.getOwnPropertySymbols(this),
                        proto: Object.getPrototypeOf(this)
                    };
                } catch (e) {
                    // Expected
                }
                
                return originalFinally.call(this, onFinally);
            };
            
            // Make a request to trigger promise chains
            try {
                await mist.request({path: "/api/v1/self"});
            } catch (e) {
                // Expected to fail
            }
            
            return {
                attack: contextSnapshot ? "CAPTURED" : "FAILED",
                snapshot: contextSnapshot
            };
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # Should NOT leak token in any form
        assert SECRET_TOKEN not in json.dumps(result)
    
    @pytest.mark.asyncio
    async def test_attack_request_init_object_inspection(self, sandbox):
        """
        ATTACK: Override the Request constructor to capture the init object
        that contains headers (including Authorization).
        
        GOAL: Intercept the Request initialization before fetch is called.
        """
        code = """async () => {
            let capturedInit = null;
            
            // Hijack Request constructor
            const OriginalRequest = globalThis.Request;
            globalThis.Request = class extends OriginalRequest {
                constructor(input, init) {
                    // Try to capture the init object
                    try {
                        capturedInit = JSON.parse(JSON.stringify(init || {}));
                    } catch (e) {
                        capturedInit = {error: e.message};
                    }
                    
                    super(input, init);
                }
            };
            
            // Make a request
            try {
                await mist.request({path: "/api/v1/self"});
            } catch (e) {
                // Expected to fail
            }
            
            return {
                attack: capturedInit && capturedInit.headers ? "SUCCESS" : "FAILED",
                captured: capturedInit
            };
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # Should NOT leak token
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
        
        # If headers were captured, Authorization should be scrubbed
        if result.get("captured", {}).get("headers"):
            headers = result["captured"]["headers"]
            if isinstance(headers, dict):
                assert headers.get("Authorization") != f"Token {SECRET_TOKEN}"


class TestMemoryForensicsV2:
    """Advanced memory forensics attacks."""
    
    @pytest.mark.asyncio
    async def test_attack_weak_set_token_tracking(self, sandbox):
        """
        ATTACK: Use WeakSet to track all objects created during execution,
        then inspect them after the IIFE completes to find lingering references.
        
        GOAL: Track object creation and inspect for token references.
        """
        code = """async () => {
            const trackedObjects = [];
            
            // Hijack Object constructor
            const OriginalObject = Object;
            const objectTracker = new WeakSet();
            
            // Override Object methods to track creation
            const originalCreate = Object.create;
            Object.create = function(...args) {
                const obj = originalCreate.apply(this, args);
                if (typeof obj === 'object' && obj !== null) {
                    trackedObjects.push(obj);
                }
                return obj;
            };
            
            // Make a request
            try {
                await mist.request({path: "/api/v1/self"});
            } catch (e) {
                // Expected to fail
            }
            
            // Inspect all tracked objects for token-like strings
            const suspects = [];
            for (const obj of trackedObjects) {
                try {
                    const str = JSON.stringify(obj);
                    if (str && str.length > 20) {
                        suspects.push(str.substring(0, 50));
                    }
                } catch (e) {
                    // Can't stringify, skip
                }
            }
            
            return {
                attack: "SCAN_COMPLETE",
                trackedCount: trackedObjects.length,
                suspects: suspects.slice(0, 5) // Only return first 5
            };
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com",
        )
        
        # Should NOT leak token
        assert SECRET_TOKEN not in json.dumps(result)
