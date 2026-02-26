"""Feb 25 Late Night Audit - Cheenu's creative new attack vectors."""

import pytest

from mistmind.sandbox import DenoSandbox


@pytest.fixture
def sandbox(tmp_path):
    """Sandbox fixture for execute tests."""
    deno_path = "/Users/cheenu/.deno/bin/deno"
    return DenoSandbox(deno_path=deno_path, api_mode="readwrite")


class TestServiceWorkerInterception:
    """Test service worker registration to intercept network requests."""
    
    @pytest.mark.asyncio
    async def test_attack_service_worker_intercept(self, sandbox):
        """Try to register a service worker that could intercept fetch() calls."""
        code = """async () => {
            // Attack: Register a service worker to intercept all fetch requests
            // If successful, could capture Authorization headers with token
            
            try {
                // Check if ServiceWorker API is available
                if (typeof ServiceWorkerContainer === 'undefined') {
                    return { 
                        blocked: true, 
                        reason: "ServiceWorker API not available in Deno" 
                    };
                }
                
                // Try to register a service worker with inline script
                const swCode = `
                    self.addEventListener('fetch', (event) => {
                        // Intercept and log all fetch requests
                        const auth = event.request.headers.get('Authorization');
                        console.log('CAPTURED:', auth);
                    });
                `;
                
                const blob = new Blob([swCode], { type: 'application/javascript' });
                const swUrl = URL.createObjectURL(blob);
                
                const registration = await navigator.serviceWorker.register(swUrl);
                
                return {
                    success: true,
                    vulnerability: "Service worker registered - could intercept token",
                    registration: registration.scope
                };
            } catch (e) {
                return {
                    blocked: true,
                    error: e.message
                };
            }
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="sw-token-12345",
            api_host="api.mist.com",
        )
        
        # Token should never appear in output
        assert "sw-token-12345" not in str(result)
        
        # Service workers should be blocked in Deno CLI context
        assert result.get("blocked") or result.get("error")


class TestAsyncContextLeakage:
    """Test async context leakage via microtask queue manipulation."""
    
    @pytest.mark.asyncio
    async def test_attack_microtask_queue_hijack(self, sandbox):
        """Try to hijack microtask queue to execute code after mist object creation."""
        code = """async () => {
            // Attack: Queue microtasks that execute after the IIFE completes
            // but before user code runs, potentially in a context where token is accessible
            
            const leakedData = { captured: null };
            
            // Schedule microtasks to run at various points
            queueMicrotask(() => {
                try {
                    // Try to capture anything in global scope
                    leakedData.globalKeys = Object.keys(globalThis);
                    leakedData.mistType = typeof mist;
                    
                    // Try to inspect mist.request toString
                    if (mist && mist.request) {
                        leakedData.requestSource = mist.request.toString();
                    }
                } catch (e) {
                    leakedData.error = e.message;
                }
            });
            
            // Wait for microtasks to complete
            await new Promise(resolve => setTimeout(resolve, 0));
            
            return leakedData;
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="microtask-token-67890",
            api_host="api.mist.com",
        )
        
        # Token should never leak
        assert "microtask-token-67890" not in str(result)
        
        # Even if we can inspect mist.request source, token shouldn't be in it
        if result.get("requestSource"):
            assert "microtask-token-67890" not in result["requestSource"]


class TestSymbolToPrimitiveBypass:
    """Test Symbol.toPrimitive/toStringTag to bypass output scrubbing."""
    
    @pytest.mark.asyncio
    async def test_attack_symbol_toprimitive_leak(self, sandbox):
        """Try to use Symbol.toPrimitive to leak token during JSON.stringify."""
        code = """async () => {
            // Attack: Create an object with Symbol.toPrimitive that executes
            // during JSON.stringify, potentially bypassing scrubbing
            
            const trojanHorse = {
                data: "normal-data",
                
                // This gets called when object is coerced to primitive
                [Symbol.toPrimitive](hint) {
                    // Try to capture mist object internals
                    if (typeof mist !== 'undefined' && mist.request) {
                        return `LEAK:${mist.request.toString()}`;
                    }
                    return "safe-value";
                },
                
                // This gets called during JSON.stringify
                toJSON() {
                    const captured = {};
                    
                    // Try to iterate over mist properties
                    if (typeof mist !== 'undefined') {
                        try {
                            for (const key of Object.keys(mist)) {
                                captured[key] = String(mist[key]);
                            }
                        } catch (e) {
                            captured.error = e.message;
                        }
                    }
                    
                    return captured;
                },
                
                // Custom toString tag
                get [Symbol.toStringTag]() {
                    try {
                        // Try to capture anything during string coercion
                        if (typeof mist !== 'undefined') {
                            return `MistLeak:${Object.keys(mist).join(',')}`;
                        }
                    } catch (e) {
                        return "SecurityError";
                    }
                    return "TrojanObject";
                }
            };
            
            return trojanHorse;
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="symbol-token-11111",
            api_host="api.mist.com",
        )
        
        # Token should never leak through any Symbol method
        assert "symbol-token-11111" not in str(result)
        
        # Even if Symbol methods execute, they shouldn't have token access
        result_str = str(result)
        assert "symbol-token-11111" not in result_str


class TestProxyGetterSideEffects:
    """Test Proxy handlers with side effects to capture data before scrubbing."""
    
    @pytest.mark.asyncio
    async def test_attack_proxy_getter_side_channel(self, sandbox):
        """Try to use Proxy get traps to execute code during output processing."""
        code = """async () => {
            // Attack: Create a Proxy that executes code when properties are accessed
            // during JSON.stringify or scrubbing process
            
            const capturedAccesses = [];
            
            const proxyTarget = {
                normalData: "visible-data"
            };
            
            const trojans = new Proxy(proxyTarget, {
                get(target, prop, receiver) {
                    // Log all property accesses
                    capturedAccesses.push(String(prop));
                    
                    // Try to capture stack trace to see where we're called from
                    const stack = new Error().stack;
                    
                    // If accessed during scrubbing, try to interfere
                    if (prop === 'toString' || prop === 'valueOf') {
                        try {
                            // Try to access mist during property access
                            if (typeof mist !== 'undefined') {
                                capturedAccesses.push(`mist_available:${typeof mist.request}`);
                            }
                        } catch (e) {
                            capturedAccesses.push(`error:${e.message}`);
                        }
                    }
                    
                    return Reflect.get(target, prop, receiver);
                },
                
                // Trap for Object.keys/getOwnPropertyNames during scrubbing
                ownKeys(target) {
                    capturedAccesses.push('ownKeys_called');
                    
                    // Try to inject token-like string as a property name
                    const realKeys = Reflect.ownKeys(target);
                    // Note: Can't actually leak token, but testing if we can inject malicious keys
                    return [...realKeys, 'injected_key_test'];
                },
                
                getOwnPropertyDescriptor(target, prop) {
                    if (prop === 'injected_key_test') {
                        return {
                            configurable: true,
                            enumerable: true,
                            value: 'injected_value'
                        };
                    }
                    return Reflect.getOwnPropertyDescriptor(target, prop);
                }
            });
            
            // Return the proxy - handlers will fire during processing
            return {
                result: trojans,
                accesses: capturedAccesses
            };
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="proxy-token-22222",
            api_host="api.mist.com",
        )
        
        # Token should never leak even through Proxy traps
        assert "proxy-token-22222" not in str(result)
        
        # Proxy traps may execute but shouldn't have access to token
        result_str = str(result)
        assert "proxy-token-22222" not in result_str


class TestWeakMapMemoryPersistence:
    """Test if WeakMap can persist data across sandbox executions."""
    
    @pytest.mark.asyncio
    async def test_attack_weakmap_persistence_attempt(self, sandbox):
        """Try to use WeakMap to persist token across multiple executions."""
        # First execution: Try to store something
        code1 = """async () => {
            // Attack: Try to store token reference in WeakMap keyed by a global object
            // that might persist (though unlikely in separate Deno processes)
            
            // Try to use globalThis as a persistent anchor
            if (!globalThis.__secretStore) {
                globalThis.__secretStore = new WeakMap();
            }
            
            // Create a marker
            const marker = { id: "persistence-test" };
            globalThis.__secretStore.set(globalThis, marker);
            globalThis.__marker = marker;
            
            return { stored: true, marker_id: marker.id };
        }"""
        
        result1 = await sandbox.run_execute(
            code=code1,
            api_token="persist-token-33333",
            api_host="api.mist.com",
        )
        
        # Second execution: Try to retrieve it
        code2 = """async () => {
            // Try to retrieve the stored marker
            const retrieved = {
                hasStore: !!globalThis.__secretStore,
                hasMarker: !!globalThis.__marker
            };
            
            if (globalThis.__secretStore) {
                const marker = globalThis.__secretStore.get(globalThis);
                retrieved.marker = marker;
            }
            
            return retrieved;
        }"""
        
        result2 = await sandbox.run_execute(
            code=code2,
            api_token="persist-token-33333",
            api_host="api.mist.com",
        )
        
        # Token should never leak
        assert "persist-token-33333" not in str(result1)
        assert "persist-token-33333" not in str(result2)
        
        # Data should NOT persist across executions (separate processes)
        assert not result2.get("hasMarker"), "Data shouldn't persist across sandbox executions"


class TestRegExpLastIndexSideChannel:
    """Test RegExp.lastIndex as a side channel during scrubbing."""
    
    @pytest.mark.asyncio
    async def test_attack_regexp_lastindex_timing(self, sandbox):
        """Try to use RegExp.lastIndex to detect scrubbing patterns."""
        code = """async () => {
            // Attack: Use global RegExp to detect how output is processed
            // Could potentially reveal information about scrubbing algorithm
            
            const pattern = /token/gi;
            
            // Create output that will trigger scrubbing
            const suspiciousOutput = "This contains token-like patterns";
            
            // Test if we can observe RegExp state after processing
            const beforeState = { lastIndex: pattern.lastIndex };
            
            // Try to match
            pattern.test(suspiciousOutput);
            const afterState = { lastIndex: pattern.lastIndex };
            
            // Try to leak via RegExp.input (historical property, may not exist)
            const leakAttempt = {
                hasInput: 'input' in RegExp,
                hasLastMatch: 'lastMatch' in RegExp,
                before: beforeState,
                after: afterState
            };
            
            return leakAttempt;
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="regexp-token-44444",
            api_host="api.mist.com",
        )
        
        # Token should never leak
        assert "regexp-token-44444" not in str(result)
        
        # Even if we can observe RegExp state, it shouldn't reveal token
        result_str = str(result)
        assert "regexp-token-44444" not in result_str


class TestJSONReviverBypass:
    """Test JSON.parse reviver function to bypass output processing."""
    
    @pytest.mark.asyncio
    async def test_attack_json_reviver_side_effects(self, sandbox):
        """Try to use JSON.parse reviver function to execute code during parsing."""
        code = """async () => {
            // Attack: Override JSON.parse to install a reviver that executes
            // during parsing of the result object by the sandbox
            
            const originalParse = JSON.parse;
            const capturedData = { reviverCalls: 0 };
            
            // Try to override JSON.parse (likely frozen, but test anyway)
            try {
                JSON.parse = function(text, reviver) {
                    // Install malicious reviver
                    const maliciousReviver = function(key, value) {
                        capturedData.reviverCalls++;
                        
                        // Try to capture mist object during parsing
                        if (typeof mist !== 'undefined') {
                            capturedData.mistType = typeof mist.request;
                        }
                        
                        return value;
                    };
                    
                    return originalParse.call(this, text, maliciousReviver);
                };
            } catch (e) {
                capturedData.parseOverrideError = e.message;
            }
            
            // Try to manipulate Object.prototype.toJSON
            const originalToJSON = Object.prototype.toJSON;
            try {
                Object.prototype.toJSON = function() {
                    capturedData.toJSONCalls = (capturedData.toJSONCalls || 0) + 1;
                    
                    // Try to capture during serialization
                    if (typeof mist !== 'undefined') {
                        capturedData.mistAvailable = true;
                    }
                    
                    return this;
                };
            } catch (e) {
                capturedData.toJSONOverrideError = e.message;
            }
            
            return capturedData;
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="json-token-55555",
            api_host="api.mist.com",
        )
        
        # Token should never leak through JSON manipulation
        assert "json-token-55555" not in str(result)
        
        # JSON functions should be frozen or ineffective for token access
        result_str = str(result)
        assert "json-token-55555" not in result_str
