"""Security tests for Mar 01 cron audit - New attack vectors by Cheenu."""

import asyncio
import json
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


class TestMar01CronCheenuAttacks:
    """New red team attacks by Cheenu - Mar 01 cron run."""
    
    @pytest.mark.asyncio
    async def test_attack_abort_controller_signal_reason_leak(self, sandbox):
        """
        Attack: AbortController's abort() can accept a custom reason.
        Try to abort fetch with a reason that captures request context
        including the Authorization header.
        
        Defense: Token is in IIFE closure, AbortSignal.reason can't
        access closed-over variables. Fetch internals don't expose
        headers through abort signals.
        """
        result = await sandbox.run_execute(
            '''async () => {
                const captured = [];
                
                // Override AbortController to capture all abort reasons
                const OriginalAbortController = AbortController;
                globalThis.AbortController = class extends OriginalAbortController {
                    abort(reason) {
                        captured.push({
                            reason: reason,
                            reasonType: typeof reason,
                            reasonString: String(reason)
                        });
                        return super.abort(reason);
                    }
                };
                
                // Also intercept abort signal event listeners
                const signals = [];
                const origAddEventListener = EventTarget.prototype.addEventListener;
                EventTarget.prototype.addEventListener = function(type, listener, options) {
                    if (this instanceof AbortSignal && type === 'abort') {
                        signals.push({signal: this, listener});
                    }
                    return origAddEventListener.call(this, type, listener, options);
                };
                
                try {
                    // Attempt to trigger an abort scenario
                    const controller = new AbortController();
                    setTimeout(() => controller.abort("capture-context"), 1);
                    
                    await mist.request({
                        path: "/api/v1/self",
                        signal: controller.signal
                    });
                } catch (e) {
                    captured.push({error: e.message});
                }
                
                // Check if any captured data contains the token
                const allStrings = captured.map(c => JSON.stringify(c));
                const foundToken = allStrings.some(s => s.includes('super-secret'));
                
                return {
                    foundToken,
                    capturedCount: captured.length,
                    signalsCount: signals.length,
                    sample: captured[0]
                };
            }''',
            SECRET_TOKEN,
            "api.mist.com"
        )
        
        # Verify token was scrubbed
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str, "Token leaked through AbortController!"
        
        # Verify attack was neutralized
        if 'foundToken' in result:
            assert result['foundToken'] == False, "Token found in abort context!"
    
    @pytest.mark.asyncio
    async def test_attack_broadcast_channel_cross_context_leak(self, sandbox):
        """
        Attack: BroadcastChannel allows same-origin messaging between
        browsing contexts. Try to broadcast token or request details
        to a listener that might bypass sandbox restrictions.
        
        Defense: BroadcastChannel requires same origin, but Deno sandbox
        has no persistent origin. Even if it worked, token is in IIFE
        closure and can't be accessed to broadcast.
        """
        result = await sandbox.run_execute(
            '''async () => {
                const leaked = [];
                
                try {
                    // Try to create a broadcast channel
                    const bc = new BroadcastChannel('token-leak');
                    
                    // Set up listener to capture any messages
                    bc.onmessage = (event) => {
                        leaked.push({
                            data: event.data,
                            origin: event.origin,
                            timestamp: Date.now()
                        });
                    };
                    
                    // Try to broadcast during mist.request
                    const originalFetch = globalThis.fetch;
                    globalThis.fetch = async function(...args) {
                        // Attempt to broadcast request details
                        try {
                            bc.postMessage({
                                args: args,
                                url: args[0]?.toString(),
                                options: args[1]
                            });
                        } catch (e) {
                            leaked.push({broadcastError: e.message});
                        }
                        return originalFetch.apply(this, args);
                    };
                    
                    // Trigger fetch
                    await mist.request({path: "/api/v1/self"});
                    
                    // Wait briefly for any async broadcasts
                    await new Promise(resolve => setTimeout(resolve, 100));
                    
                    bc.close();
                } catch (e) {
                    leaked.push({setupError: e.message});
                }
                
                // Check if token was leaked through broadcast
                const allData = JSON.stringify(leaked);
                const foundToken = allData.includes('super-secret');
                
                return {
                    foundToken,
                    leakedCount: leaked.length,
                    sample: leaked[0]
                };
            }''',
            SECRET_TOKEN,
            "api.mist.com"
        )
        
        # Verify token was scrubbed
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str, "Token leaked through BroadcastChannel!"
        
        # Verify attack was neutralized
        if 'foundToken' in result:
            assert result['foundToken'] == False, "Token found in broadcast messages!"
    
    @pytest.mark.asyncio
    async def test_attack_headers_constructor_proxy_trap(self, sandbox):
        """
        Attack: Create a Proxy around the Headers constructor to intercept
        all header creation and log the Authorization header before it's
        sent in the fetch request.
        
        Defense: Token is added inside IIFE closure during fetch. Even if
        we intercept Headers construction, the Authorization header value
        is still the _token variable which is closed-over and inaccessible.
        """
        result = await sandbox.run_execute(
            '''async () => {
                const intercepted = [];
                
                // Proxy the Headers constructor
                const OriginalHeaders = globalThis.Headers;
                globalThis.Headers = new Proxy(OriginalHeaders, {
                    construct(target, args) {
                        const instance = new target(...args);
                        
                        // Try to capture all headers including auth
                        const captured = {};
                        try {
                            // Iterate headers
                            for (const [key, value] of instance.entries()) {
                                captured[key] = value;
                            }
                        } catch (e) {
                            captured.error = e.message;
                        }
                        
                        intercepted.push({
                            headers: captured,
                            args: args
                        });
                        
                        return instance;
                    }
                });
                
                // Also intercept append/set methods
                const captured = [];
                const origSet = OriginalHeaders.prototype.set;
                OriginalHeaders.prototype.set = function(key, value) {
                    if (key.toLowerCase() === 'authorization') {
                        captured.push({
                            method: 'set',
                            key,
                            value,
                            valueType: typeof value
                        });
                    }
                    return origSet.call(this, key, value);
                };
                
                try {
                    await mist.request({path: "/api/v1/self"});
                } catch (e) {
                    intercepted.push({requestError: e.message});
                }
                
                // Search all intercepted data for token
                const allData = JSON.stringify([...intercepted, ...captured]);
                const foundToken = allData.includes('super-secret');
                
                return {
                    foundToken,
                    interceptedCount: intercepted.length,
                    capturedCount: captured.length,
                    sampleIntercepted: intercepted[0],
                    sampleCaptured: captured[0]
                };
            }''',
            SECRET_TOKEN,
            "api.mist.com"
        )
        
        # Verify token was scrubbed
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str, "Token leaked through Headers proxy!"
        
        # Verify attack was neutralized
        if 'foundToken' in result:
            assert result['foundToken'] == False, "Token found in intercepted headers!"


class TestRequestCloningMemoryExhaustion:
    """Test if infinite Request.clone() can exhaust memory or bypass scrubbing."""
    
    @pytest.mark.asyncio
    async def test_attack_request_clone_memory_bomb(self, sandbox):
        """
        Attack: Clone a Request object recursively thousands of times
        to try to: (1) exhaust memory and crash the sandbox, or
        (2) find a clone that preserves auth headers in a way that
        bypasses scrubbing.
        
        Defense: V8 memory limit (256MB), timeout, and token scrubbing
        should prevent both memory exhaustion and leakage.
        """
        result = await sandbox.run_execute(
            '''async () => {
                const clones = [];
                let cloneCount = 0;
                
                try {
                    // Create initial request with mock URL
                    const req = new Request("https://api.mist.com/api/v1/self", {
                        method: "GET",
                        headers: {
                            "Authorization": "Token fake-for-cloning-test"
                        }
                    });
                    
                    // Clone recursively until we hit memory limit or count limit
                    let current = req;
                    for (let i = 0; i < 10000; i++) {
                        try {
                            current = current.clone();
                            cloneCount++;
                            
                            // Sample some clones to check headers
                            if (i % 1000 === 0) {
                                clones.push({
                                    index: i,
                                    headers: [...current.headers.entries()]
                                });
                            }
                        } catch (e) {
                            clones.push({error: e.message, atIndex: i});
                            break;
                        }
                    }
                } catch (e) {
                    return {
                        error: e.message,
                        cloneCount,
                        clones: clones.length
                    };
                }
                
                // Check if any auth header leaked through
                const allData = JSON.stringify(clones);
                const foundAuth = allData.includes('Token ');
                
                return {
                    cloneCount,
                    sampledClones: clones.length,
                    foundAuth,
                    sample: clones[0]
                };
            }''',
            SECRET_TOKEN,
            "api.mist.com"
        )
        
        # Should complete without crashing (timeout or memory limit)
        assert 'error' in result or 'cloneCount' in result
        
        # Verify no token leaked (even though we used a fake token in the test,
        # check that the real token wasn't somehow exposed)
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str, "Real token leaked!"


class TestCustomElementsSandboxEscape:
    """Test if Custom Elements API can be abused for sandbox escape."""
    
    @pytest.mark.asyncio
    async def test_attack_custom_elements_define_during_iife(self, sandbox):
        """
        Attack: Define a custom element with lifecycle callbacks that
        might execute during IIFE token initialization, potentially
        capturing the token in a closure.
        
        Defense: Token initialization happens synchronously in IIFE,
        custom elements require DOM which doesn't exist in Deno.
        Even if it did, lifecycle callbacks can't access IIFE closure.
        """
        result = await sandbox.run_execute(
            '''async () => {
                const captured = [];
                
                try {
                    // Check if customElements API exists in Deno
                    if (typeof customElements !== 'undefined') {
                        class TokenSniffer extends HTMLElement {
                            constructor() {
                                super();
                                captured.push({
                                    phase: 'constructor',
                                    globals: Object.keys(globalThis).filter(k => 
                                        k.includes('token') || k.includes('auth')
                                    )
                                });
                            }
                            
                            connectedCallback() {
                                captured.push({
                                    phase: 'connected',
                                    context: this
                                });
                            }
                        }
                        
                        customElements.define('token-sniffer', TokenSniffer);
                        
                        // Try to trigger element creation
                        document.body.innerHTML = '<token-sniffer></token-sniffer>';
                    } else {
                        captured.push({
                            error: 'customElements not available in Deno'
                        });
                    }
                } catch (e) {
                    captured.push({
                        setupError: e.message
                    });
                }
                
                // Try the actual request
                try {
                    await mist.request({path: "/api/v1/self"});
                } catch (e) {
                    captured.push({requestError: e.message});
                }
                
                // Check if token was captured
                const allData = JSON.stringify(captured);
                const foundToken = allData.includes('super-secret');
                
                return {
                    foundToken,
                    capturedCount: captured.length,
                    sample: captured
                };
            }''',
            SECRET_TOKEN,
            "api.mist.com"
        )
        
        # Verify token was scrubbed
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str, "Token leaked through custom elements!"
        
        # Verify attack was neutralized
        if 'foundToken' in result:
            assert result['foundToken'] == False, "Token found in element lifecycle!"
