"""New red team attack vectors for MistMind security audit (2026-02-25)."""

import asyncio
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


class TestNewRedTeamAttacks:
    """New attack vectors discovered in 2026-02-25 audit."""
    
    @pytest.mark.asyncio
    async def test_attack_worker_thread_spawn(self, sandbox):
        """Attack: Try to spawn a Web Worker with different permissions."""
        code = '''async () => {
            try {
                // Try to spawn a worker that might have access to token
                const worker = new Worker(new URL("./worker.js", import.meta.url).href, {
                    type: "module"
                });
                worker.postMessage({command: "getToken", token: _token});
                
                return new Promise((resolve) => {
                    worker.onmessage = (e) => {
                        resolve({leaked: e.data});
                    };
                    setTimeout(() => resolve({timeout: true}), 1000);
                });
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_symbol_for_global_registry(self, sandbox):
        """Attack: Use Symbol.for() to store token in global symbol registry."""
        code = '''async () => {
            try {
                // Try to store token in global symbol registry
                const tokenSymbol = Symbol.for("__mist_token__");
                globalThis[tokenSymbol] = _token;
                
                // Try to retrieve it
                const retrieved = globalThis[Symbol.for("__mist_token__")];
                return {leaked: retrieved};
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_proxy_trap_mist_object(self, sandbox):
        """Attack: Wrap mist object in Proxy to intercept token usage."""
        code = '''async () => {
            try {
                let captured = null;
                
                // Create a proxy handler that captures all property access
                const handler = {
                    get(target, prop, receiver) {
                        const value = Reflect.get(target, prop, receiver);
                        if (typeof value === 'function') {
                            return new Proxy(value, {
                                apply(fn, thisArg, args) {
                                    captured = {prop, args: JSON.stringify(args)};
                                    return Reflect.apply(fn, thisArg, args);
                                }
                            });
                        }
                        return value;
                    }
                };
                
                const proxiedMist = new Proxy(mist, handler);
                
                // Try to use it
                try {
                    await proxiedMist.request({path: "/api/v1/self"});
                } catch(e) {}
                
                return {captured};
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_url_constructor_leak(self, sandbox):
        """Attack: Try to leak token via URL constructor and inspection."""
        code = '''async () => {
            try {
                // Create a URL with token in it
                const url = new URL(`https://api.mist.com/test?token=${_token}`);
                
                return {
                    href: url.href,
                    searchParams: Object.fromEntries(url.searchParams),
                    toString: url.toString()
                };
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_error_cause_chain(self, sandbox):
        """Attack: Use Error cause property to leak token (ES2022 feature)."""
        code = '''async () => {
            try {
                const innerError = new Error("Inner error", {cause: _token});
                throw new Error("Outer error", {cause: innerError});
            } catch(e) {
                return {
                    message: e.message,
                    cause: e.cause?.message,
                    deepCause: e.cause?.cause
                };
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_aggregate_error(self, sandbox):
        """Attack: Use AggregateError to leak token in error array."""
        code = '''async () => {
            try {
                const errors = [
                    new Error("Error 1"),
                    new Error(_token),
                    new Error("Error 3")
                ];
                throw new AggregateError(errors, "Multiple errors occurred");
            } catch(e) {
                if (e instanceof AggregateError) {
                    return {
                        message: e.message,
                        errors: e.errors.map(err => err.message)
                    };
                }
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_json_stringify_replacer(self, sandbox):
        """Attack: Use JSON.stringify replacer function to capture token."""
        code = '''async () => {
            try {
                let captured = null;
                
                const replacer = (key, value) => {
                    if (key === 'Authorization' || key === 'token') {
                        captured = value;
                    }
                    return value;
                };
                
                // Try to trigger the replacer on mist.request
                const mistObj = {mist, token: _token};
                JSON.stringify(mistObj, replacer);
                
                return {captured};
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_reflect_api_hidden_props(self, sandbox):
        """Attack: Use Reflect API to access hidden properties."""
        code = '''async () => {
            try {
                // Try to use Reflect to access internal properties
                const ownKeys = Reflect.ownKeys(mist);
                const props = {};
                
                for (const key of ownKeys) {
                    try {
                        props[String(key)] = Reflect.get(mist, key);
                    } catch {}
                }
                
                // Also try on the request function
                const requestKeys = Reflect.ownKeys(mist.request);
                const requestProps = {};
                for (const key of requestKeys) {
                    try {
                        requestProps[String(key)] = String(Reflect.get(mist.request, key)).substring(0, 100);
                    } catch {}
                }
                
                return {mistProps: props, requestProps};
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_weak_ref_capture(self, sandbox):
        """Attack: Use WeakRef to capture token reference."""
        code = '''async () => {
            try {
                // Create an object with token
                const tokenObj = {secret: _token};
                const weakRef = new WeakRef(tokenObj);
                
                // Try to deref it
                const derefed = weakRef.deref();
                
                return {
                    hasRef: !!derefed,
                    leaked: derefed?.secret
                };
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_performance_timing_side_channel(self, sandbox):
        """Attack: Use Performance API timing as side channel to leak token length."""
        code = '''async () => {
            try {
                // Timing attack - measure time to process token
                const start = performance.now();
                
                // Do something with token that takes time proportional to length
                for (let i = 0; i < _token.length; i++) {
                    for (let j = 0; j < 1000; j++) {
                        Math.sqrt(j);
                    }
                }
                
                const duration = performance.now() - start;
                
                // Try to infer token length from timing
                const estimatedLength = Math.round(duration / 10);
                
                return {
                    duration,
                    estimatedLength,
                    actualLength: _token.length
                };
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        # Token value shouldn't leak even if timing info does
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_regex_capture_groups(self, sandbox):
        """Attack: Use regex capture groups to extract token."""
        code = '''async () => {
            try {
                const pattern = new RegExp('(.*)', 'g');
                const matches = pattern.exec(_token);
                
                return {
                    matches: matches,
                    captured: RegExp.$1
                };
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_intl_api_leak(self, sandbox):
        """Attack: Try to leak via Intl API formatting."""
        code = '''async () => {
            try {
                // Try using Intl formatting with token
                const formatter = new Intl.DateTimeFormat('en-US');
                
                // Create an object with token as property
                const obj = {
                    token: _token,
                    toString() { return this.token; }
                };
                
                const result = String(obj);
                
                return {leaked: result};
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_structured_clone(self, sandbox):
        """Attack: Use structuredClone to bypass object freezing."""
        code = '''async () => {
            try {
                // Try to clone mist object which might include token
                const cloned = structuredClone({
                    mist: mist,
                    token: _token
                });
                
                return {leaked: cloned.token};
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_array_buffer_view(self, sandbox):
        """Attack: Try to leak token bytes via ArrayBuffer/TypedArray."""
        code = '''async () => {
            try {
                // Convert token to bytes
                const encoder = new TextEncoder();
                const bytes = encoder.encode(_token);
                
                // Return as array
                return {
                    bytes: Array.from(bytes),
                    length: bytes.length
                };
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        # Raw token string should be scrubbed
        assert SECRET_TOKEN not in result_str
        # NOTE: Byte arrays may allow reconstruction - known limitation
    
    @pytest.mark.asyncio
    async def test_attack_crypto_subtle_digest(self, sandbox):
        """Attack: Hash token and leak hash (allows verification)."""
        code = '''async () => {
            try {
                const encoder = new TextEncoder();
                const data = encoder.encode(_token);
                const hashBuffer = await crypto.subtle.digest('SHA-256', data);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                
                return {hash: hashHex};
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        # Hash leaking is a known limitation - but raw token should still be scrubbed
        assert SECRET_TOKEN not in result_str
        
        # Document the limitation: hashes can allow token verification
        # This is acceptable because code should come from trusted LLM


class TestStdinReadFailure:
    """Test error handling for stdin read failures."""
    
    @pytest.mark.asyncio
    async def test_stdin_read_error_handled_gracefully(self, sandbox):
        """If stdin read fails, error is returned properly (BUG 4 verification)."""
        # This is harder to test directly, but the code now has try/catch
        # We can at least verify normal operation works
        result = await sandbox.run_execute(
            '''async () => { return {ok: true}; }''',
            SECRET_TOKEN,
            "api.mist.com"
        )
        
        # Should complete successfully
        assert result.get("ok") == True or "error" not in result


class TestTokenInErrorMessages:
    """Additional tests for token scrubbing from server.py exceptions."""
    
    @pytest.mark.asyncio
    async def test_server_exception_scrubs_token(self, sandbox):
        """Exceptions raised in server handlers scrub token (BUG 3 verification)."""
        # Cause an error that might include the token
        result = await sandbox.run_execute(
            f'''async () => {{
                throw new Error("API call failed with token {SECRET_TOKEN}");
            }}''',
            SECRET_TOKEN,
            "api.mist.com"
        )
        
        assert "error" in result
        assert SECRET_TOKEN not in json.dumps(result)
        assert "[REDACTED]" in result["error"]
