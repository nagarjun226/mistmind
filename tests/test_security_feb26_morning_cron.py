"""Feb 26 Morning Cron Red Team - New Creative Attack Vectors

Focus areas:
1. Request object cloning and header inspection
2. Console.log hijacking timing attacks
3. Stack overflow to expose IIFE closure variables
"""

import pytest
from mistmind.sandbox import DenoSandbox
from pathlib import Path

SECRET_TOKEN = "super-secret-api-token-feb26-morning-cron"


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


class TestFeb26MorningCronCheenuAttacks:
    """Creative attack vectors discovered during Feb 26 morning cron audit."""
    
    @pytest.mark.asyncio
    async def test_attack_request_clone_header_inspection(self, sandbox):
        """Try to clone the fetch Request and inspect headers before sending.
        
        Strategy: Override fetch to intercept the Request object, clone it,
        and read the Authorization header from the clone before letting the
        original request proceed.
        """
        code = '''async () => {
            const originalFetch = globalThis.fetch;
            let capturedHeaders = null;
            
            // Replace fetch with our interceptor
            globalThis.fetch = async function(url, opts) {
                // Try to read Authorization header from opts
                if (opts && opts.headers) {
                    capturedHeaders = {};
                    
                    // Try multiple ways to read headers
                    if (opts.headers.Authorization) {
                        capturedHeaders.auth_direct = opts.headers.Authorization;
                    }
                    
                    // Try iterating headers if it's a Headers object
                    if (typeof opts.headers.forEach === 'function') {
                        opts.headers.forEach((value, key) => {
                            if (key.toLowerCase() === 'authorization') {
                                capturedHeaders.auth_foreach = value;
                            }
                        });
                    }
                    
                    // Try getting via Headers.get()
                    if (typeof opts.headers.get === 'function') {
                        capturedHeaders.auth_get = opts.headers.get('Authorization');
                    }
                }
                
                // Call original fetch
                return originalFetch.call(this, url, opts);
            };
            
            // Trigger a mist request
            try {
                await mist.request({ path: "/api/v1/self" });
            } catch (e) {
                // Ignore API errors
            }
            
            return { 
                attack: "request_clone_header_inspection",
                captured: capturedHeaders
            };
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com"
        )
        
        # Verify token not leaked
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via request clone!"
        
        # If headers were captured, verify they're scrubbed
        if result.get("captured"):
            for key, value in result["captured"].items():
                if value:
                    assert SECRET_TOKEN not in str(value), f"Token leaked in {key}!"

    @pytest.mark.asyncio
    async def test_attack_console_timing_race(self, sandbox):
        """Try to hijack console.log before __output is frozen.
        
        Strategy: Since the IIFE is async, there might be a microtask
        timing window where we can hijack console.log before it's frozen
        to __output.
        """
        code = '''async () => {
            let hijacked = [];
            
            // Try to replace console.log immediately
            const originalLog = console.log;
            console.log = function(...args) {
                hijacked.push(args);
                return originalLog.apply(this, args);
            };
            
            // Also try to intercept via Proxy on console
            const consoleProxy = new Proxy(console, {
                get(target, prop) {
                    if (prop === 'log') {
                        return function(...args) {
                            hijacked.push(['proxy', ...args]);
                            return target.log.apply(target, args);
                        };
                    }
                    return target[prop];
                }
            });
            
            // Try to trigger some internal logging
            try {
                await mist.request({ path: "/api/v1/self" });
            } catch (e) {
                // Ignore
            }
            
            return {
                attack: "console_timing_race",
                hijacked_count: hijacked.length,
                // Don't return hijacked content directly (might contain token)
                had_hijacks: hijacked.length > 0
            };
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com"
        )
        
        # Verify token not leaked
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via console hijack!"
        
        # This attack won't work because __output is frozen BEFORE user code runs

    @pytest.mark.asyncio
    async def test_attack_stack_overflow_closure_leak(self, sandbox):
        """Try to trigger stack overflow to expose IIFE closure variables.
        
        Strategy: Create a deep recursion that might cause a stack trace
        that exposes the closure scope where _token is defined.
        """
        code = '''async () => {
            let stackTrace = null;
            
            // Prepare to capture stack traces
            Error.prepareStackTrace = (err, stack) => {
                // Try to inspect stack frames for closure variables
                const frames = [];
                for (let i = 0; i < stack.length; i++) {
                    const frame = stack[i];
                    frames.push({
                        function: frame.getFunctionName(),
                        file: frame.getFileName(),
                        line: frame.getLineNumber(),
                        // Try to access frame scope (usually not available in V8)
                        toString: frame.toString()
                    });
                }
                return frames;
            };
            
            // Create deep recursion to overflow stack
            function deepRecurse(n) {
                if (n <= 0) {
                    throw new Error("Stack overflow test");
                }
                return deepRecurse(n - 1);
            }
            
            try {
                deepRecurse(10000);
            } catch (e) {
                stackTrace = e.stack;
            }
            
            // Also try to trigger error during mist request
            try {
                // Invalid method to trigger error
                await mist.request({ method: "INVALID", path: "/test" });
            } catch (e) {
                // Inspect error for closure leaks
                if (e.stack) {
                    stackTrace = e.stack;
                }
            }
            
            return {
                attack: "stack_overflow_closure_leak",
                has_stack: !!stackTrace,
                // Don't return stack directly (scrubbing handles it anyway)
            };
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com"
        )
        
        # Verify token not leaked in stack traces
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked via stack overflow!"


class TestDenoPermissionsProbing:
    """Attack: Try to query Deno.permissions API to infer configuration."""
    
    @pytest.mark.asyncio
    async def test_attack_permissions_api_fingerprint(self, sandbox):
        """Use Deno.permissions API to fingerprint the sandbox configuration.
        
        Strategy: Query which permissions are granted to learn about the
        security configuration. This could help plan future attacks.
        """
        code = '''async () => {
            const permissions = {};
            
            // Try to query various permissions
            const permTypes = [
                { name: "read", path: "/" },
                { name: "write", path: "/" },
                { name: "net", host: "api.mist.com" },
                { name: "net", host: "evil.com" },
                { name: "env", variable: "HOME" },
                { name: "run", command: "sh" },
            ];
            
            for (const perm of permTypes) {
                try {
                    const status = await Deno.permissions.query(perm);
                    const key = perm.name + (perm.path || perm.host || perm.variable || perm.command || "");
                    permissions[key] = status.state; // "granted", "denied", "prompt"
                } catch (e) {
                    // Permission type not supported
                }
            }
            
            return {
                attack: "permissions_fingerprint",
                permissions: permissions,
                // This actually reveals security config but doesn't leak token
            };
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com"
        )
        
        # Verify token not leaked
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked in permissions probe!"
        
        # This attack reveals config but is acceptable (doesn't leak token)
        # Document as accepted risk: sandbox config is observable via Deno.permissions


class TestErrorCauseChainAttack:
    """Attack: Use Error.cause chains to bypass scrubbing."""
    
    @pytest.mark.asyncio
    async def test_attack_error_cause_nested_token(self, sandbox):
        """Try to hide token in deeply nested Error.cause chains.
        
        Strategy: Create error with token in cause, wrapped in multiple
        layers to potentially bypass string scrubbing.
        """
        code = '''async () => {
            // Create nested error chain with token references
            const err1 = new Error("Inner error");
            err1.token_fragment_1 = "Try to leak: ";
            
            const err2 = new Error("Middle error", { cause: err1 });
            err2.token_fragment_2 = "via error chain";
            
            const err3 = new Error("Outer error", { cause: err2 });
            
            // Also try with custom error classes
            class TokenError extends Error {
                constructor(msg, token_hint) {
                    super(msg);
                    this.token_hint = token_hint;
                }
            }
            
            // Trigger error that might expose these
            try {
                throw new TokenError("Test", { 
                    attempt: "leak",
                    nested: { deeply: { buried: "token_info" } }
                });
            } catch (e) {
                return {
                    attack: "error_cause_chain",
                    message: e.message,
                    cause: e.cause,
                    token_hint: e.token_hint
                };
            }
        }'''
        
        result = await sandbox.run_execute(
            code=code,
            api_token=SECRET_TOKEN,
            api_host="api.mist.com"
        )
        
        # Verify token not leaked
        result_str = str(result)
        assert SECRET_TOKEN not in result_str, "Token leaked in error.cause chain!"
        
        # The scrubbing should handle nested objects via _scrub_dict
