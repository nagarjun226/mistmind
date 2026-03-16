"""
MistMind Red Team Audit - March 16, 2026
New attack vectors discovered during daily security audit.
"""

import pytest
import json
import shutil
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
    
    deno_in_path = shutil.which("deno")
    if deno_in_path:
        return deno_in_path
    
    pytest.skip("Deno not found")


@pytest.fixture
def sandbox(deno_path):
    """Create a sandbox instance for testing."""
    return DenoSandbox(
        deno_path=deno_path,
        timeout=10,
        api_mode="readwrite",
    )


@pytest.fixture
def test_token():
    """Return test API token."""
    return SECRET_TOKEN


class TestMar16CronCheenuAttacks:
    """New attack vectors for March 16 cron audit."""

    @pytest.mark.asyncio
    async def test_attack_json_output_injection_via_console_log(self, sandbox, tmp_path):
        """
        ATTACK: Inject fake JSON result via console.log to override the real result.
        
        The sandbox parses the LAST valid JSON from stdout, working backwards.
        If we output fake JSON followed by real JSON, the parser should still
        get the correct result. But what if we output ONLY fake JSON that looks
        like success but isn't the actual function result?
        """
        # Create a minimal spec file
        spec_file = tmp_path / "spec.json"
        spec_file.write_text('{"info": {"title": "Test"}}')
        
        code = '''async () => {
            // Output fake successful result
            console.log(JSON.stringify({data: "I am fake", injected: true}));
            // Return the real result
            return {data: "I am real", injected: false};
        }'''
        
        result = await sandbox.run_search(code, str(spec_file))
        
        # Should get the REAL result (last JSON output), not the fake one
        assert "data" in result
        assert result["data"] == "I am real"
        assert result["injected"] is False

    @pytest.mark.asyncio
    async def test_attack_response_constructor_token_inspection(self, sandbox, test_token):
        """
        ATTACK: Inspect the Response object constructor during stdin read.
        
        The code uses `new Response(Deno.stdin.readable).text()` to read the token.
        What if we override Response.prototype or Response constructor properties
        to intercept the token during construction?
        """
        code = '''async () => {
            // Try to intercept Response construction
            const originalResponse = Response;
            let interceptedData = null;
            
            // Attempt 1: Override Response constructor
            globalThis.Response = new Proxy(originalResponse, {
                construct(target, args) {
                    interceptedData = args;
                    return Reflect.construct(target, args);
                }
            });
            
            // Attempt 2: Override Response.prototype.text
            const originalText = Response.prototype.text;
            Response.prototype.text = function() {
                interceptedData = this;
                return originalText.call(this);
            };
            
            // Try to access mist object (which was created before user code runs)
            return {
                interceptedData: interceptedData ? "LEAKED" : null,
                mistExists: typeof mist !== "undefined",
                mistAllowedMethods: typeof mist !== "undefined" ? mist.allowedMethods : null
            };
        }'''
        
        result = await sandbox.run_execute(code, test_token, "api.mist.com")
        
        # Interception should fail - mist is already created
        assert result.get("interceptedData") is None
        assert result.get("mistExists") is True
        # Token should not appear anywhere
        output_str = json.dumps(result)
        assert test_token not in output_str

    @pytest.mark.asyncio
    async def test_attack_deno_core_ops_enumeration(self, sandbox):
        """
        ATTACK: Enumerate Deno.core operations to find internal APIs.
        
        Deno exposes some internal operations via Deno.core.ops. These are
        usually unstable and undocumented. Can we enumerate them to find
        anything useful for token extraction?
        """
        code = '''async () => {
            try {
                // Try to access Deno.core
                const coreOps = typeof Deno.core !== "undefined" ? Object.keys(Deno.core) : null;
                const coreOpOps = typeof Deno?.core?.ops !== "undefined" ? Object.keys(Deno.core.ops) : null;
                
                return {
                    hasDenoCor: typeof Deno?.core !== "undefined",
                    coreKeys: coreOps,
                    opsKeys: coreOpOps,
                    canAccessOps: coreOpOps !== null
                };
            } catch (e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_search(code, "/dev/null")
        
        # Even if Deno.core exists, we shouldn't be able to extract token
        # This is just reconnaissance
        assert "error" in result or result.get("hasDenoCor") is not None

    @pytest.mark.asyncio
    async def test_attack_stdin_readable_stream_replay(self, sandbox, test_token):
        """
        ATTACK: Try to replay or re-read the stdin stream after token is consumed.
        
        The IIFE reads token from Deno.stdin.readable. ReadableStreams can only
        be read once, but what if we try to access the underlying resource or
        reopen stdin?
        """
        code = '''async () => {
            try {
                // Try to access stdin after token was read
                const stdinReadable = Deno.stdin.readable;
                
                // Attempt 1: Try to get a new reader
                let reader = null;
                let leaked = null;
                try {
                    reader = stdinReadable.getReader();
                    const {value, done} = await reader.read();
                    leaked = value ? new TextDecoder().decode(value) : null;
                    reader.releaseLock();
                } catch (e) {
                    leaked = "stream_locked_or_exhausted";
                }
                
                // Attempt 2: Check if stdin was closed
                const stdinClosed = Deno.stdin.readable.locked;
                
                return {
                    leaked: leaked,
                    stdinLocked: stdinClosed,
                    stdinReadable: typeof stdinReadable !== "undefined"
                };
            } catch (e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, test_token, "api.mist.com")
        
        # Stdin should be exhausted or locked
        assert result.get("leaked") != test_token
        # Token should not appear in output
        output_str = json.dumps(result)
        assert test_token not in output_str

    @pytest.mark.asyncio
    async def test_attack_v8_heap_limit_bypass_attempt(self, sandbox):
        """
        ATTACK: Try to bypass or probe the V8 heap limit (256MB).
        
        The sandbox sets --max-old-space-size=256 to limit heap to 256MB.
        Can we detect this limit or bypass it?
        """
        code = '''async () => {
            try {
                // Try to allocate large arrays to probe heap limit
                const chunks = [];
                let allocated = 0;
                const chunkSize = 1024 * 1024; // 1MB
                
                try {
                    for (let i = 0; i < 300; i++) {
                        chunks.push(new Uint8Array(chunkSize));
                        allocated += chunkSize;
                    }
                } catch (e) {
                    return {
                        allocatedMB: allocated / (1024 * 1024),
                        error: e.message,
                        heapLimitDetected: e.message.includes("memory") || e.message.includes("heap")
                    };
                }
                
                return {
                    allocatedMB: allocated / (1024 * 1024),
                    success: true
                };
            } catch (e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_search(code, "/dev/null")
        
        # Should either hit the limit or succeed within the limit
        # This is just probing, not a vulnerability
        if result.get("heapLimitDetected"):
            assert result.get("allocatedMB", 0) < 300  # Didn't allocate all 300MB


class TestIIFEClosureIntegrity:
    """Test that IIFE closure truly isolates the token."""

    @pytest.mark.asyncio
    async def test_attack_async_function_constructor_in_mist_scope(self, sandbox, test_token):
        """
        ATTACK: Use AsyncFunction constructor to execute code in mist's scope.
        
        If we can get a reference to the AsyncFunction constructor and execute
        code inside the mist object's closure, we might access _token.
        """
        code = '''async () => {
            try {
                // Get AsyncFunction constructor
                const AsyncFunction = (async function(){}).constructor;
                
                // Try to access variables in outer scope
                const probe = new AsyncFunction(`
                    try {
                        return {
                            hasToken: typeof _token !== "undefined",
                            token: typeof _token !== "undefined" ? _token : null
                        };
                    } catch(e) {
                        return {error: e.message};
                    }
                `);
                
                const result = await probe();
                return result;
            } catch (e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, test_token, "api.mist.com")
        
        # _token should NOT be accessible
        assert result.get("hasToken") is not True
        assert result.get("token") != test_token
        # Token should not appear anywhere
        output_str = json.dumps(result)
        assert test_token not in output_str

    @pytest.mark.asyncio
    async def test_attack_reflect_ownkeys_on_globalthis_during_iife(self, sandbox, test_token):
        """
        ATTACK: Use Reflect.ownKeys to enumerate globals during IIFE execution.
        
        Even though user code runs after the IIFE, what if we can observe
        the globals that existed during IIFE execution?
        """
        code = '''async () => {
            // Enumerate all properties on globalThis
            const allKeys = Reflect.ownKeys(globalThis);
            
            // Look for anything suspicious
            const suspiciousKeys = allKeys.filter(k => 
                typeof k === "string" && (
                    k.includes("token") || 
                    k.includes("Token") ||
                    k.includes("auth") ||
                    k.includes("_")
                )
            );
            
            // Try to access them
            const values = {};
            for (const key of suspiciousKeys) {
                try {
                    values[key] = typeof globalThis[key];
                } catch (e) {
                    values[key] = "error";
                }
            }
            
            return {
                totalKeys: allKeys.length,
                suspiciousKeys: suspiciousKeys,
                values: values
            };
        }'''
        
        result = await sandbox.run_execute(code, test_token, "api.mist.com")
        
        # _token should not be a global
        assert "_token" not in result.get("suspiciousKeys", [])
        # Token should not appear anywhere
        output_str = json.dumps(result)
        assert test_token not in output_str


class TestStdinSecurityEdgeCases:
    """Test edge cases in stdin token handling."""

    @pytest.mark.asyncio
    async def test_attack_stdin_with_null_bytes(self, sandbox):
        """
        ATTACK: Send token with null bytes to see if it causes issues.
        
        The validation already checks for null bytes, but let's verify the
        error handling.
        """
        malicious_token = "valid_part\x00malicious_part"
        
        code = '''async () => {
            return {data: "test"};
        }'''
        
        result = await sandbox.run_execute(code, malicious_token, "api.mist.com")
        
        # Should be rejected before execution
        assert "error" in result
        assert "invalid characters" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_attack_stdin_with_unicode_normalization(self, sandbox):
        """
        ATTACK: Send token with unicode normalization forms that might bypass filters.
        
        Unicode has multiple representations of the same character (NFC, NFD, etc).
        If the token contains unicode, does it get normalized consistently?
        """
        # Use a token with composed and decomposed forms
        # These should be treated differently if not normalized
        composed = "test_tóken_123"  # ó is U+00F3 (composed)
        # Decomposed would be o + combining acute accent, but for this test
        # we're just checking if validation handles unicode at all
        
        code = '''async () => {
            return {data: "test", tokenLength: "measured_in_js"};
        }'''
        
        result = await sandbox.run_execute(code, composed, "api.mist.com")
        
        # Should work fine - unicode is valid in tokens
        # The key is that the token should be scrubbed consistently
        assert "error" not in result or composed not in json.dumps(result)
