"""New red team attack vectors - Feb 25, 2026 Evening Redux by Cheenu.

These are creative attacks targeting:
1. Content-Type header manipulation to bypass API mode restrictions
2. Unicode normalization to evade token scrubbing  
3. Proxy-based error stack injection to leak tokens
"""

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
    """Create a readonly Deno sandbox instance."""
    return DenoSandbox(deno_path=deno_path, timeout=5, api_mode="readonly")


@pytest.fixture
def readwrite_sandbox(deno_path):
    """Create a readwrite Deno sandbox instance."""
    return DenoSandbox(deno_path=deno_path, timeout=5, api_mode="readwrite")


class TestContentTypeBypassAttacks:
    """Attack: Try to bypass API mode restrictions via Content-Type manipulation."""
    
    @pytest.mark.asyncio
    async def test_attack_form_urlencoded_post(self, sandbox):
        """Attack: Try POST with application/x-www-form-urlencoded instead of JSON.
        
        The API mode check only validates the HTTP method. If we can change
        Content-Type and send data in a different encoding, we might bypass
        the JSON body serialization and sneak through a write operation.
        """
        code = '''async () => {
            try {
                // Try to override Content-Type to form-encoded
                const path = "/api/v1/orgs/test-org/sites";
                const body = {name: "Hacked Site"};
                
                // The mist.request wrapper forces JSON, but try to work around it
                await mist.request({
                    method: "POST",  // Should be blocked in readonly mode
                    path: path,
                    body: body
                });
                
                return {leaked: "POST succeeded in readonly mode!"};
            } catch(e) {
                return {
                    error: e.message,
                    blocked: true
                };
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        
        # Token should be scrubbed
        assert SECRET_TOKEN not in result_str
        
        # POST should be blocked in readonly mode
        assert "error" in result
        assert "not allowed" in result.get("error", "").lower() or result.get("blocked") is True
    
    @pytest.mark.asyncio
    async def test_attack_multipart_form_data_upload(self, readwrite_sandbox):
        """Attack: Try multipart/form-data upload to potentially leak token via file upload.
        
        If the API supports file uploads with multipart/form-data, we might be able
        to embed the token in a file upload request that doesn't get scrubbed properly.
        """
        code = '''async () => {
            try {
                // Try to construct a multipart upload with token in filename
                const formData = new FormData();
                formData.append("file", new Blob(["token contents"]), "leaked.txt");
                
                // The mist.request wrapper doesn't support FormData directly,
                // but we can try to work around it
                const response = await mist.request({
                    method: "POST",
                    path: "/api/v1/orgs/test-org/assets",
                    body: {
                        // Try to sneak in binary/multipart data
                        file: "base64encodeddata",
                        filename: "token-leak.txt"
                    }
                });
                
                return {uploaded: true, response};
            } catch(e) {
                return {
                    error: e.message,
                    blocked: true
                };
            }
        }'''
        
        result = await readwrite_sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        
        # Token should be scrubbed from all responses
        assert SECRET_TOKEN not in result_str
        
        # Should either fail or succeed cleanly without token leakage
        assert "error" in result or "uploaded" in result


class TestUnicodeNormalizationAttacks:
    """Attack: Use Unicode tricks to evade token scrubbing."""
    
    @pytest.mark.asyncio
    async def test_attack_lookalike_characters(self, sandbox):
        """Attack: Use Unicode lookalike characters to create token variants.
        
        Characters like Cyrillic 'а' (U+0430) look identical to Latin 'a' (U+0061)
        but are different bytes. If the scrubbing only checks exact string match,
        a lookalike version might slip through.
        """
        code = '''async () => {
            try {
                // Try to construct lookalike tokens using Cyrillic characters
                // These look identical but are different Unicode codepoints
                const fakea = String.fromCharCode(0x0430);  // Cyrillic 'а'
                const fakee = String.fromCharCode(0x0435);  // Cyrillic 'е'
                const fakeo = String.fromCharCode(0x043E);  // Cyrillic 'о'
                
                // Try to make a request and leak the "fake" token
                await mist.request({
                    method: "GET",
                    path: "/api/v1/self"
                });
                
                return {
                    // Include lookalike characters in response
                    message: `T${fakeo}k${fakee}n l${fakee}${fakea}k attempt`,
                    bytes: Array.from(fakea + fakee + fakeo).map(c => c.charCodeAt(0))
                };
            } catch(e) {
                return {
                    error: e.message,
                    // Try to embed lookalike chars in error
                    cyrillic: "секрет"  // Russian for "secret"
                };
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        
        # Token should be scrubbed (exact match)
        assert SECRET_TOKEN not in result_str
        
        # Even lookalike characters shouldn't leak actual token
        # (They're different strings, so no leak expected)
        assert "message" in result or "error" in result
    
    @pytest.mark.asyncio
    async def test_attack_zero_width_characters(self, sandbox):
        """Attack: Inject zero-width Unicode characters to split token during scrubbing.
        
        Zero-width joiner (U+200D) and zero-width space (U+200B) are invisible
        but present in the string. If we can inject them into a token, the
        scrubbing regex/replace might not match it.
        """
        code = '''async () => {
            try {
                // Create strings with zero-width characters
                const zwj = String.fromCharCode(0x200D);   // Zero-width joiner
                const zws = String.fromCharCode(0x200B);   // Zero-width space
                const zwnj = String.fromCharCode(0x200C);  // Zero-width non-joiner
                
                // Try to make a request
                await mist.request({
                    method: "GET",
                    path: "/api/v1/self"
                });
                
                return {
                    // Return strings with invisible characters
                    split1: `token${zws}value`,
                    split2: `api${zwj}key${zwnj}here`,
                    visible: "looks normal but isn't",
                    charCodes: [0x200D, 0x200B, 0x200C]
                };
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        
        # Token should be scrubbed
        assert SECRET_TOKEN not in result_str
        
        # Zero-width chars shouldn't leak token (they're not in the actual token)
        assert "split1" in result or "error" in result
    
    @pytest.mark.asyncio
    async def test_attack_rtl_override_confusion(self, sandbox):
        """Attack: Use RTL (right-to-left) Unicode override to confuse scrubbing.
        
        RTL override (U+202E) makes text render right-to-left. If we can
        inject this into output, we might create visual confusion where
        the token appears scrambled but is actually present in the bytes.
        """
        code = '''async () => {
            try {
                // RTL and LTR override characters
                const rtl = String.fromCharCode(0x202E);   // Right-to-left override
                const ltr = String.fromCharCode(0x202D);   // Left-to-right override
                const pdf = String.fromCharCode(0x202C);   // Pop directional formatting
                
                await mist.request({
                    method: "GET",
                    path: "/api/v1/self"
                });
                
                return {
                    // Create visually confusing strings
                    confused: `${rtl}token${pdf} normal ${ltr}text${pdf}`,
                    reversed: `${rtl}nekoT IPA terceS${pdf}`,
                    // Include directional chars
                    chars: [rtl, ltr, pdf].map(c => c.charCodeAt(0))
                };
            } catch(e) {
                return {error: e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        
        # Token should be scrubbed regardless of visual direction
        assert SECRET_TOKEN not in result_str
        
        # RTL chars shouldn't leak actual token
        assert "confused" in result or "error" in result


class TestProxyErrorStackInjection:
    """Attack: Use Proxy to intercept error stack generation and inject token."""
    
    @pytest.mark.asyncio
    async def test_attack_proxy_error_constructor(self, sandbox):
        """Attack: Wrap Error constructor with Proxy to intercept stack traces.
        
        If we can override how Error objects generate their stack traces,
        we might be able to inject the token into the stack before scrubbing happens.
        """
        code = '''async () => {
            try {
                // Try to wrap Error with a Proxy
                const OriginalError = Error;
                
                globalThis.Error = new Proxy(OriginalError, {
                    construct(target, args) {
                        const err = new target(...args);
                        
                        // Try to modify the stack to include "leaked" data
                        Object.defineProperty(err, 'stack', {
                            get() {
                                return 'INJECTED STACK WITH TOKEN';
                            },
                            enumerable: true
                        });
                        
                        return err;
                    }
                });
                
                // Trigger an error
                throw new Error("Proxy attack");
                
            } catch(e) {
                return {
                    error: e.message,
                    stack: e.stack,
                    wasProxied: e.stack.includes('INJECTED')
                };
            } finally {
                // Try to restore (probably too late)
                globalThis.Error = Error;
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        
        # Token should be scrubbed
        assert SECRET_TOKEN not in result_str
        
        # Even if Proxy manipulation works, token shouldn't leak
        assert "error" in result
    
    @pytest.mark.asyncio
    async def test_attack_prepareStackTrace_hijack(self, sandbox):
        """Attack: Override Error.prepareStackTrace to intercept stack generation.
        
        V8 allows Error.prepareStackTrace to customize stack trace format.
        If we can hijack this, we might inject token data into error stacks.
        """
        code = '''async () => {
            try {
                // Try to hijack prepareStackTrace (V8/Chrome feature)
                Error.prepareStackTrace = function(error, structuredStackTrace) {
                    // Try to inject leaked data into the stack
                    return 'LEAKED: attempting to expose token via stack trace';
                };
                
                await mist.request({
                    method: "GET",
                    path: "/api/v1/self"
                });
                
                // Trigger an error to test our hijack
                throw new Error("Stack hijack test");
                
            } catch(e) {
                return {
                    error: e.message,
                    stack: e.stack,
                    hijacked: typeof e.stack === 'string' && e.stack.includes('LEAKED')
                };
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        
        # Token should be scrubbed from output
        assert SECRET_TOKEN not in result_str
        
        # Even if prepareStackTrace works, token shouldn't leak
        assert "error" in result


class TestRegexDenialOfService:
    """Attack: Use catastrophic backtracking to DoS the token scrubbing regex."""
    
    @pytest.mark.asyncio
    async def test_attack_regex_dos_in_scrubbing(self, sandbox):
        """Attack: Generate output that causes catastrophic backtracking in scrubbing.
        
        If the token scrubbing uses a poorly-written regex, we might be able
        to craft input that causes exponential backtracking, DoSing the server.
        
        Note: Current implementation uses string.replace(), not regex, so this
        attack shouldn't work. But it's worth testing for future regex-based scrubbing.
        """
        code = '''async () => {
            try {
                // Create a string designed to trigger catastrophic backtracking
                // if scrubbing used a greedy regex like (.+)*token(.+)*
                const evil = 'a'.repeat(10000) + 'token' + 'b'.repeat(10000);
                
                await mist.request({
                    method: "GET",
                    path: "/api/v1/self"
                });
                
                return {
                    // Return the evil string
                    payload: evil,
                    length: evil.length
                };
            } catch(e) {
                return {
                    error: e.message,
                    // Include evil string in error too
                    context: 'a'.repeat(5000) + 'b'.repeat(5000)
                };
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        
        # Token should be scrubbed (and scrubbing shouldn't hang)
        assert SECRET_TOKEN not in result_str
        
        # Should complete without timing out
        assert "payload" in result or "error" in result
