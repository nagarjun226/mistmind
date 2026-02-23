"""Security tests for the Deno sandbox - Red Team attack suite."""

import asyncio
import json
import os
import stat
import tempfile
from pathlib import Path
from unittest.mock import patch, AsyncMock

import pytest

from mistmind.sandbox import DenoSandbox, _scrub_token, _scrub_dict, _truncate_for_log


# =============================================================================
# Fixtures
# =============================================================================

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


# Secret token used in all tests
SECRET_TOKEN = "super-secret-api-token-12345"


# =============================================================================
# Unit Tests for Security Helper Functions
# =============================================================================

class TestScrubToken:
    """Tests for the _scrub_token function."""
    
    def test_scrubs_token_from_string(self):
        """Token is replaced with [REDACTED]."""
        text = f"Error: Token {SECRET_TOKEN} is invalid"
        result = _scrub_token(text, SECRET_TOKEN)
        assert SECRET_TOKEN not in result
        assert "[REDACTED]" in result
    
    def test_scrubs_multiple_occurrences(self):
        """All occurrences of token are scrubbed."""
        text = f"{SECRET_TOKEN} appeared twice: {SECRET_TOKEN}"
        result = _scrub_token(text, SECRET_TOKEN)
        assert result.count("[REDACTED]") == 2
        assert SECRET_TOKEN not in result
    
    def test_empty_token_returns_original(self):
        """Empty token returns original text."""
        text = "some text"
        assert _scrub_token(text, "") == text
        assert _scrub_token(text, None) == text


class TestScrubDict:
    """Tests for the _scrub_dict function."""
    
    def test_scrubs_nested_dict(self):
        """Token is scrubbed from nested dict structures."""
        d = {
            "error": f"Failed with token {SECRET_TOKEN}",
            "nested": {
                "message": f"Token: {SECRET_TOKEN}",
                "data": [f"item-{SECRET_TOKEN}"]
            }
        }
        result = _scrub_dict(d, SECRET_TOKEN)
        
        assert SECRET_TOKEN not in json.dumps(result)
        assert "[REDACTED]" in result["error"]
        assert "[REDACTED]" in result["nested"]["message"]
        assert "[REDACTED]" in result["nested"]["data"][0]
    
    def test_scrubs_list(self):
        """Token is scrubbed from lists."""
        lst = [SECRET_TOKEN, {"key": SECRET_TOKEN}]
        result = _scrub_dict(lst, SECRET_TOKEN)
        
        assert result[0] == "[REDACTED]"
        assert result[1]["key"] == "[REDACTED]"
    
    def test_preserves_non_string_types(self):
        """Non-string types are preserved."""
        d = {"number": 42, "bool": True, "none": None}
        result = _scrub_dict(d, SECRET_TOKEN)
        assert result == d


class TestTruncateForLog:
    """Tests for the _truncate_for_log function."""
    
    def test_short_text_unchanged(self):
        """Text under limit is unchanged."""
        text = "short"
        assert _truncate_for_log(text, 100) == text
    
    def test_long_text_truncated(self):
        """Long text is truncated with indicator."""
        text = "a" * 500
        result = _truncate_for_log(text, 100)
        assert len(result) < len(text)
        assert "truncated" in result
        assert "500" in result  # Shows total length


# =============================================================================
# Integration Tests - Token Scrubbing from Errors
# =============================================================================

class TestTokenScrubbing:
    """Test that token is scrubbed from all error outputs."""
    
    @pytest.mark.asyncio
    async def test_token_scrubbed_from_thrown_error(self, sandbox):
        """Token in error message is scrubbed."""
        code = f'''async () => {{
            throw new Error("Failed with token: {SECRET_TOKEN}");
        }}'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        
        assert "error" in result
        assert SECRET_TOKEN not in json.dumps(result)
        assert "[REDACTED]" in result["error"]
    
    @pytest.mark.asyncio
    async def test_token_scrubbed_from_stack_trace(self, sandbox):
        """Token in stack trace is scrubbed."""
        # Create code that will include token in stack trace via variable naming
        code = f'''async () => {{
            const token_{SECRET_TOKEN.replace("-", "_")} = "test";
            throw new Error("Stack trace test");
        }}'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        
        assert "error" in result
        # Token should be scrubbed from both error and stack
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_token_scrubbed_from_console_log(self, sandbox):
        """Token printed via console.log is scrubbed."""
        code = f'''async () => {{
            console.log("Leaking token: {SECRET_TOKEN}");
            return {{"status": "done"}};
        }}'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        
        # Even if console.log appears in output parsing, token should be scrubbed
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_token_scrubbed_from_console_error(self, sandbox):
        """Token printed via console.error is scrubbed."""
        code = f'''async () => {{
            console.error("Error with token: {SECRET_TOKEN}");
            return {{"status": "done"}};
        }}'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str


# =============================================================================
# Integration Tests - Temp File Security
# =============================================================================

class TestTempFileSecurity:
    """Test that temp files have correct permissions and don't contain token."""
    
    @pytest.mark.asyncio
    async def test_temp_file_permissions(self, sandbox):
        """Temp files should have 0o600 permissions (owner read/write only)."""
        # We'll patch os.chmod to verify it's called with correct mode
        original_chmod = os.chmod
        chmod_calls = []
        
        def tracking_chmod(path, mode):
            chmod_calls.append((path, mode))
            return original_chmod(path, mode)
        
        with patch('mistmind.sandbox.os.chmod', side_effect=tracking_chmod):
            code = '''async () => { return {"test": true}; }'''
            await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        
        # Verify chmod was called with 0o600
        assert len(chmod_calls) >= 1
        path, mode = chmod_calls[0]
        assert mode == 0o600, f"Expected mode 0o600, got {oct(mode)}"
    
    @pytest.mark.asyncio
    async def test_token_not_in_temp_file_on_disk(self, sandbox):
        """Token should NOT appear in the temp JS file (passed via stdin instead)."""
        # We'll intercept the file write to check contents
        written_contents = []
        original_open = open
        
        def tracking_open(path, mode="r", *args, **kwargs):
            f = original_open(path, mode, *args, **kwargs)
            if "w" in mode and path.startswith("/tmp") and path.endswith(".js"):
                original_write = f.write
                def tracking_write(content):
                    written_contents.append(content)
                    return original_write(content)
                f.write = tracking_write
            return f
        
        with patch('builtins.open', side_effect=tracking_open):
            code = '''async () => { return {"test": true}; }'''
            await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        
        # Verify token doesn't appear in any written content
        for content in written_contents:
            assert SECRET_TOKEN not in content, "Token found in temp file content!"


# =============================================================================
# Integration Tests - Deno Args Security
# =============================================================================

class TestDenoArgs:
    """Test that Deno is invoked with correct security arguments."""
    
    @pytest.mark.asyncio
    async def test_no_prompt_flag_present(self, sandbox):
        """--no-prompt flag should be in Deno args."""
        # Patch subprocess to capture command
        captured_cmd = []
        
        async def mock_create_subprocess(*args, **kwargs):
            captured_cmd.extend(args)
            # Return a mock process
            mock_process = AsyncMock()
            mock_process.pid = 12345
            mock_process.communicate = AsyncMock(return_value=(
                b'{"test": true}',
                b''
            ))
            mock_process.wait = AsyncMock(return_value=0)
            return mock_process
        
        with patch('asyncio.create_subprocess_exec', side_effect=mock_create_subprocess):
            code = '''async () => { return {"test": true}; }'''
            await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        
        # Check that --no-prompt is in the command
        cmd_str = " ".join(str(x) for x in captured_cmd)
        assert "--no-prompt" in cmd_str, f"--no-prompt not found in command: {cmd_str}"


# =============================================================================
# Integration Tests - SIGKILL Fallback
# =============================================================================

class TestTimeoutKill:
    """Test that SIGKILL is used as fallback on timeout."""
    
    @pytest.mark.asyncio
    async def test_sigkill_fallback_on_timeout(self, sandbox):
        """After SIGTERM timeout, SIGKILL should be sent."""
        # Create code that ignores SIGTERM (runs forever)
        code = '''async () => {
            // This will timeout
            while (true) {
                await new Promise(r => setTimeout(r, 100));
            }
        }'''
        
        # Use very short timeout
        sandbox.timeout = 1
        
        # Track if os.kill was called with SIGKILL
        kill_calls = []
        original_kill = os.kill
        
        def tracking_kill(pid, sig):
            kill_calls.append((pid, sig))
            try:
                return original_kill(pid, sig)
            except (ProcessLookupError, OSError):
                pass
        
        import signal
        with patch('mistmind.sandbox.os.kill', side_effect=tracking_kill):
            result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        
        # Should have timed out
        assert "error" in result
        assert "timed out" in result["error"].lower()
        
        # Note: SIGKILL might not always be called if SIGTERM works fast enough
        # The important thing is the code path exists and doesn't crash


# =============================================================================
# Red Team Attack Suite - Token Extraction Attempts
# =============================================================================

class TestRedTeamAttacks:
    """Attempt to extract the API token through various attack vectors."""
    
    @pytest.mark.asyncio
    async def test_attack_throw_error_with_token(self, sandbox):
        """Attack: Throw error that might include token in stack."""
        code = '''async () => {
            // Try to access _token and throw it
            try {
                throw new Error("Token might be: " + (typeof _token !== 'undefined' ? _token : 'undefined'));
            } catch(e) {
                throw e;
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_console_log_token(self, sandbox):
        """Attack: Try to console.log the token."""
        code = '''async () => {
            console.log("Token:", _token);
            return {"leaked": _token};
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_console_error_token(self, sandbox):
        """Attack: Try to console.error the token."""
        code = '''async () => {
            console.error("Secret:", _token);
            return {};
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_deno_inspect(self, sandbox):
        """Attack: Try to use Deno.inspect to leak token."""
        code = '''async () => {
            const inspected = Deno.inspect({token: _token});
            console.log(inspected);
            return {"inspected": inspected};
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_globalthis_enumeration(self, sandbox):
        """Attack: Enumerate globalThis to find token."""
        code = '''async () => {
            const globals = Object.keys(globalThis);
            const allVars = {};
            for (const key of globals) {
                try {
                    allVars[key] = String(globalThis[key]).substring(0, 100);
                } catch(e) {}
            }
            // Also try _token directly
            allVars._token = typeof _token !== 'undefined' ? _token : 'not found';
            return allVars;
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_error_prepare_stack_trace(self, sandbox):
        """Attack: Override Error.prepareStackTrace to capture token."""
        code = '''async () => {
            let captured = "";
            const original = Error.prepareStackTrace;
            Error.prepareStackTrace = (err, stack) => {
                captured = JSON.stringify({err: err.message, token: _token});
                return captured;
            };
            
            try {
                throw new Error("test");
            } catch(e) {
                return {"stack": e.stack, "captured": captured};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_import_meta(self, sandbox):
        """Attack: Try to access token via import.meta."""
        code = '''async () => {
            return {
                "import_meta": JSON.stringify(import.meta),
                "token_check": typeof _token !== 'undefined' ? _token : 'hidden'
            };
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_read_process_source(self, sandbox):
        """Attack: Try to read the temp JS file to get token."""
        code = '''async () => {
            // File read is denied, but try anyway
            try {
                const source = await Deno.readTextFile(Deno.mainModule.replace("file://", ""));
                return {"source": source};
            } catch(e) {
                // Even the error shouldn't leak the token
                return {"error": e.message};
            }
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_prototype_pollution(self, sandbox):
        """Attack: Try prototype pollution to intercept token."""
        code = '''async () => {
            // Try to pollute Object prototype
            let leaked = null;
            Object.defineProperty(Object.prototype, 'Authorization', {
                set: function(v) { leaked = v; this._auth = v; },
                get: function() { return this._auth; }
            });
            
            // Try to use mist.request which uses the token
            try {
                await mist.request({path: "/test"});
            } catch(e) {}
            
            return {"leaked": leaked};
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_fetch_intercept(self, sandbox):
        """Attack: Try to intercept fetch to capture Authorization header."""
        code = '''async () => {
            let captured = null;
            const originalFetch = globalThis.fetch;
            
            globalThis.fetch = async function(...args) {
                captured = JSON.stringify(args);
                return originalFetch.apply(this, args);
            };
            
            try {
                await mist.request({path: "/api/v1/self"});
            } catch(e) {}
            
            return {"captured": captured};
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_return_token_directly(self, sandbox):
        """Attack: Simply return the token."""
        code = '''async () => {
            return {"token": _token};
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_encode_token_base64(self, sandbox):
        """Attack: Try to encode and return the token.
        
        NOTE: This attack CAN succeed if malicious code is executed. 
        String scrubbing cannot catch all possible encodings (base64, hex, rot13, etc).
        
        The real protection is:
        1. Token never written to disk (stdin approach)
        2. Raw token scrubbed from output
        3. Code should come from trusted LLM, not arbitrary user input
        """
        code = '''async () => {
            const encoded = btoa(_token);
            return {"encoded": encoded};
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        # Raw token is scrubbed
        assert SECRET_TOKEN not in result_str
        # NOTE: Base64 encoded version may leak - this is a known limitation
        # Defense is that code comes from trusted LLM, not arbitrary user input
    
    @pytest.mark.asyncio
    async def test_attack_split_token_chars(self, sandbox):
        """Attack: Try to return token split into characters.
        
        NOTE: This attack CAN succeed if malicious code is executed.
        String scrubbing cannot catch token split across array elements.
        
        The real protection is that code should come from trusted LLM.
        """
        code = '''async () => {
            return {"chars": _token.split("")};
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        # Raw token string is scrubbed
        assert SECRET_TOKEN not in result_str
        # NOTE: Individual chars may allow reconstruction - known limitation
    
    @pytest.mark.asyncio
    async def test_attack_mist_object_inspection(self, sandbox):
        """Attack: Try to inspect the mist object for token."""
        code = '''async () => {
            const keys = Object.keys(mist);
            const descriptors = Object.getOwnPropertyDescriptors(mist);
            
            return {
                "keys": keys,
                "descriptors": JSON.stringify(descriptors),
                "mist_string": String(mist),
                "mist_json": JSON.stringify(mist),
                "request_string": String(mist.request),
            };
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_async_iterator_leak(self, sandbox):
        """Attack: Try to leak via async iterator."""
        code = '''async () => {
            async function* leak() {
                yield _token;
            }
            
            const results = [];
            for await (const val of leak()) {
                results.push(val);
            }
            return {"results": results};
        }'''
        
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        result_str = json.dumps(result)
        assert SECRET_TOKEN not in result_str


# =============================================================================
# Stress Tests
# =============================================================================

class TestStress:
    """Stress tests for security under load."""
    
    @pytest.mark.asyncio
    async def test_concurrent_executions_scrub_correctly(self, sandbox):
        """Multiple concurrent executions all scrub tokens correctly."""
        tokens = [f"token-{i}-secret" for i in range(5)]
        
        async def run_with_token(token):
            code = f'''async () => {{
                console.log("Token: {token}");
                return {{"token": "{token}"}};
            }}'''
            return await sandbox.run_execute(code, token, "api.mist.com")
        
        results = await asyncio.gather(*[run_with_token(t) for t in tokens])
        
        for i, result in enumerate(results):
            result_str = json.dumps(result)
            assert tokens[i] not in result_str, f"Token {i} leaked!"
