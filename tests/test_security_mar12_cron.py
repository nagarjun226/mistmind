"""Security tests for March 12 cron audit - New attack vectors by Cheenu."""

import pytest
from pathlib import Path
import shutil

from mistmind.sandbox import DenoSandbox

SECRET_TOKEN = "super-secret-api-token-mar12"


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
    """Create sandbox with readonly API mode."""
    return DenoSandbox(
        deno_path=deno_path,
        api_mode="readonly",
        timeout=5,
    )


class TestMar12CronCheenuAttacks:
    """New attack vectors discovered during March 12 red-team audit."""

    @pytest.mark.asyncio
    async def test_attack_structured_clone_bypass_freeze(self, sandbox):
        """
        ATTACK: Use structuredClone() to bypass Object.freeze() on mist object.
        DEFENSE: structuredClone cannot clone functions, so mist.request is lost.
        """
        code = '''async () => {
            try {
                const cloned = structuredClone(mist);
                return {leaked: "structuredClone succeeded", cloned};
            } catch (e) {
                return {defense: "structuredClone failed", error: e.message};
            }
        }'''
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        assert SECRET_TOKEN not in str(result)

    @pytest.mark.asyncio
    async def test_attack_async_disposal_symbol_leak(self, sandbox):
        """
        ATTACK: Use Symbol.asyncDispose to capture references during cleanup.
        DEFENSE: Token is in IIFE closure, not accessible from user code.
        """
        code = '''async () => {
            let captured = null;
            const resource = {
                async [Symbol.asyncDispose]() {
                    captured = {
                        globalThis: Object.keys(globalThis),
                        mist: typeof mist !== "undefined" ? Object.keys(mist) : "undefined"
                    };
                }
            };
            try {
                await using res = resource;
            } catch (e) {
                return {defense: "async using not supported", error: e.message};
            }
            return {leaked: "Captured during disposal", captured};
        }'''
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        assert SECRET_TOKEN not in str(result)

    @pytest.mark.asyncio
    async def test_attack_json_parse_reviver_intercept(self, sandbox):
        """
        ATTACK: Override JSON.parse to intercept Response.json() parsing.
        DEFENSE: resp.json() uses native parsing, token is scrubbed from output.
        """
        code = '''async () => {
            let captured = [];
            const originalParse = JSON.parse;
            JSON.parse = function(text, reviver) {
                captured.push({text: String(text).substring(0, 100)});
                return originalParse.call(this, text, reviver);
            };
            try {
                await mist.request({method: "GET", path: "/api/v1/self"});
            } catch (e) {}
            return {leaked: "JSON.parse intercept", captured};
        }'''
        result = await sandbox.run_execute(code, SECRET_TOKEN, "api.mist.com")
        assert SECRET_TOKEN not in str(result)
