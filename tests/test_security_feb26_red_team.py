"""
Red Team Security Audit - February 26, 2026
New attack vectors by Cheenu (MistMind Red Team)
"""

import shutil
from pathlib import Path
from unittest.mock import patch, AsyncMock

import pytest
from mistmind.sandbox import DenoSandbox


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
    
    deno_in_path = shutil.which("deno")
    if deno_in_path:
        return deno_in_path
    
    pytest.skip("Deno not found")


@pytest.fixture
def sandbox(deno_path):
    """Create a Deno sandbox instance with readwrite mode for testing."""
    return DenoSandbox(deno_path=deno_path, timeout=5, api_mode="readwrite")


@pytest.fixture
def mock_mist_api():
    """Mock the Mist API for testing."""
    with patch('mistmind.sandbox.DenoSandbox.MIST_HOSTS', ['httpbin.org']):
        yield


class TestFeb26CheenuRedTeam:
    """Creative attack vectors to extract token or bypass sandbox."""

    @pytest.mark.asyncio
    async def test_attack_proxy_revocable_timing_leak(self, sandbox: DenoSandbox, mock_mist_api):
        """
        Attack: Use Proxy.revocable() to create timing side-channel.
        
        Attempt to measure timing differences when accessing the mist object
        via a revocable proxy, potentially leaking information about the token
        through timing analysis.
        
        Defense: IIFE closure prevents token access, timing differences are
        negligible and don't leak token data.
        """
        code = """async () => {
  // Create a revocable proxy around mist to intercept access
  const { proxy, revoke } = Proxy.revocable(mist, {
    get(target, prop) {
      const startTime = performance.now();
      const value = Reflect.get(target, prop);
      const endTime = performance.now();
      
      // Try to leak timing information
      if (typeof value === 'function') {
        return function(...args) {
          const fnStartTime = performance.now();
          const result = value.apply(target, args);
          const fnEndTime = performance.now();
          // Attempt to infer token from timing
          return result;
        };
      }
      return value;
    }
  });
  
  try {
    // Try to measure access patterns
    const timings = [];
    for (let i = 0; i < 100; i++) {
      const start = performance.now();
      const methods = proxy.allowedMethods;
      const end = performance.now();
      timings.push(end - start);
    }
    
    // Try to extract token via timing analysis
    const avgTiming = timings.reduce((a, b) => a + b) / timings.length;
    
    // Attempt to access internal state via revocation timing
    revoke();
    
    try {
      await proxy.request({ path: '/api/v1/self' });
    } catch (e) {
      return { attack: "timing_leak_via_revocable_proxy", timings, error: e.message };
    }
    
    return { attack: "failed", avgTiming };
  } catch (e) {
    return { error: e.message, stack: e.stack };
  }
}"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test-token-12345",
            api_host="httpbin.org",
        )
        
        # Should not leak token through timing
        result_str = str(result)
        assert "test-token-12345" not in result_str
        assert "[REDACTED]" not in result_str or "error" in result
    
    @pytest.mark.asyncio
    async def test_attack_bigint_coercion_side_channel(self, sandbox: DenoSandbox, mock_mist_api):
        """
        Attack: Use BigInt coercion and valueOf() to leak token data.
        
        Attempt to override valueOf() or toString() on various objects to
        intercept token data during BigInt coercion operations.
        
        Defense: Token is in IIFE closure, never exposed to user scope.
        BigInt operations on mist object don't leak internal state.
        """
        code = """async () => {
  // Override BigInt coercion to capture data
  const originalValueOf = Object.prototype.valueOf;
  const captured = [];
  
  Object.prototype.valueOf = function() {
    captured.push(this);
    return originalValueOf.call(this);
  };
  
  try {
    // Try to coerce mist object to BigInt (triggers valueOf)
    try {
      BigInt(mist);
    } catch {}
    
    // Try to coerce request function
    try {
      BigInt(mist.request);
    } catch {}
    
    // Try arithmetic operations that might trigger coercion
    try {
      1n + BigInt.asUintN(64, mist);
    } catch {}
    
    // Check if we captured anything sensitive
    const leak = captured.map(obj => {
      try {
        return JSON.stringify(obj);
      } catch {
        return Object.keys(obj || {});
      }
    });
    
    return { attack: "bigint_coercion", captured: leak };
  } finally {
    Object.prototype.valueOf = originalValueOf;
  }
}"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test-token-67890",
            api_host="httpbin.org",
        )
        
        # Should not leak token via BigInt coercion
        result_str = str(result)
        assert "test-token-67890" not in result_str
    
    @pytest.mark.asyncio
    async def test_attack_temporal_dead_zone_race(self, sandbox: DenoSandbox, mock_mist_api):
        """
        Attack: Exploit temporal dead zone to access mist before frozen.
        
        Attempt to access the mist object or its properties during the
        temporal dead zone - the time between declaration and initialization,
        or between creation and freezing.
        
        Defense: IIFE pattern ensures mist is frozen before user code runs.
        No temporal dead zone exists for user code to exploit.
        """
        code = """async () => {
  // Try to access mist in various ways that might exploit TDZ
  const results = [];
  
  // Attempt 1: Immediate access (should work - mist is already frozen)
  try {
    results.push({ attempt: "immediate", value: typeof mist });
  } catch (e) {
    results.push({ attempt: "immediate", error: e.message });
  }
  
  // Attempt 2: Async microtask race
  try {
    const mistRef = mist;
    await Promise.resolve();
    results.push({ attempt: "microtask", frozen: Object.isFrozen(mistRef) });
  } catch (e) {
    results.push({ attempt: "microtask", error: e.message });
  }
  
  // Attempt 3: Try to redefine mist before it's used
  try {
    Object.defineProperty(globalThis, 'mist', {
      get() { return { leaked: "token" }; }
    });
    results.push({ attempt: "redefine", success: true });
  } catch (e) {
    results.push({ attempt: "redefine", error: e.message });
  }
  
  // Attempt 4: Try to access __proto__ chain during initialization
  try {
    const proto = Object.getPrototypeOf(mist);
    const protoProps = Object.getOwnPropertyNames(proto);
    results.push({ attempt: "proto", props: protoProps });
  } catch (e) {
    results.push({ attempt: "proto", error: e.message });
  }
  
  // Attempt 5: Intercept freeze operation
  try {
    const originalFreeze = Object.freeze;
    Object.freeze = function(obj) {
      if (obj && obj.request) {
        return { leaked: "intercepted" };
      }
      return originalFreeze(obj);
    };
    results.push({ attempt: "freeze_intercept", mist_type: typeof mist });
  } catch (e) {
    results.push({ attempt: "freeze_intercept", error: e.message });
  }
  
  return { attack: "temporal_dead_zone", results };
}"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test-token-tdz-13579",
            api_host="httpbin.org",
        )
        
        # Should not leak token via TDZ exploitation
        result_str = str(result)
        assert "test-token-tdz-13579" not in result_str
        
        # Note: User CAN redefine mist on globalThis AFTER it's been created,
        # but this doesn't help them because:
        # 1. The token is in IIFE closure, not accessible from mist object
        # 2. Their function has already captured the real mist reference
        # 3. Redefining globalThis.mist doesn't affect the closure-scoped mist
        # This is not a vulnerability - just confirms the IIFE isolation works


class TestResourceAmplificationAttacks:
    """Test resource exhaustion via amplification attacks."""
    
    @pytest.mark.asyncio
    async def test_attack_compression_bomb_json_stringify(self, sandbox: DenoSandbox):
        """
        Attack: Create a compression bomb via deeply nested JSON.
        
        Attempt to exhaust memory or CPU by creating a JSON structure that
        expands exponentially during JSON.stringify().
        
        Defense: V8 memory limits (256MB) and timeout prevent exhaustion.
        """
        code = """async () => {
  // Create exponentially growing nested structure
  let obj = { value: "x" };
  
  for (let i = 0; i < 20; i++) {
    obj = {
      a: obj,
      b: obj,
      c: obj,
      d: obj,
      e: obj,
      f: obj,
      g: obj,
      h: obj
    };
  }
  
  // Try to stringify (should hit memory/time limits)
  try {
    const str = JSON.stringify(obj);
    return { attack: "compression_bomb", size: str.length };
  } catch (e) {
    return { attack: "compression_bomb", defended: true, error: e.message };
  }
}"""
        
        result = await sandbox.run_search(
            code=code,
            spec_path="spec/mist.resolved.json",
        )
        
        # Should either timeout or hit memory limit
        assert "error" in result or ("defended" in result and result["defended"])


class TestIIFEBypassAttempts:
    """Advanced attempts to break out of IIFE closure."""
    
    @pytest.mark.asyncio
    async def test_attack_async_context_tracking(self, sandbox: DenoSandbox, mock_mist_api):
        """
        Attack: Use async context tracking to leak closure variables.
        
        Attempt to use async_hooks or similar mechanisms (if available in Deno)
        to track async context and potentially access closure variables.
        
        Defense: Deno doesn't expose Node.js async_hooks, and IIFE closure
        is impenetrable from user code.
        """
        code = """async () => {
  const leaks = [];
  
  // Attempt 1: Check for async_hooks (Node.js API)
  try {
    const asyncHooks = await import('async_hooks');
    leaks.push({ source: "async_hooks", available: true });
  } catch (e) {
    leaks.push({ source: "async_hooks", available: false });
  }
  
  // Attempt 2: Try to inspect async stack trace
  try {
    const err = new Error();
    Error.captureStackTrace(err);
    const stack = err.stack;
    leaks.push({ source: "stack_trace", stack: stack.slice(0, 200) });
  } catch (e) {
    leaks.push({ source: "stack_trace", error: e.message });
  }
  
  // Attempt 3: Queueing microtasks to intercept async flow
  try {
    const captured = [];
    const originalThen = Promise.prototype.then;
    Promise.prototype.then = function(...args) {
      captured.push({ args, context: this });
      return originalThen.apply(this, args);
    };
    
    // Trigger async operation
    await mist.request({ path: "/post", method: "POST", body: { test: 1 } });
    
    Promise.prototype.then = originalThen;
    leaks.push({ source: "promise_intercept", captured: captured.length });
  } catch (e) {
    leaks.push({ source: "promise_intercept", error: e.message });
  }
  
  return { attack: "async_context_tracking", leaks };
}"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test-token-async-24680",
            api_host="httpbin.org",
        )
        
        # Should not leak token via async context tracking
        result_str = str(result)
        assert "test-token-async-24680" not in result_str
        
        # async_hooks should not be available in Deno
        if "leaks" in result:
            async_hooks_leak = next((l for l in result["leaks"] if l.get("source") == "async_hooks"), None)
            if async_hooks_leak:
                assert not async_hooks_leak.get("available")
