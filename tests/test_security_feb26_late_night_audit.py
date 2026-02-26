"""
Red Team Security Audit - February 26, 2026 Late Night
Advanced attack vectors by Cheenu (MistMind Red Team)
Focus: WebAssembly, ArrayBuffer, and memory side channels
"""

import shutil
from pathlib import Path
from unittest.mock import patch

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


class TestWebAssemblyMemorySideChannel:
    """Test attacks using WebAssembly linear memory as a side channel."""

    @pytest.mark.asyncio
    async def test_attack_wasm_memory_leak_via_import(self, sandbox: DenoSandbox, mock_mist_api):
        """
        Attack: Use WebAssembly linear memory to leak token data.
        
        Create a WASM module that can access JavaScript strings via imports,
        potentially copying token data into WASM linear memory where it might
        be accessible through different mechanisms.
        
        Defense: Token is never exposed to user code, so WASM can't access it.
        Even if WASM could see mist object, token is in IIFE closure.
        """
        code = """async () => {
  try {
    // Create a minimal WASM module with memory
    // This is a hand-crafted WASM binary that exports memory and a function
    const wasmCode = new Uint8Array([
      0x00, 0x61, 0x73, 0x6d, // magic '\\0asm'
      0x01, 0x00, 0x00, 0x00, // version 1
      
      // Memory section: 1 memory with 1 page (64KB)
      0x05, 0x03, 0x01, 0x00, 0x01,
      
      // Export section: export memory as "mem"
      0x07, 0x07, 0x01, 0x03, 0x6d, 0x65, 0x6d, 0x02, 0x00,
      
      // Function section: 1 function
      0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
      
      // Code section: empty function body
      0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b
    ]);
    
    const wasmModule = await WebAssembly.instantiate(wasmCode, {
      js: {
        // Try to pass mist object to WASM
        logMist: (ptr) => {
          // In real attack, would try to write mist/token to WASM memory
          return 0;
        }
      }
    });
    
    const memory = wasmModule.instance.exports.mem;
    
    // Try to write sensitive data to WASM memory
    const buffer = new Uint8Array(memory.buffer);
    
    // Attempt to serialize mist object into WASM memory
    const mistStr = JSON.stringify({
      type: typeof mist,
      keys: Object.keys(mist),
      request: typeof mist.request
    });
    
    const encoder = new TextEncoder();
    const encoded = encoder.encode(mistStr);
    buffer.set(encoded, 0);
    
    // Try to read back from WASM memory (looking for leaks)
    const decoder = new TextDecoder();
    const leaked = decoder.decode(buffer.slice(0, encoded.length));
    
    return {
      attack: "wasm_memory_side_channel",
      leaked,
      hasToken: leaked.includes("token") || leaked.includes("Token")
    };
  } catch (e) {
    return { attack: "wasm_memory_side_channel", error: e.message };
  }
}"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test-token-wasm-11111",
            api_host="httpbin.org",
        )
        
        # Should not leak actual token value
        result_str = str(result)
        assert "test-token-wasm-11111" not in result_str


class TestArrayBufferDetachAttack:
    """Test attacks using ArrayBuffer detach/transfer mechanisms."""

    @pytest.mark.asyncio
    async def test_attack_arraybuffer_detach_intercept(self, sandbox: DenoSandbox, mock_mist_api):
        """
        Attack: Intercept ArrayBuffer detach operations to leak data.
        
        Override ArrayBuffer detach mechanisms or MessageChannel transfers
        to intercept data that might contain token information during
        internal operations.
        
        Defense: Token is never converted to ArrayBuffer, always stays as
        string in IIFE closure. User code can't intercept internal Deno/V8
        buffer operations.
        """
        code = """async () => {
  const leaks = [];
  
  try {
    // Attempt 1: Override structuredClone to intercept transfers
    const originalClone = globalThis.structuredClone;
    globalThis.structuredClone = function(value, options) {
      leaks.push({
        source: "structuredClone",
        type: typeof value,
        hasTransfer: options?.transfer?.length > 0
      });
      return originalClone(value, options);
    };
    
    // Attempt 2: Create MessageChannel to try to intercept messages
    const channel = new MessageChannel();
    channel.port1.onmessage = (e) => {
      leaks.push({ source: "messageChannel", data: e.data });
    };
    
    // Try to send mist through channel (should fail or not leak token)
    try {
      channel.port2.postMessage(mist);
    } catch (e) {
      leaks.push({ source: "messageChannel", error: e.message });
    }
    
    // Attempt 3: Monitor ArrayBuffer.prototype.transfer (if available)
    if (ArrayBuffer.prototype.transfer) {
      const originalTransfer = ArrayBuffer.prototype.transfer;
      ArrayBuffer.prototype.transfer = function(...args) {
        leaks.push({
          source: "arrayBufferTransfer",
          byteLength: this.byteLength
        });
        return originalTransfer.apply(this, args);
      };
    }
    
    // Attempt 4: Try to make a request and intercept buffer operations
    try {
      await mist.request({ path: "/post", method: "POST", body: { test: 1 } });
    } catch (e) {
      leaks.push({ source: "request", error: e.message });
    }
    
    return { attack: "arraybuffer_detach_intercept", leaks };
  } catch (e) {
    return { attack: "arraybuffer_detach_intercept", error: e.message, stack: e.stack };
  }
}"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test-token-arraybuffer-22222",
            api_host="httpbin.org",
        )
        
        # Should not leak token through ArrayBuffer operations
        result_str = str(result)
        assert "test-token-arraybuffer-22222" not in result_str


class TestIntlAPITimingSideChannel:
    """Test timing side channels via Internationalization APIs."""

    @pytest.mark.asyncio
    async def test_attack_intl_collator_timing_leak(self, sandbox: DenoSandbox, mock_mist_api):
        """
        Attack: Use Intl.Collator timing to leak token character data.
        
        Intl.Collator.compare() has different timing characteristics for
        different strings. By measuring comparison times against known
        strings, might be able to infer token characters through timing
        side channel.
        
        Defense: Token is in IIFE closure, never accessible to user code.
        Can't compare what you can't access.
        """
        code = """async () => {
  try {
    const collator = new Intl.Collator('en', { sensitivity: 'base' });
    const timings = [];
    
    // Try to measure comparison timings
    const testStrings = [
      'test-token',
      'api-key',
      'authorization',
      'bearer',
      'Token',
      'REDACTED'
    ];
    
    for (const testStr of testStrings) {
      const iterations = 1000;
      const start = performance.now();
      
      for (let i = 0; i < iterations; i++) {
        // Try to compare against mist properties
        try {
          collator.compare(testStr, String(mist));
          collator.compare(testStr, String(mist.request));
          collator.compare(testStr, String(mist.allowedMethods));
        } catch {}
      }
      
      const end = performance.now();
      const avgTime = (end - start) / iterations;
      
      timings.push({
        testString: testStr,
        avgMicroseconds: avgTime * 1000
      });
    }
    
    // Try to infer token from timing patterns
    const sortedByTime = [...timings].sort((a, b) => a.avgMicroseconds - b.avgMicroseconds);
    
    return {
      attack: "intl_collator_timing",
      timings,
      fastest: sortedByTime[0],
      slowest: sortedByTime[sortedByTime.length - 1]
    };
  } catch (e) {
    return { attack: "intl_collator_timing", error: e.message };
  }
}"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test-token-intl-33333",
            api_host="httpbin.org",
        )
        
        # Should not leak token through timing analysis
        result_str = str(result)
        assert "test-token-intl-33333" not in result_str
        
        # Even if timing differences exist, they shouldn't be meaningful
        # because token is never passed to Intl.Collator


class TestAtomicsSharedMemoryAttack:
    """Test attacks using SharedArrayBuffer and Atomics (if available)."""

    @pytest.mark.asyncio
    async def test_attack_shared_array_buffer_side_channel(self, sandbox: DenoSandbox, mock_mist_api):
        """
        Attack: Use SharedArrayBuffer + Atomics for side-channel timing.
        
        If SharedArrayBuffer is available, create a worker (if possible) or
        use Atomics.waitAsync to create precise timing measurements that
        might leak information about token through cache timing or other
        microarchitectural side channels.
        
        Defense: Even with SharedArrayBuffer, token is in IIFE closure and
        never exposed to user code. No side channel can leak what's not
        accessible.
        """
        code = """async () => {
  const results = [];
  
  try {
    // Check if SharedArrayBuffer is available
    const sab = new SharedArrayBuffer(1024);
    const view = new Int32Array(sab);
    
    results.push({ sharedArrayBufferAvailable: true });
    
    // Try to use Atomics for precise timing
    if (typeof Atomics !== 'undefined') {
      // Attempt to measure atomic operations timing
      const timings = [];
      
      for (let i = 0; i < 100; i++) {
        const start = performance.now();
        
        // Perform atomic operations
        Atomics.store(view, 0, i);
        const loaded = Atomics.load(view, 0);
        Atomics.add(view, 0, 1);
        
        const end = performance.now();
        timings.push(end - start);
      }
      
      const avgTiming = timings.reduce((a, b) => a + b) / timings.length;
      
      results.push({
        atomicsAvailable: true,
        avgAtomicOpMicroseconds: avgTiming * 1000
      });
      
      // Try to use Atomics.waitAsync (if available)
      if (Atomics.waitAsync) {
        try {
          const waitResult = Atomics.waitAsync(view, 0, 0, 100);
          results.push({
            atomicsWaitAsyncAvailable: true,
            waitResult: waitResult.async ? "async" : "timed-out"
          });
        } catch (e) {
          results.push({
            atomicsWaitAsyncAvailable: false,
            error: e.message
          });
        }
      }
    }
    
    // Try to access mist via shared memory (should fail)
    try {
      const mistStr = String(mist);
      const encoder = new TextEncoder();
      const encoded = encoder.encode(mistStr);
      
      // Try to write to shared buffer
      const u8view = new Uint8Array(sab);
      u8view.set(encoded.slice(0, 1024));
      
      results.push({ wroteToSharedMemory: true });
    } catch (e) {
      results.push({ wroteToSharedMemory: false, error: e.message });
    }
    
    return { attack: "shared_array_buffer_side_channel", results };
  } catch (e) {
    // SharedArrayBuffer might not be available
    return {
      attack: "shared_array_buffer_side_channel",
      sharedArrayBufferAvailable: false,
      error: e.message
    };
  }
}"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test-token-atomics-44444",
            api_host="httpbin.org",
        )
        
        # Should not leak token through SharedArrayBuffer
        result_str = str(result)
        assert "test-token-atomics-44444" not in result_str


class TestURLPatternExploitation:
    """Test attacks using URLPattern API for data extraction."""

    @pytest.mark.asyncio
    async def test_attack_url_pattern_regex_extraction(self, sandbox: DenoSandbox, mock_mist_api):
        """
        Attack: Use URLPattern to extract data via regex patterns.
        
        URLPattern allows complex regex-like matching. Try to use it to
        extract or infer token data by matching against various patterns.
        
        Defense: Token is in IIFE closure, never exposed as URL or to
        URLPattern API.
        """
        code = """async () => {
  try {
    // Check if URLPattern is available (newer browsers/Deno)
    if (typeof URLPattern === 'undefined') {
      return { attack: "url_pattern", available: false };
    }
    
    const patterns = [
      new URLPattern({ pathname: '/api/*' }),
      new URLPattern({ pathname: '/:token' }),
      new URLPattern({ search: 'token=*' }),
      new URLPattern({ hash: '#:secret' })
    ];
    
    const matches = [];
    
    // Try to match against mist object properties
    const mistStr = String(mist);
    const requestStr = String(mist.request);
    
    for (const pattern of patterns) {
      try {
        // Try to match against stringified mist
        const match1 = pattern.test({ pathname: mistStr });
        const match2 = pattern.test({ pathname: requestStr });
        
        matches.push({
          pattern: pattern.pathname || pattern.search || pattern.hash,
          matchedMist: match1,
          matchedRequest: match2
        });
      } catch {}
    }
    
    return { attack: "url_pattern", available: true, matches };
  } catch (e) {
    return { attack: "url_pattern", error: e.message };
  }
}"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test-token-urlpattern-55555",
            api_host="httpbin.org",
        )
        
        # Should not leak token through URLPattern
        result_str = str(result)
        assert "test-token-urlpattern-55555" not in result_str


class TestCompressionStreamLeak:
    """Test attacks using CompressionStream to leak data."""

    @pytest.mark.asyncio
    async def test_attack_compression_stream_side_channel(self, sandbox: DenoSandbox, mock_mist_api):
        """
        Attack: Use CompressionStream to leak data via compression ratios.
        
        Different strings compress differently. By measuring compression
        ratios of data that includes attempts to reference the token,
        might infer token content through compression side channel.
        
        Defense: Token is in IIFE closure, never accessible to user code.
        Can't compress what you can't access.
        """
        code = """async () => {
  try {
    // Check if CompressionStream is available
    if (typeof CompressionStream === 'undefined') {
      return { attack: "compression_stream", available: false };
    }
    
    const testStrings = [
      'test-token-',
      'api-key-',
      'secret-',
      'auth-',
      'bearer-'
    ];
    
    const compressionResults = [];
    
    for (const prefix of testStrings) {
      // Create test data by trying to combine with mist references
      const testData = prefix + String(mist) + String(mist.request);
      
      const encoder = new TextEncoder();
      const encoded = encoder.encode(testData);
      
      // Compress the data
      const stream = new CompressionStream('gzip');
      const writer = stream.writable.getWriter();
      writer.write(encoded);
      writer.close();
      
      // Read compressed output
      const reader = stream.readable.getReader();
      const chunks = [];
      
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
      }
      
      // Calculate compression ratio
      const compressedSize = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
      const ratio = encoded.length / compressedSize;
      
      compressionResults.push({
        prefix,
        originalSize: encoded.length,
        compressedSize,
        ratio
      });
    }
    
    // Sort by compression ratio (might reveal patterns)
    const sorted = [...compressionResults].sort((a, b) => b.ratio - a.ratio);
    
    return {
      attack: "compression_stream",
      available: true,
      results: compressionResults,
      bestCompression: sorted[0],
      worstCompression: sorted[sorted.length - 1]
    };
  } catch (e) {
    return { attack: "compression_stream", error: e.message };
  }
}"""
        
        result = await sandbox.run_execute(
            code=code,
            api_token="test-token-compression-66666",
            api_host="httpbin.org",
        )
        
        # Should not leak token through compression side channel
        result_str = str(result)
        assert "test-token-compression-66666" not in result_str
