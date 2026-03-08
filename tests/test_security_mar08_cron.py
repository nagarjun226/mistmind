"""Security audit tests for March 8, 2026 cron run.

Red team attack vectors focusing on:
- Console API advanced formatting methods
- TextDecoder stream mode buffer retention
- Intl API token fingerprinting via segmentation timing
"""

import pytest
from pathlib import Path
from mistmind.sandbox import DenoSandbox


@pytest.fixture
def deno_path():
    """Get path to Deno binary."""
    home = Path.home()
    deno_in_home = home / ".deno" / "bin" / "deno"
    
    if deno_in_home.exists():
        return str(deno_in_home)
    
    import shutil
    deno_which = shutil.which("deno")
    if deno_which:
        return deno_which
    
    pytest.skip("Deno binary not found")


class TestMar08CronCheenuAttacks:
    """New attack vectors from March 8 security audit."""

    @pytest.mark.asyncio
    async def test_attack_console_table_object_structure_leak(self, deno_path):
        """Attack: Use console.table() to bypass token scrubbing via structured formatting.
        
        Theory: console.table() formats objects in a special table format that might
        bypass string-based token scrubbing. It introspects object properties deeply
        and might reveal the mist object structure including token-bearing methods.
        
        Can we use console.table() to:
        1. Display the mist object structure and see token in headers
        2. Cause the formatter to call toString/valueOf on internal objects
        3. Leak token through table column names or cell formatting
        
        Defense: Token is in IIFE closure, mist object is frozen, output is scrubbed.
        """
        sandbox = DenoSandbox(deno_path=deno_path, timeout=5)
        
        attack_code = """async () => {
            const leaked = [];
            
            // Attempt 1: Table format the mist object
            try {
                console.table(mist);
                leaked.push("mist object tabled");
            } catch (e) {
                leaked.push("table failed: " + e.message);
            }
            
            // Attempt 2: Try to table globalThis to see if token leaked there
            try {
                const props = {};
                for (const key of Object.getOwnPropertyNames(globalThis)) {
                    if (key.includes('token') || key.includes('_')) {
                        props[key] = typeof globalThis[key];
                    }
                }
                console.table(props);
                leaked.push("globalThis props tabled");
            } catch (e) {}
            
            // Attempt 3: Create proxy around mist.request to intercept and table the args
            try {
                const originalRequest = mist.request.bind(mist);
                const requestHistory = [];
                
                // Override (won't work because mist is frozen, but try)
                Object.defineProperty(mist, 'request', {
                    value: function(args) {
                        requestHistory.push(args);
                        console.table(args);
                        return originalRequest(args);
                    }
                });
                
                await mist.request({ path: "/api/v1/self" });
                leaked.push("request intercepted: " + JSON.stringify(requestHistory));
            } catch (e) {
                leaked.push("request intercept failed: " + e.message);
            }
            
            // Attempt 4: Use console.dir with depth to introspect mist deeply
            try {
                console.dir(mist, { depth: 10, showHidden: true });
                leaked.push("mist dir dumped");
            } catch (e) {}
            
            return { leaked, message: "console.table structure leak attempt" };
        }"""
        
        result = await sandbox.run_execute(
            code=attack_code,
            api_token="test_console_table_token_12345",
            api_host="api.mist.com",
        )
        
        # Verify token not leaked via console.table or console.dir
        assert "test_console_table_token_12345" not in str(result)
        assert "[REDACTED]" not in str(result) or "error" in result

    @pytest.mark.asyncio
    async def test_attack_textdecoder_stream_mode_buffer_retention(self, deno_path):
        """Attack: Use TextDecoder stream mode to retain token chunks across decode calls.
        
        Theory: TextDecoder in stream mode (new TextDecoder('utf-8', {stream: true}))
        retains incomplete UTF-8 sequences in internal buffers. If we can:
        1. Create a TextDecoder before IIFE somehow
        2. Or create one that shares state with IIFE's stdin read
        3. The token bytes might remain in the decoder's internal buffer
        
        Can we:
        - Iterate over all TextDecoder instances in memory?
        - Access the decoder used by Response.text() inside IIFE?
        - Force a garbage collection and inspect decoder buffers?
        
        Defense: IIFE creates isolated Response, user code runs after stdin consumed.
        """
        sandbox = DenoSandbox(deno_path=deno_path, timeout=5)
        
        attack_code = """async () => {
            const leaked = [];
            
            // Attempt 1: Create streaming decoder and try to intercept IIFE stdin read
            const streamDecoder = new TextDecoder('utf-8', { stream: true, fatal: false });
            
            // Try to poison TextDecoder constructor
            const originalTextDecoder = TextDecoder;
            const allDecoders = [];
            
            globalThis.TextDecoder = function(...args) {
                const decoder = new originalTextDecoder(...args);
                allDecoders.push(decoder);
                
                // Wrap decode method to capture all decoded data
                const originalDecode = decoder.decode.bind(decoder);
                decoder.decode = function(input, options) {
                    const result = originalDecode(input, options);
                    leaked.push("decoded: " + result.substring(0, 20));
                    return result;
                };
                
                return decoder;
            };
            
            // Attempt 2: Try to read from Deno.stdin again (should be consumed)
            try {
                const reader = Deno.stdin.readable.getReader();
                const { value, done } = await reader.read();
                if (value) {
                    leaked.push("stdin chunk: " + new TextDecoder().decode(value));
                }
                if (done) {
                    leaked.push("stdin already consumed");
                }
            } catch (e) {
                leaked.push("stdin read error: " + e.message);
            }
            
            // Attempt 3: Try to access internal decoder state via memory introspection
            try {
                // Check if decoder has any accessible internal buffers
                for (const decoder of allDecoders) {
                    const props = Object.getOwnPropertyNames(decoder);
                    leaked.push("decoder props: " + props.join(","));
                    
                    // Try to decode empty buffer to flush any retained state
                    const flushed = decoder.decode(new Uint8Array(0), { stream: false });
                    if (flushed) {
                        leaked.push("flushed: " + flushed);
                    }
                }
            } catch (e) {}
            
            return { leaked, decoderCount: allDecoders.length, message: "TextDecoder stream buffer retention attempt" };
        }"""
        
        result = await sandbox.run_execute(
            code=attack_code,
            api_token="test_textdecoder_stream_token_xyz",
            api_host="api.mist.com",
        )
        
        # Verify token not leaked via TextDecoder stream buffers
        assert "test_textdecoder_stream_token_xyz" not in str(result)
        assert "[REDACTED]" not in str(result) or "error" in result

    @pytest.mark.asyncio
    async def test_attack_intl_segmenter_token_fingerprint_timing(self, deno_path):
        """Attack: Use Intl.Segmenter to fingerprint token structure via timing side channel.
        
        Theory: Intl.Segmenter can break text into graphemes, words, or sentences.
        Different segmentation patterns take different amounts of time. If we can:
        1. Guess token format (e.g., "mist_api_token_12345")
        2. Use Segmenter with different locales and measure timing
        3. Iterate through character sets and measure segmentation time
        4. Binary search the token space using timing oracle
        
        Even without direct access to token, timing differences in how the V8
        engine handles different string patterns might leak information.
        
        Defense: Token is isolated, no direct access. Timing alone without
        token access doesn't constitute a leak.
        """
        sandbox = DenoSandbox(deno_path=deno_path, timeout=5)
        
        attack_code = """async () => {
            const results = { timings: {}, analysis: [] };
            
            // Token format candidates to test
            const tokenFormats = [
                "api_token_12345",
                "mist_api_key_xyz",
                "Bearer_abc123def",
                "sk-proj-abcdef123456",
            ];
            
            // Test segmentation timing for each format
            for (const format of tokenFormats) {
                const start = performance.now();
                
                // Create segmenter for each locale
                const locales = ['en', 'zh', 'ja', 'ar', 'hi'];
                for (const locale of locales) {
                    try {
                        const segmenter = new Intl.Segmenter(locale, { granularity: 'grapheme' });
                        const segments = [...segmenter.segment(format)];
                        
                        // Force full iteration to ensure consistent timing
                        segments.forEach(s => s.segment.length);
                    } catch (e) {}
                }
                
                const elapsed = performance.now() - start;
                results.timings[format] = elapsed;
            }
            
            // Attempt to probe mist object for token-like properties
            try {
                const mistProps = Object.getOwnPropertyNames(mist);
                results.mistProps = mistProps;
                
                // Try to segment method names
                const segmenter = new Intl.Segmenter('en', { granularity: 'word' });
                for (const prop of mistProps) {
                    const segments = [...segmenter.segment(prop)];
                    if (segments.length > 0) {
                        results.analysis.push({
                            prop,
                            segments: segments.map(s => s.segment)
                        });
                    }
                }
            } catch (e) {
                results.mistPropsError = e.message;
            }
            
            // Try to use Collator for fuzzy matching against known token patterns
            try {
                const collator = new Intl.Collator('en', { sensitivity: 'base' });
                const tokenPatterns = ['token', 'key', 'auth', 'bearer'];
                
                // Check if any globalThis properties match token patterns
                const matches = [];
                for (const key of Object.getOwnPropertyNames(globalThis)) {
                    for (const pattern of tokenPatterns) {
                        if (collator.compare(key.toLowerCase(), pattern) === 0) {
                            matches.push(key);
                        }
                    }
                }
                results.collatorMatches = matches;
            } catch (e) {}
            
            return results;
        }"""
        
        result = await sandbox.run_execute(
            code=attack_code,
            api_token="test_intl_segmenter_token_secret_999",
            api_host="api.mist.com",
        )
        
        # Verify token not leaked via Intl API timing or analysis
        assert "test_intl_segmenter_token_secret_999" not in str(result)
        assert "[REDACTED]" not in str(result) or "error" in result
        # Timing patterns alone without token access are not a vulnerability


class TestAbortSignalTimeoutRace:
    """Test race conditions with AbortSignal.timeout during IIFE execution."""

    @pytest.mark.asyncio
    async def test_attack_abortsignal_timeout_iife_race(self, deno_path):
        """Attack: Use AbortSignal.timeout to interrupt IIFE stdin read.
        
        Theory: AbortSignal.timeout creates a signal that aborts after a delay.
        If we can:
        1. Create AbortSignal before IIFE somehow
        2. Or poison the AbortSignal constructor
        3. Interrupt the stdin read inside IIFE
        4. Cause partial token read or error state that leaks info
        
        Defense: IIFE executes before user code, signals can't affect it.
        """
        sandbox = DenoSandbox(deno_path=deno_path, timeout=5)
        
        attack_code = """async () => {
            const leaked = [];
            
            // Attempt 1: Poison AbortSignal to intercept any abortable operations
            const originalAbortSignal = AbortSignal;
            const allSignals = [];
            
            try {
                globalThis.AbortSignal = class extends originalAbortSignal {
                    constructor(...args) {
                        super(...args);
                        allSignals.push(this);
                        leaked.push("AbortSignal created");
                    }
                    
                    static timeout(ms) {
                        const signal = originalAbortSignal.timeout(ms);
                        allSignals.push(signal);
                        leaked.push("AbortSignal.timeout created: " + ms);
                        return signal;
                    }
                };
            } catch (e) {
                leaked.push("AbortSignal poison failed: " + e.message);
            }
            
            // Attempt 2: Create very short timeout to race with mist.request
            try {
                const controller = new AbortController();
                const signal = controller.signal;
                
                // Abort immediately
                setTimeout(() => controller.abort("race attack"), 1);
                
                // Try to make request with abort signal
                await mist.request({
                    path: "/api/v1/self",
                    signal: signal  // This param probably doesn't exist
                });
            } catch (e) {
                leaked.push("abort race error: " + e.message.substring(0, 100));
            }
            
            // Attempt 3: Check if any AbortSignals were created that we can inspect
            leaked.push("Total signals created: " + allSignals.length);
            
            return { leaked, message: "AbortSignal timeout race attempt" };
        }"""
        
        result = await sandbox.run_execute(
            code=attack_code,
            api_token="test_abortsignal_race_token_777",
            api_host="api.mist.com",
        )
        
        # Verify token not leaked via AbortSignal race conditions
        assert "test_abortsignal_race_token_777" not in str(result)
        assert "[REDACTED]" not in str(result) or "error" in result
