"""Deno sandbox for secure JavaScript code execution."""

import asyncio
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)


def _js_safe_string(value: str) -> str:
    """Safely encode a string for embedding in JavaScript source code."""
    return json.dumps(value)


class DenoSandbox:
    """Secure sandbox for executing JavaScript code in Deno."""

    # Maximum output size (1MB) to prevent context flooding
    MAX_OUTPUT_BYTES = 1 * 1024 * 1024

    # All Mist API hosts that should be allowed for execute
    MIST_HOSTS = [
        "api.mist.com",
        "api.eu.mist.com",
        "api.gc1.mist.com",
        "api.gc2.mist.com",
        "api.gc3.mist.com",
        "api.gc4.mist.com",
        "api.gc5.mist.com",
        "api.gc6.mist.com",
        "api.gc7.mist.com",
        "api.ac2.mist.com",
        "api.ac5.mist.com",
        "api.ac6.mist.com",
    ]

    def __init__(self, deno_path: str, timeout: int = 30):
        """Initialize sandbox with path to Deno binary and timeout."""
        self.deno_path = deno_path
        self.timeout = timeout
        
        # Verify Deno exists
        if not Path(deno_path).exists():
            raise FileNotFoundError(f"Deno not found at {deno_path}")

    async def _run_deno(
        self,
        js_code: str,
        args: list[str],
    ) -> Dict[str, Any]:
        """Run JavaScript code in Deno with specified arguments."""
        # Create temp file for JS code
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".js",
            delete=False,
            dir="/tmp",
        ) as tmp:
            tmp.write(js_code)
            tmp_path = tmp.name
        
        try:
            # Build Deno command
            cmd = [self.deno_path, "run"] + args + [tmp_path]
            
            logger.debug(f"Running Deno: {' '.join(cmd)}")
            
            # Execute Deno
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            # Wait with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout,
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    "error": f"Execution timed out after {self.timeout} seconds",
                    "stderr": "",
                }
            
            # Decode output
            stdout_text = stdout.decode("utf-8")
            stderr_text = stderr.decode("utf-8")
            
            # Log stderr if present
            if stderr_text:
                logger.debug(f"Deno stderr: {stderr_text}")
            
            # Enforce output size limit to prevent context flooding
            if len(stdout_text) > self.MAX_OUTPUT_BYTES:
                return {
                    "error": f"Output too large ({len(stdout_text)} bytes, max {self.MAX_OUTPUT_BYTES}). "
                             "Filter or summarize results in your code before returning.",
                    "stderr": stderr_text,
                }
            
            # Parse the LAST line of stdout as JSON (ignore any prior console.log output)
            # The wrapper template always outputs the result as the final console.log
            stdout_lines = stdout_text.strip().splitlines()
            
            # Try to find valid JSON starting from the last line, working backwards
            # to handle pretty-printed JSON (multi-line)
            json_text = None
            for i in range(len(stdout_lines)):
                candidate = "\n".join(stdout_lines[i:])
                try:
                    json.loads(candidate)
                    json_text = candidate
                    break
                except json.JSONDecodeError:
                    continue
            
            if json_text is None:
                logger.error(f"No valid JSON found in Deno output")
                logger.error(f"stdout: {stdout_text}")
                return {
                    "error": "No valid JSON in output",
                    "stderr": stderr_text,
                    "stdout": stdout_text[:500],
                }
            
            try:
                result = json.loads(json_text)
                return result
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Deno output as JSON: {e}")
                logger.error(f"stdout: {stdout_text}")
                return {
                    "error": f"Invalid JSON output: {str(e)}",
                    "stderr": stderr_text,
                    "stdout": stdout_text[:500],
                }
        
        finally:
            # Clean up temp file
            try:
                os.unlink(tmp_path)
            except Exception as e:
                logger.warning(f"Failed to delete temp file {tmp_path}: {e}")

    async def run_search(self, code: str, spec_path: str) -> Dict[str, Any]:
        """Execute JavaScript code with `spec` available as a global.
        
        Args:
            code: JavaScript async arrow function to execute
            spec_path: Path to the resolved OpenAPI spec JSON file
        
        Returns:
            Result of the function execution or error dict
        """
        # Verify spec file exists and get absolute path
        spec_file = Path(spec_path).resolve()
        if not spec_file.exists():
            return {
                "error": f"Spec file not found: {spec_path}",
                "stderr": "",
            }
        
        # Build JavaScript wrapper (use file:// URL for Deno)
        spec_url = f"file://{spec_file}"
        js_template = f'''import spec from "{spec_url}" with {{ type: "json" }};

// Freeze output function so user code can't override it
const __output = console.log.bind(console);

const fn = {code};

try {{
  const result = await fn();
  __output(JSON.stringify(result, null, 2));
}} catch(e) {{
  __output(JSON.stringify({{error: e.message, stack: e.stack}}));
}}
'''
        
        # Deno permissions: deny network, allow read for spec only
        deno_args = [
            "--deny-net",
            f"--allow-read={spec_file}",
            "--deny-write",
            "--deny-env",
            "--deny-run",
        ]
        
        return await self._run_deno(js_template, deno_args)

    async def run_execute(
        self,
        code: str,
        api_token: str,
        api_host: str,
    ) -> Dict[str, Any]:
        """Execute JavaScript code with `mist` client available.
        
        Args:
            code: JavaScript async arrow function to execute
            api_token: Mist API token
            api_host: Mist API host (e.g., api.mist.com)
        
        Returns:
            Result of the function execution or error dict
        """
        # Build JavaScript wrapper with mist client
        # Use json.dumps to safely escape token/host (prevents JS injection)
        safe_host = _js_safe_string(api_host)
        safe_token = _js_safe_string(api_token)
        js_template = f'''// Freeze output function so user code can't override it
const __output = console.log.bind(console);

const mist = Object.freeze({{
  async request({{method = "GET", path, body, params}}) {{
    const _host = {safe_host};
    const _token = {safe_token};
    const url = new URL(`https://${{_host}}${{path}}`);
    
    if (params) {{
      Object.entries(params).forEach(([k, v]) => {{
        if (v !== undefined && v !== null) {{
          url.searchParams.set(k, String(v));
        }}
      }});
    }}
    
    const opts = {{
      method,
      headers: {{
        'Authorization': `Token ${{_token}}`,
        'Content-Type': 'application/json',
      }},
    }};
    
    if (body && method !== 'GET') {{
      opts.body = JSON.stringify(body);
    }}
    
    const resp = await fetch(url.toString(), opts);
    const data = await resp.json();
    
    if (!resp.ok) {{
      throw new Error(`Mist API error ${{resp.status}}: ${{JSON.stringify(data)}}`);
    }}
    
    return data;
  }}
}});

const fn = {code};

try {{
  const result = await fn();
  __output(JSON.stringify(result, null, 2));
}} catch(e) {{
  __output(JSON.stringify({{error: e.message, stack: e.stack}}));
}}
'''
        
        # Deno permissions: allow network for Mist hosts only
        allowed_hosts = ",".join(self.MIST_HOSTS)
        deno_args = [
            f"--allow-net={allowed_hosts}",
            "--deny-read",
            "--deny-write",
            "--deny-env",
            "--deny-run",
        ]
        
        return await self._run_deno(js_template, deno_args)
