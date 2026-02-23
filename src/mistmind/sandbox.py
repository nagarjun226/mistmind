"""Deno sandbox for secure JavaScript code execution."""

import asyncio
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)


class DenoSandbox:
    """Secure sandbox for executing JavaScript code in Deno."""

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
            
            # Parse stdout as JSON
            try:
                result = json.loads(stdout_text)
                return result
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Deno output as JSON: {e}")
                logger.error(f"stdout: {stdout_text}")
                return {
                    "error": f"Invalid JSON output: {str(e)}",
                    "stderr": stderr_text,
                    "stdout": stdout_text,
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

const fn = {code};

try {{
  const result = await fn();
  console.log(JSON.stringify(result, null, 2));
}} catch(e) {{
  console.log(JSON.stringify({{error: e.message, stack: e.stack}}));
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
        js_template = f'''const mist = {{
  _host: "{api_host}",
  _token: "{api_token}",
  
  async request({{method = "GET", path, body, params}}) {{
    const url = new URL(`https://${{this._host}}${{path}}`);
    
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
        'Authorization': `Token ${{this._token}}`,
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
}};

const fn = {code};

try {{
  const result = await fn();
  console.log(JSON.stringify(result, null, 2));
}} catch(e) {{
  console.log(JSON.stringify({{error: e.message, stack: e.stack}}));
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
