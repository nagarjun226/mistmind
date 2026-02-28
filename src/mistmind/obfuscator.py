"""Runtime API Spec Obfuscation for testing code mode patterns.

When enabled, this module rewrites the OpenAPI spec at startup so the LLM
sees fictional resource names (entities, locations, nodes...) instead of real
Mist terms (orgs, sites, devices...). This proves code mode works with zero
pre-trained API knowledge.

The obfuscation mapping is defined once here and consumed by:
  - This module (to rewrite the spec)
  - sandbox.py (to de-obfuscate paths before hitting the real API)
  - server.py (to swap example snippets in tool descriptions)
  - spec_indexer.py (to strengthen the "search first" instruction)
"""

import json
import re
import tempfile
from pathlib import Path
from typing import Any


# ──────────────────────────────────────────────────────────────────────
# Single source of truth for the obfuscation mapping.
# Add new entries here and they propagate everywhere automatically.
# ──────────────────────────────────────────────────────────────────────

PATH_MAPPING: dict[str, str] = {
    "orgs": "entities",
    "sites": "locations",
    "devices": "nodes",
    "wlans": "wireless_networks",
    "clients": "endpoints",
    "self": "current_user",
    "admins": "administrators",
    "msps": "service_providers",
    "const": "constants",
    "stats": "metrics",
}

TAG_MAPPING: dict[str, str] = {
    "Orgs": "Entities",
    "Sites": "Locations",
    "Devices": "Nodes",
    "WLANs": "Wireless Networks",
    "Clients": "Endpoints",
    "Self": "Current User",
    "Admins": "Administrators",
    "MSPs": "Service Providers",
}

# Reverse mapping (obfuscated → real) for de-obfuscation in the sandbox.
REVERSE_PATH_MAPPING: dict[str, str] = {v: k for k, v in PATH_MAPPING.items()}


def _obfuscate_spec(spec: dict, path_mapping: dict, tag_mapping: dict) -> dict:
    """Obfuscate an OpenAPI spec by renaming paths, tags, and operationIds.

    Args:
        spec: Original OpenAPI spec.
        path_mapping: Dict mapping original path segments to obfuscated ones.
        tag_mapping: Dict mapping original tag prefixes to obfuscated ones.

    Returns:
        Deep-copied spec with obfuscated names.
    """
    obfuscated = json.loads(json.dumps(spec))  # Deep copy

    # --- Paths -----------------------------------------------------------
    new_paths: dict[str, Any] = {}
    for path, methods in obfuscated.get("paths", {}).items():
        new_path = path
        for old, new in path_mapping.items():
            new_path = re.sub(rf"/{old}(/|$)", rf"/{new}\1", new_path)

        new_methods: dict[str, Any] = {}
        for method, op in methods.items():
            if method not in {"get", "post", "put", "delete", "patch", "head", "options"}:
                new_methods[method] = op
                continue

            # Tags
            if "tags" in op:
                op["tags"] = [
                    _apply_mapping(tag, tag_mapping) for tag in op["tags"]
                ]

            # operationId
            if "operationId" in op:
                op_id = op["operationId"]
                for old, new in path_mapping.items():
                    op_id = op_id.replace(old.capitalize(), new.capitalize())
                    op_id = op_id.replace(old, new)
                op["operationId"] = op_id

            new_methods[method] = op

        new_paths[new_path] = new_methods

    obfuscated["paths"] = new_paths

    # --- Top-level tags --------------------------------------------------
    if "tags" in obfuscated:
        obfuscated["tags"] = [
            {**tag, "name": _apply_mapping(tag.get("name", ""), tag_mapping)}
            for tag in obfuscated["tags"]
        ]

    # --- Info ------------------------------------------------------------
    if "info" in obfuscated:
        obfuscated["info"]["title"] = "Obfuscated Test API"

    return obfuscated


def _apply_mapping(text: str, mapping: dict[str, str]) -> str:
    """Apply a string→string mapping to *text*."""
    for old, new in mapping.items():
        text = text.replace(old, new)
    return text


def obfuscate_spec_file(input_path: Path) -> Path:
    """Read an OpenAPI spec file, obfuscate it, and save to a temp file.

    Args:
        input_path: Path to the original OpenAPI spec file.

    Returns:
        Path to the newly created obfuscated temporary JSON spec file.
    """
    with open(input_path, "r") as f:
        spec = json.load(f)

    obfuscated = _obfuscate_spec(spec, PATH_MAPPING, TAG_MAPPING)

    temp_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    )
    json.dump(obfuscated, temp_file, indent=2)
    temp_file.close()

    return Path(temp_file.name)


def generate_deobfuscation_js() -> str:
    """Generate the JavaScript snippet that de-obfuscates paths at runtime.

    Returns a JS block (suitable for embedding in an f-string template) that
    maps obfuscated path segments back to real ones before the fetch call.
    """
    mapping_entries = ",\n          ".join(
        f"'{obf}': '{real}'"
        for obf, real in REVERSE_PATH_MAPPING.items()
    )
    return f"""
      // De-obfuscate path segments (runtime obfuscation mode)
      const __pathMapping = {{
          {mapping_entries}
      }};
      let realPath = path;
      for (const [obf, real] of Object.entries(__pathMapping)) {{
          realPath = realPath.replace(
              new RegExp(`/${{obf}}(?=/|\\\\?|#|$)`, 'g'),
              `/${{real}}`
          );
      }}
      path = realPath;"""
