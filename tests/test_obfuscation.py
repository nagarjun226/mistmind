"""Test that MistMind works on obfuscated (private/unknown) APIs.

This is the KEY test that proves MistMind doesn't depend on training data
about specific APIs. We obfuscate the Mist spec completely (rename paths,
tags, operations) while keeping the structure intact, then verify the
spec_indexer can still auto-detect the hierarchy and the sandbox can
still discover and execute searches.
"""

import asyncio
import json
import shutil
from pathlib import Path

import pytest

from mistmind.obfuscator import obfuscate_spec_file, generate_deobfuscation_js
from mistmind.spec_indexer import generate_index_from_file


def _find_deno() -> str:
    """Auto-detect Deno binary path."""
    deno = shutil.which("deno")
    if deno:
        return deno
    home_deno = Path.home() / ".deno" / "bin" / "deno"
    if home_deno.exists():
        return str(home_deno)
    pytest.skip("Deno not found")


class TestObfuscation:
    """Test MistMind on obfuscated API specs."""

    @pytest.fixture
    def obfuscated_spec_path(self):
        """Create an obfuscated version of the Mist spec."""
        spec_dir = Path(__file__).parent.parent / "spec"
        original_path = spec_dir / "mist.openapi.json"

        obfuscated_path = obfuscate_spec_file(original_path)
        yield str(obfuscated_path)
        obfuscated_path.unlink(missing_ok=True)

    # ── Index generation tests ───────────────────────────────────────

    def test_obfuscated_spec_generates_valid_index(self, obfuscated_spec_path):
        """spec_indexer can generate a valid index from obfuscated spec."""
        index = generate_index_from_file(obfuscated_spec_path)

        assert "Obfuscated Test API" in index
        assert "endpoints" in index
        assert "=== API HIERARCHY ===" in index
        assert "=== AUTH PATTERN ===" in index
        assert "=== PAGINATION ===" in index
        assert "=== RESPONSE PATTERNS ===" in index
        assert "=== SEARCH GUIDE ===" in index

    def test_obfuscated_spec_detects_hierarchy(self, obfuscated_spec_path):
        """The obfuscated scope names (Entities, Locations, …) are detected."""
        index = generate_index_from_file(obfuscated_spec_path)

        assert "Entities" in index
        assert "Locations" in index
        assert "Service Providers" in index or "Service" in index

        # Original Mist names must NOT appear as scope labels
        assert "Sites (" not in index
        assert "MSPs" not in index

    def test_obfuscated_spec_detects_auth(self, obfuscated_spec_path):
        """Auth endpoint is detected even after /self → /current_user rename."""
        index = generate_index_from_file(obfuscated_spec_path)
        assert "current_user" in index.lower() or "Token-based" in index

    def test_obfuscated_spec_detects_pagination(self, obfuscated_spec_path):
        index = generate_index_from_file(obfuscated_spec_path)
        assert "=== PAGINATION ===" in index

    def test_obfuscated_spec_counts_correct(self, obfuscated_spec_path):
        """Endpoint count matches original (~1011)."""
        index = generate_index_from_file(obfuscated_spec_path)
        assert "1011" in index

    def test_force_search_first_flag(self, obfuscated_spec_path):
        """force_search_first adds stronger instructions."""
        normal = generate_index_from_file(obfuscated_spec_path, force_search_first=False)
        forced = generate_index_from_file(obfuscated_spec_path, force_search_first=True)

        assert "CRITICAL INSTRUCTIONS:" in forced
        assert "CRITICAL INSTRUCTIONS:" not in normal
        assert "ALWAYS search" in normal

    # ── Sandbox search tests ─────────────────────────────────────────

    def test_search_works_on_obfuscated_spec(self, obfuscated_spec_path):
        """Can discover endpoints in a completely renamed API."""
        from mistmind.sandbox import DenoSandbox

        sandbox = DenoSandbox(deno_path=_find_deno(), timeout=30, api_mode="readonly")

        code = """
        async () => {
            const results = [];
            for (const [path, methods] of Object.entries(spec.paths)) {
                for (const [method, op] of Object.entries(methods)) {
                    if ((method === 'get' || method === 'post') &&
                        (path.includes('nodes') ||
                         op.tags?.some(t => t.toLowerCase().includes('nodes')))) {
                        results.push({method: method.toUpperCase(), path, summary: op.summary, tags: op.tags});
                    }
                }
            }
            return results.slice(0, 10);
        }
        """

        result = asyncio.run(sandbox.run_search(code=code, spec_path=obfuscated_spec_path))

        if isinstance(result, dict) and "error" in result:
            pytest.fail(f"Search failed: {result['error']}")

        assert isinstance(result, list)
        assert len(result) > 0, "Should find at least one endpoint"
        for item in result:
            path = item["path"].lower()
            assert "nodes" in path or "entities" in path or "locations" in path

    def test_search_by_scope_works_on_obfuscated(self, obfuscated_spec_path):
        """Searching by scope (Entities) works on obfuscated spec."""
        from mistmind.sandbox import DenoSandbox

        sandbox = DenoSandbox(deno_path=_find_deno(), timeout=30, api_mode="readonly")

        code = """
        async () => {
            const results = [];
            for (const [path, methods] of Object.entries(spec.paths)) {
                if (path.includes('/entities/')) {
                    for (const [method, op] of Object.entries(methods)) {
                        if (method === 'get') {
                            results.push({method: 'GET', path, tags: op.tags});
                            if (results.length >= 5) break;
                        }
                    }
                }
                if (results.length >= 5) break;
            }
            return results;
        }
        """

        result = asyncio.run(sandbox.run_search(code=code, spec_path=obfuscated_spec_path))

        if isinstance(result, dict) and "error" in result:
            pytest.fail(f"Search failed: {result['error']}")

        assert isinstance(result, list)
        assert len(result) > 0
        for item in result:
            assert "/entities/" in item["path"]

    def test_obfuscated_spec_structure_intact(self, obfuscated_spec_path):
        """Verify obfuscation preserves spec structure (params, schemas, etc)."""
        with open(obfuscated_spec_path, "r") as f:
            spec = json.load(f)

        assert "paths" in spec
        assert "info" in spec
        assert len(spec["paths"]) > 100

        # Sample a GET endpoint — should still have tags/summary
        for path, methods in spec["paths"].items():
            if "get" in methods:
                op = methods["get"]
                assert "tags" in op or "summary" in op
                break

    # ── De-obfuscation mapping tests ─────────────────────────────────

    def test_deobfuscation_js_generated(self):
        """generate_deobfuscation_js produces valid JS with all mappings."""
        js = generate_deobfuscation_js()
        assert "__pathMapping" in js
        assert "'entities': 'orgs'" in js
        assert "'locations': 'sites'" in js
        assert "'nodes': 'devices'" in js
        assert "'current_user': 'self'" in js

    def test_deobfuscation_round_trip(self):
        """Obfuscated paths correctly map back to real ones."""
        from mistmind.obfuscator import PATH_MAPPING, REVERSE_PATH_MAPPING

        # Every entry in PATH_MAPPING must have a reverse
        for real, obf in PATH_MAPPING.items():
            assert obf in REVERSE_PATH_MAPPING
            assert REVERSE_PATH_MAPPING[obf] == real


if __name__ == "__main__":
    """Run obfuscation tests and print the obfuscated index."""
    from mistmind.obfuscator import obfuscate_spec_file

    spec_dir = Path(__file__).parent.parent / "spec"
    original_path = spec_dir / "mist.openapi.json"

    print("Creating obfuscated spec...")
    obf_path = obfuscate_spec_file(original_path)

    print(f"Obfuscated spec written to: {obf_path}\n")

    print("=== OBFUSCATED SPEC INDEX ===\n")
    index = generate_index_from_file(str(obf_path))
    print(index)

    print(f"\n\n=== STATS ===\n")
    print(f"Characters: {len(index)}")
    print(f"Estimated tokens: ~{len(index) // 4}")

    obf_path.unlink(missing_ok=True)
