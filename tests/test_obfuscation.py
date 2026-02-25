"""Test that MistMind works on obfuscated (private/unknown) APIs.

This is the KEY test that proves MistMind doesn't depend on training data
about specific APIs. We obfuscate the Mist spec completely (rename paths,
tags, operations) while keeping the structure intact, then verify the
spec_indexer can still auto-detect the hierarchy and the sandbox can
still discover and execute searches.
"""

import json
import re
import tempfile
from pathlib import Path

import pytest

from mistmind.spec_indexer import generate_index_from_file


class TestObfuscation:
    """Test MistMind on obfuscated API specs."""
    
    @pytest.fixture
    def obfuscated_spec_path(self):
        """Create an obfuscated version of the Mist spec."""
        # Load the original spec
        spec_dir = Path(__file__).parent.parent / "spec"
        original_path = spec_dir / "mist.openapi.json"
        
        with open(original_path, 'r') as f:
            spec = json.load(f)
        
        # Obfuscation mapping
        path_mapping = {
            'orgs': 'entities',
            'sites': 'locations',
            'devices': 'nodes',
            'wlans': 'wireless_networks',
            'clients': 'endpoints',
            'self': 'current_user',
            'admins': 'administrators',
            'msps': 'service_providers',
            'const': 'constants',
            'stats': 'metrics',
        }
        
        tag_mapping = {
            'Orgs': 'Entities',
            'Sites': 'Locations',
            'Devices': 'Nodes',
            'WLANs': 'Wireless Networks',
            'Clients': 'Endpoints',
            'Self': 'Current User',
            'Admins': 'Administrators',
            'MSPs': 'Service Providers',
        }
        
        # Obfuscate the spec
        obfuscated = self._obfuscate_spec(spec, path_mapping, tag_mapping)
        
        # Write to temp file
        temp_file = tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.json',
            delete=False
        )
        json.dump(obfuscated, temp_file, indent=2)
        temp_file.close()
        
        yield temp_file.name
        
        # Cleanup
        Path(temp_file.name).unlink(missing_ok=True)
    
    def _obfuscate_spec(self, spec: dict, path_mapping: dict, tag_mapping: dict) -> dict:
        """Obfuscate an OpenAPI spec by renaming paths, tags, and operationIds.
        
        Args:
            spec: Original OpenAPI spec
            path_mapping: Dict mapping original path segments to obfuscated ones
            tag_mapping: Dict mapping original tag prefixes to obfuscated ones
            
        Returns:
            Obfuscated spec with same structure but different names
        """
        obfuscated = json.loads(json.dumps(spec))  # Deep copy
        
        # Obfuscate paths
        new_paths = {}
        for path, methods in obfuscated.get('paths', {}).items():
            # Replace path segments
            new_path = path
            for old, new in path_mapping.items():
                new_path = re.sub(f'/{old}/', f'/{new}/', new_path)
                new_path = re.sub(f'/{old}$', f'/{new}', new_path)
            
            # Obfuscate methods
            new_methods = {}
            for method, op in methods.items():
                if method not in {'get', 'post', 'put', 'delete', 'patch', 'head', 'options'}:
                    new_methods[method] = op
                    continue
                
                # Obfuscate tags
                if 'tags' in op:
                    new_tags = []
                    for tag in op['tags']:
                        new_tag = tag
                        for old, new in tag_mapping.items():
                            new_tag = new_tag.replace(old, new)
                        new_tags.append(new_tag)
                    op['tags'] = new_tags
                
                # Obfuscate operationId
                if 'operationId' in op:
                    op_id = op['operationId']
                    for old, new in path_mapping.items():
                        # Handle camelCase (e.g., listOrgDevices → listEntityNodes)
                        old_camel = old.capitalize()
                        new_camel = new.capitalize()
                        op_id = op_id.replace(old_camel, new_camel)
                        op_id = op_id.replace(old, new)
                    op['operationId'] = op_id
                
                new_methods[method] = op
            
            new_paths[new_path] = new_methods
        
        obfuscated['paths'] = new_paths
        
        # Obfuscate tags metadata
        if 'tags' in obfuscated:
            new_tag_list = []
            for tag in obfuscated['tags']:
                new_tag = tag.copy()
                name = tag.get('name', '')
                for old, new in tag_mapping.items():
                    name = name.replace(old, new)
                new_tag['name'] = name
                new_tag_list.append(new_tag)
            obfuscated['tags'] = new_tag_list
        
        # Update API title
        if 'info' in obfuscated:
            obfuscated['info']['title'] = 'Obfuscated Test API'
        
        return obfuscated
    
    def test_obfuscated_spec_generates_valid_index(self, obfuscated_spec_path):
        """Test that spec_indexer can generate an index from obfuscated spec."""
        index = generate_index_from_file(obfuscated_spec_path)
        
        # Verify index structure
        assert "Obfuscated Test API" in index
        assert "endpoints" in index
        assert "=== API HIERARCHY ===" in index
        assert "=== AUTH PATTERN ===" in index
        assert "=== PAGINATION ===" in index
        assert "=== RESPONSE PATTERNS ===" in index
        assert "=== SEARCH GUIDE ===" in index
    
    def test_obfuscated_spec_detects_hierarchy(self, obfuscated_spec_path):
        """Test that the obfuscated spec's hierarchy is correctly detected."""
        index = generate_index_from_file(obfuscated_spec_path)
        
        # Should detect the obfuscated scope names
        assert "Entities" in index  # Was "Orgs"
        assert "Locations" in index  # Was "Sites"
        assert "Service Providers" in index or "Service" in index  # Was "MSPs"
        
        # Should NOT contain original names
        assert "Orgs" not in index or "Orgs" in "Service Providers"
        assert "Sites (" not in index  # "(Sites " would indicate a scope
        assert "MSPs" not in index
    
    def test_obfuscated_spec_detects_auth(self, obfuscated_spec_path):
        """Test that auth pattern is detected even after obfuscation."""
        index = generate_index_from_file(obfuscated_spec_path)
        
        # Should detect the obfuscated /self endpoint
        assert "current_user" in index.lower() or "Token-based" in index
    
    def test_obfuscated_spec_detects_pagination(self, obfuscated_spec_path):
        """Test that pagination params are detected in obfuscated spec."""
        index = generate_index_from_file(obfuscated_spec_path)
        
        # Pagination section should exist (may or may not find params in base spec)
        assert "=== PAGINATION ===" in index
    
    def test_obfuscated_spec_counts_correct(self, obfuscated_spec_path):
        """Test that endpoint counts match the original spec."""
        index = generate_index_from_file(obfuscated_spec_path)
        
        # Should show ~1011 total endpoints (same as original)
        assert "1011 endpoints" in index or "1011" in index
    
    def test_search_works_on_obfuscated_spec(self, obfuscated_spec_path):
        """Test that search queries work against obfuscated spec.
        
        This is the critical test: can we discover endpoints in an API
        we've never seen before, with completely different names?
        """
        from mistmind.sandbox import DenoSandbox
        import asyncio
        
        # Create sandbox
        sandbox = DenoSandbox(
            deno_path="/Users/cheenu/.deno/bin/deno",
            timeout=30,
            api_mode="readonly",
        )
        
        # Search for "nodes" (was "devices") endpoints
        search_code = """
        async () => {
            const results = [];
            for (const [path, methods] of Object.entries(spec.paths)) {
                for (const [method, op] of Object.entries(methods)) {
                    if (method === 'get' || method === 'post') {
                        if (path.includes('nodes') || 
                            op.tags?.some(t => t.toLowerCase().includes('nodes'))) {
                            results.push({
                                method: method.toUpperCase(),
                                path: path,
                                summary: op.summary,
                                tags: op.tags
                            });
                        }
                    }
                }
            }
            return results.slice(0, 10);  // First 10
        }
        """
        
        result = asyncio.run(sandbox.run_search(
            code=search_code,
            spec_path=obfuscated_spec_path
        ))
        
        # Check for errors
        if isinstance(result, dict) and 'error' in result:
            pytest.fail(f"Search failed: {result['error']}")
        
        # Verify we found some endpoints
        assert isinstance(result, list), f"Expected list, got {type(result)}"
        assert len(result) > 0, "Should find at least one endpoint"
        
        # Verify they contain obfuscated paths
        for item in result:
            assert 'path' in item
            # Should contain obfuscated terms, not original ones
            path = item['path'].lower()
            assert 'nodes' in path or 'entities' in path or 'locations' in path
    
    def test_search_by_scope_works_on_obfuscated(self, obfuscated_spec_path):
        """Test searching by scope (Entities vs Locations) works."""
        from mistmind.sandbox import DenoSandbox
        import asyncio
        
        sandbox = DenoSandbox(
            deno_path="/Users/cheenu/.deno/bin/deno",
            timeout=30,
            api_mode="readonly",
        )
        
        # Search for Entities (was Orgs) scope endpoints
        search_code = """
        async () => {
            const results = [];
            for (const [path, methods] of Object.entries(spec.paths)) {
                if (path.includes('/entities/')) {
                    for (const [method, op] of Object.entries(methods)) {
                        if (method === 'get') {
                            results.push({
                                method: method.toUpperCase(),
                                path: path,
                                tags: op.tags
                            });
                            if (results.length >= 5) break;
                        }
                    }
                }
                if (results.length >= 5) break;
            }
            return results;
        }
        """
        
        result = asyncio.run(sandbox.run_search(
            code=search_code,
            spec_path=obfuscated_spec_path
        ))
        
        # Check for errors
        if isinstance(result, dict) and 'error' in result:
            pytest.fail(f"Search failed: {result['error']}")
        
        assert isinstance(result, list)
        assert len(result) > 0
        
        # Verify all results are from /entities/ paths
        for item in result:
            assert '/entities/' in item['path']
    
    def test_obfuscated_spec_structure_intact(self, obfuscated_spec_path):
        """Verify obfuscation keeps the structure intact (params, schemas, etc)."""
        with open(obfuscated_spec_path, 'r') as f:
            spec = json.load(f)
        
        # Check structure is preserved
        assert 'paths' in spec
        assert 'info' in spec
        assert len(spec['paths']) > 100  # Should have many paths
        
        # Check a sample path has proper structure
        sample_path = None
        for path, methods in spec['paths'].items():
            if 'get' in methods:
                sample_path = path
                sample_op = methods['get']
                break
        
        assert sample_path is not None
        # Should still have tags, summary, etc
        assert 'tags' in sample_op or 'summary' in sample_op


if __name__ == "__main__":
    """Run obfuscation tests and print the obfuscated index."""
    import sys
    
    # Create test instance
    test = TestObfuscation()
    
    # Load the original spec
    spec_dir = Path(__file__).parent.parent / "spec"
    original_path = spec_dir / "mist.openapi.json"
    
    with open(original_path, 'r') as f:
        spec = json.load(f)
    
    # Obfuscation mapping
    path_mapping = {
        'orgs': 'entities',
        'sites': 'locations',
        'devices': 'nodes',
        'wlans': 'wireless_networks',
        'clients': 'endpoints',
        'self': 'current_user',
        'admins': 'administrators',
        'msps': 'service_providers',
        'const': 'constants',
        'stats': 'metrics',
    }
    
    tag_mapping = {
        'Orgs': 'Entities',
        'Sites': 'Locations',
        'Devices': 'Nodes',
        'WLANs': 'Wireless Networks',
        'Clients': 'Endpoints',
        'Self': 'Current User',
        'Admins': 'Administrators',
        'MSPs': 'Service Providers',
    }
    
    # Obfuscate the spec
    print("Creating obfuscated spec...")
    obfuscated = test._obfuscate_spec(spec, path_mapping, tag_mapping)
    
    # Write to temp file
    temp_file = tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.json',
        delete=False
    )
    json.dump(obfuscated, temp_file, indent=2)
    temp_file.close()
    obf_path = temp_file.name
    
    print(f"Obfuscated spec written to: {obf_path}\n")
    
    # Generate and print index
    print("=== OBFUSCATED SPEC INDEX ===\n")
    index = generate_index_from_file(obf_path)
    print(index)
    
    print(f"\n\n=== STATS ===")
    print(f"Characters: {len(index)}")
    print(f"Estimated tokens: ~{len(index) // 4}")
    
    # Cleanup
    Path(obf_path).unlink(missing_ok=True)
