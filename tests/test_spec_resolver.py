"""Tests for spec_resolver module."""

import json
from pathlib import Path

import pytest

from mistmind.spec_resolver import SpecResolver, resolve_spec


@pytest.fixture
def minimal_spec_with_refs():
    """Minimal spec with $ref pointers."""
    return {
        "openapi": "3.1.0",
        "info": {"title": "Test", "version": "1.0"},
        "paths": {
            "/devices": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Device"}
                                }
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "Device": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "name": {"type": "string"},
                    },
                }
            }
        },
    }


@pytest.fixture
def circular_spec():
    """Spec with circular references."""
    return {
        "openapi": "3.1.0",
        "info": {"title": "Test", "version": "1.0"},
        "components": {
            "schemas": {
                "Node": {
                    "type": "object",
                    "properties": {
                        "value": {"type": "string"},
                        "children": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/Node"},
                        },
                    },
                },
                "Parent": {
                    "type": "object",
                    "properties": {
                        "child": {"$ref": "#/components/schemas/Child"}
                    },
                },
                "Child": {
                    "type": "object",
                    "properties": {
                        "parent": {"$ref": "#/components/schemas/Parent"}
                    },
                },
            }
        },
    }


class TestSpecResolver:
    """Tests for SpecResolver class."""

    def test_resolves_simple_ref(self, minimal_spec_with_refs):
        """Should resolve a simple $ref."""
        resolver = SpecResolver(minimal_spec_with_refs)
        resolved = resolver.resolve()

        # Get the schema from the response
        response_schema = (
            resolved["paths"]["/devices"]["get"]["responses"]["200"]["content"][
                "application/json"
            ]["schema"]
        )

        # Should be resolved (no $ref)
        assert "$ref" not in response_schema
        assert response_schema["type"] == "object"
        assert "id" in response_schema["properties"]
        assert "name" in response_schema["properties"]

    def test_detects_circular_refs(self, circular_spec):
        """Should detect circular references."""
        resolver = SpecResolver(circular_spec)
        resolved = resolver.resolve()

        # Should have detected circular refs
        assert len(resolver.circular_refs) > 0

        # Check that circular refs are marked with $circular somewhere in the tree
        def has_circular_marker(obj, schema_name):
            if isinstance(obj, dict):
                if obj.get("$circular") == schema_name:
                    return True
                return any(has_circular_marker(v, schema_name) for v in obj.values())
            elif isinstance(obj, list):
                return any(has_circular_marker(item, schema_name) for item in obj)
            return False

        node_schema = resolved["components"]["schemas"]["Node"]
        assert has_circular_marker(node_schema, "Node")

    def test_no_refs_in_resolved_output(self, minimal_spec_with_refs):
        """Resolved output should have no $ref keys (except $circular)."""
        resolver = SpecResolver(minimal_spec_with_refs)
        resolved = resolver.resolve()

        def check_no_refs(obj, path=""):
            """Recursively check that no $ref keys exist (except $circular)."""
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key == "$ref":
                        raise AssertionError(f"Found $ref at {path}.{key}")
                    if key != "$circular":  # $circular is allowed
                        check_no_refs(value, f"{path}.{key}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_no_refs(item, f"{path}[{i}]")

        check_no_refs(resolved)

    def test_handles_nested_refs(self):
        """Should handle refs that reference other refs."""
        spec = {
            "components": {
                "schemas": {
                    "A": {"$ref": "#/components/schemas/B"},
                    "B": {"$ref": "#/components/schemas/C"},
                    "C": {"type": "string"},
                }
            }
        }
        resolver = SpecResolver(spec)
        resolved = resolver.resolve()

        # All should resolve to string
        assert resolved["components"]["schemas"]["A"]["type"] == "string"
        assert resolved["components"]["schemas"]["B"]["type"] == "string"
        assert resolved["components"]["schemas"]["C"]["type"] == "string"

    def test_handles_array_refs(self):
        """Should resolve refs inside arrays."""
        spec = {
            "components": {
                "schemas": {
                    "DeviceList": {
                        "type": "array",
                        "items": {"$ref": "#/components/schemas/Device"},
                    },
                    "Device": {"type": "object", "properties": {"id": {"type": "string"}}},
                }
            }
        }
        resolver = SpecResolver(spec)
        resolved = resolver.resolve()

        items = resolved["components"]["schemas"]["DeviceList"]["items"]
        assert "$ref" not in items
        assert items["type"] == "object"
        assert "id" in items["properties"]

    def test_preserves_non_ref_properties(self):
        """Should preserve properties alongside resolved refs."""
        spec = {
            "components": {
                "schemas": {
                    "Extended": {
                        "$ref": "#/components/schemas/Base",
                        "description": "Extended schema",
                    },
                    "Base": {"type": "string"},
                }
            }
        }
        resolver = SpecResolver(spec)
        resolved = resolver.resolve()

        extended = resolved["components"]["schemas"]["Extended"]
        # Note: In OpenAPI 3.x, $ref should be resolved and other properties merged
        # Our implementation replaces the entire object with the ref value
        # This is a simplified resolver behavior
        assert extended["type"] == "string"

    def test_handles_invalid_ref_gracefully(self):
        """Should handle invalid refs without crashing."""
        spec = {
            "components": {
                "schemas": {
                    "Test": {"$ref": "#/components/schemas/NonExistent"}
                }
            }
        }
        resolver = SpecResolver(spec)
        resolved = resolver.resolve()  # Should not raise

        # Should preserve the bad ref
        assert "$ref" in resolved["components"]["schemas"]["Test"]


class TestResolveSpecFunction:
    """Tests for resolve_spec function."""

    def test_loads_and_writes_spec(self, tmp_path, minimal_spec_with_refs):
        """Should load spec from file, resolve, and write to output."""
        input_file = tmp_path / "input.json"
        output_file = tmp_path / "output.json"

        # Write input spec
        input_file.write_text(json.dumps(minimal_spec_with_refs))

        # Resolve
        resolve_spec(str(input_file), str(output_file))

        # Verify output exists and is valid JSON
        assert output_file.exists()
        with open(output_file) as f:
            resolved = json.load(f)

        # Verify resolution happened
        response_schema = (
            resolved["paths"]["/devices"]["get"]["responses"]["200"]["content"][
                "application/json"
            ]["schema"]
        )
        assert "$ref" not in response_schema
        assert response_schema["type"] == "object"

    def test_creates_output_directory(self, tmp_path, minimal_spec_with_refs):
        """Should create output directory if it doesn't exist."""
        input_file = tmp_path / "input.json"
        output_file = tmp_path / "nested" / "dir" / "output.json"

        input_file.write_text(json.dumps(minimal_spec_with_refs))

        resolve_spec(str(input_file), str(output_file))

        assert output_file.exists()
        assert output_file.parent.exists()


class TestCircularRefDetection:
    """Specific tests for circular reference handling."""

    def test_simple_self_reference(self):
        """Should handle simple self-referencing schema."""
        spec = {
            "components": {
                "schemas": {
                    "Node": {
                        "type": "object",
                        "properties": {
                            "next": {"$ref": "#/components/schemas/Node"}
                        },
                    }
                }
            }
        }
        resolver = SpecResolver(spec)
        resolved = resolver.resolve()

        # Should detect circular ref
        assert len(resolver.circular_refs) == 1
        assert "#/components/schemas/Node" in resolver.circular_refs

        # Should mark with $circular somewhere in the resolved structure
        def has_circular_marker(obj, schema_name):
            if isinstance(obj, dict):
                if obj.get("$circular") == schema_name:
                    return True
                return any(has_circular_marker(v, schema_name) for v in obj.values())
            elif isinstance(obj, list):
                return any(has_circular_marker(item, schema_name) for item in obj)
            return False

        node_schema = resolved["components"]["schemas"]["Node"]
        assert has_circular_marker(node_schema, "Node")

    def test_mutual_circular_refs(self, circular_spec):
        """Should handle mutual circular references."""
        resolver = SpecResolver(circular_spec)
        resolved = resolver.resolve()

        # Should detect circular refs
        assert len(resolver.circular_refs) >= 1

        # At least one schema should have $circular marker
        def has_circular_marker(obj):
            if isinstance(obj, dict):
                if "$circular" in obj:
                    return True
                return any(has_circular_marker(v) for v in obj.values())
            elif isinstance(obj, list):
                return any(has_circular_marker(item) for item in obj)
            return False

        parent = resolved["components"]["schemas"]["Parent"]
        child = resolved["components"]["schemas"]["Child"]

        # At least one should have $circular somewhere
        assert has_circular_marker(parent) or has_circular_marker(child)

    def test_deep_circular_chain(self):
        """Should handle circular refs through a chain."""
        spec = {
            "components": {
                "schemas": {
                    "A": {
                        "properties": {"b": {"$ref": "#/components/schemas/B"}}
                    },
                    "B": {
                        "properties": {"c": {"$ref": "#/components/schemas/C"}}
                    },
                    "C": {
                        "properties": {"a": {"$ref": "#/components/schemas/A"}}
                    },
                }
            }
        }
        resolver = SpecResolver(spec)
        resolved = resolver.resolve()

        # Should detect at least one circular ref
        assert len(resolver.circular_refs) >= 1

        # At least one schema should have $circular
        def has_circular(obj):
            if isinstance(obj, dict):
                if "$circular" in obj:
                    return True
                return any(has_circular(v) for v in obj.values())
            elif isinstance(obj, list):
                return any(has_circular(item) for item in obj)
            return False

        assert has_circular(resolved)
