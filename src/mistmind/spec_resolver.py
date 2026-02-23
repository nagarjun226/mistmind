"""OpenAPI spec $ref resolver for pre-processing the Mist API spec."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Set

logger = logging.getLogger(__name__)


class SpecResolver:
    """Resolves $ref pointers in OpenAPI specs recursively."""

    def __init__(self, spec: Dict[str, Any]):
        """Initialize resolver with the OpenAPI spec."""
        self.spec = spec
        self.visited: Set[str] = set()
        self.circular_refs: Set[str] = set()

    def _get_ref_value(self, ref_path: str) -> Any:
        """Get the value at a $ref path like '#/components/schemas/Device'."""
        if not ref_path.startswith("#/"):
            raise ValueError(f"Only local refs supported: {ref_path}")

        parts = ref_path[2:].split("/")
        value = self.spec
        
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
                if value is None:
                    raise ValueError(f"Ref not found: {ref_path}")
            else:
                raise ValueError(f"Invalid ref path: {ref_path}")
        
        return value

    def _resolve_value(self, value: Any, ref_chain: Set[str]) -> Any:
        """Recursively resolve a value that may contain $refs."""
        if isinstance(value, dict):
            # Check for $ref
            if "$ref" in value:
                ref_path = value["$ref"]
                
                # Check for circular reference
                if ref_path in ref_chain:
                    # Extract schema name from ref path
                    schema_name = ref_path.split("/")[-1]
                    self.circular_refs.add(ref_path)
                    return {"$circular": schema_name}
                
                # Mark as visited
                if ref_path not in self.visited:
                    self.visited.add(ref_path)
                
                # Get the referenced value
                try:
                    ref_value = self._get_ref_value(ref_path)
                    
                    # Recursively resolve the referenced value
                    new_chain = ref_chain | {ref_path}
                    resolved = self._resolve_value(ref_value, new_chain)
                    
                    return resolved
                except Exception as e:
                    logger.warning(f"Failed to resolve {ref_path}: {e}")
                    return value
            else:
                # Recursively resolve all values in the dict
                return {
                    key: self._resolve_value(val, ref_chain)
                    for key, val in value.items()
                }
        
        elif isinstance(value, list):
            # Recursively resolve all items in the list
            return [self._resolve_value(item, ref_chain) for item in value]
        
        else:
            # Primitive value, return as-is
            return value

    def resolve(self) -> Dict[str, Any]:
        """Resolve all $refs in the spec."""
        logger.info("Starting spec resolution...")
        resolved_spec = self._resolve_value(self.spec, set())
        
        logger.info(
            f"Resolved {len(self.visited)} unique $refs, "
            f"found {len(self.circular_refs)} circular references"
        )
        
        if self.circular_refs:
            logger.info(f"Circular refs: {', '.join(sorted(self.circular_refs)[:10])}")
        
        return resolved_spec


def resolve_spec(input_path: str, output_path: str) -> None:
    """Load OpenAPI spec, resolve all $refs, and write to output path."""
    input_file = Path(input_path)
    output_file = Path(output_path)
    
    logger.info(f"Loading spec from {input_file}...")
    with open(input_file, "r") as f:
        spec = json.load(f)
    
    logger.info(f"Spec loaded: {len(spec.get('paths', {}))} paths")
    
    # Resolve refs
    resolver = SpecResolver(spec)
    resolved_spec = resolver.resolve()
    
    # Write resolved spec
    logger.info(f"Writing resolved spec to {output_file}...")
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, "w") as f:
        json.dump(resolved_spec, f, indent=2)
    
    # Get file sizes
    input_size = input_file.stat().st_size / (1024 * 1024)
    output_size = output_file.stat().st_size / (1024 * 1024)
    
    logger.info(
        f"Resolution complete! "
        f"Input: {input_size:.2f}MB, Output: {output_size:.2f}MB"
    )


if __name__ == "__main__":
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) != 3:
        print("Usage: python -m mistmind.spec_resolver <input_spec> <output_spec>")
        sys.exit(1)
    
    resolve_spec(sys.argv[1], sys.argv[2])
