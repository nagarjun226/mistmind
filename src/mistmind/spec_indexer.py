"""Generic OpenAPI spec indexer for dynamic tool descriptions.

This module analyzes any OpenAPI spec and generates a structured text summary
suitable for LLM tool descriptions. It auto-detects API hierarchy, auth patterns,
pagination, and common response patterns without any API-specific knowledge.
"""

import json
from collections import defaultdict
from pathlib import Path
from typing import Any


def generate_index(spec: dict) -> str:
    """Generate a structured index/description from an OpenAPI spec.
    
    Args:
        spec: OpenAPI 3.x specification dict (with or without resolved $refs)
        
    Returns:
        Formatted text description suitable for LLM tool descriptions
    """
    # Extract basic info
    api_title = spec.get('info', {}).get('title', 'API')
    
    # Count total operations
    total_ops = _count_operations(spec)
    
    # Detect scopes and hierarchy
    scopes = _detect_scopes(spec)
    
    # Detect auth pattern
    auth_pattern = _detect_auth_pattern(spec)
    
    # Detect pagination patterns
    pagination = _detect_pagination(spec)
    
    # Detect response patterns
    response_patterns = _detect_response_patterns(spec)
    
    # Build the index text
    lines = [
        f"Search the {api_title} ({total_ops} endpoints).",
        "Write a JS async arrow function receiving `spec` (OpenAPI 3.1, all $refs pre-resolved).",
        "",
        "=== API HIERARCHY ===",
    ]
    
    # Add scope hierarchy
    for scope_name, scope_data in sorted(scopes.items(), key=lambda x: -x[1]['count']):
        count = scope_data['count']
        lines.append(f"{scope_name} ({count} endpoints)")
        
        # Group categories for large scopes
        categories = scope_data.get('categories', {})
        if len(categories) > 10:
            # Sub-group into themes
            themes = _group_into_themes(categories)
            for theme_name, theme_cats in themes.items():
                cat_list = ', '.join(sorted(theme_cats.keys())[:8])
                if len(theme_cats) > 8:
                    cat_list += f" +{len(theme_cats) - 8} more"
                lines.append(f"  • {theme_name}: {cat_list}")
        else:
            # List all categories
            for cat_name, cat_count in sorted(categories.items(), key=lambda x: -x[1])[:10]:
                lines.append(f"  • {cat_name} ({cat_count})")
        lines.append("")
    
    lines.extend([
        "=== AUTH PATTERN ===",
        auth_pattern,
        "",
        "=== PAGINATION ===",
        pagination,
        "",
        "=== RESPONSE PATTERNS ===",
    ])
    lines.extend(response_patterns)
    
    lines.extend([
        "",
        "=== SEARCH GUIDE ===",
        "• spec.paths[path][method] → {summary, tags, parameters, requestBody, responses}",
        "• spec.tags[] → {name, description} for each category",
        "• spec.components.schemas → data models",
        "• Common: operationId naming patterns (e.g., listOrgDevices, searchSiteClients)",
        "",
        "ALWAYS search to discover exact paths and parameters before executing.",
    ])
    
    return "\n".join(lines)


def generate_index_from_file(spec_path: str) -> str:
    """Generate index from an OpenAPI spec file.
    
    Args:
        spec_path: Path to OpenAPI JSON file
        
    Returns:
        Formatted text description
    """
    with open(spec_path, 'r') as f:
        spec = json.load(f)
    return generate_index(spec)


def _count_operations(spec: dict) -> int:
    """Count total operations across all paths."""
    http_methods = {'get', 'post', 'put', 'delete', 'patch', 'head', 'options'}
    total = 0
    for path_data in spec.get('paths', {}).values():
        total += sum(1 for method in path_data.keys() if method in http_methods)
    return total


def _detect_scopes(spec: dict) -> dict[str, dict]:
    """Auto-detect API scopes from path prefixes and tag patterns.
    
    Returns:
        Dict mapping scope name to {count, categories, path_prefix}
    """
    # First pass: collect by tags (more structured)
    tag_scopes = defaultdict(lambda: {'count': 0, 'categories': defaultdict(int)})
    
    paths = spec.get('paths', {})
    http_methods = {'get', 'post', 'put', 'delete', 'patch', 'head', 'options'}
    
    for path, methods in paths.items():
        for method, op in methods.items():
            if method not in http_methods:
                continue
            
            tags = op.get('tags', [])
            if not tags:
                continue
                
            for tag in tags:
                # Extract tag prefix (e.g., "Orgs Devices" → "Orgs")
                tag_prefix = tag.split()[0] if ' ' in tag else tag
                if tag_prefix:
                    tag_scopes[tag_prefix]['count'] += 1
                    tag_scopes[tag_prefix]['categories'][tag] += 1
    
    # Normalize and filter
    consolidated = {}
    scope_aliases = {
        'Const': 'Constants',
        'Msp': 'MSPs',
        'Org': 'Orgs',
        'Site': 'Sites',
        'Util': 'Utilities',
    }
    
    for scope_name, data in tag_scopes.items():
        # Normalize using aliases
        normalized = scope_aliases.get(scope_name, scope_name)
        
        # Skip small scopes (< 5 endpoints) unless they're named scopes
        if data['count'] < 5 and normalized not in {'Self', 'Admins', 'Installer'}:
            continue
        
        if normalized not in consolidated:
            consolidated[normalized] = data
        else:
            consolidated[normalized]['count'] += data['count']
            for cat, count in data['categories'].items():
                consolidated[normalized]['categories'][cat] += count
    
    return consolidated


def _group_into_themes(categories: dict[str, int]) -> dict[str, dict]:
    """Group categories into themes based on common patterns.
    
    Args:
        categories: Dict of category names to counts (e.g., "Orgs Devices", "Sites WLANs")
        
    Returns:
        Dict of theme names to category dicts (with scope prefixes stripped)
    """
    import re
    themes = defaultdict(dict)
    
    def strip_scope_prefix(cat_name: str) -> str:
        """Strip scope prefix from category name (e.g., 'Orgs Devices' -> 'Devices')."""
        # Common scope prefixes
        scope_prefixes = ['Orgs ', 'Sites ', 'MSPs ', 'Self ', 'Admins ', 'Installer ', 
                         'Constants ', 'Utilities ']
        for prefix in scope_prefixes:
            if cat_name.startswith(prefix):
                return cat_name[len(prefix):]
        return cat_name
    
    def matches_theme(category: str, patterns: list[str]) -> bool:
        """Check if category matches any pattern with word boundary awareness."""
        cat_lower = category.lower()
        for pattern in patterns:
            # Exact word match or hyphen-separated match
            if re.search(rf'\b{re.escape(pattern.lower())}\b', cat_lower):
                return True
            # Special case: "Stats -" prefix
            if pattern == "Stats -" and cat_lower.startswith("stats -"):
                return True
        return False
    
    # Define theme patterns (word-boundary safe)
    # Order matters: more specific patterns first to prevent misclassification
    theme_patterns = {
        'Wireless': ['WLAN', 'WLANs', 'RF Template', 'AP Template', 'RRM', 'Spectrum', 'Rogue', 
                     'Beacon', 'Rfdiag', 'vBeacon', 'Wireless'],
        'Monitoring': ['Alarm', 'Alarms', 'Event', 'Events', 'SLE', 'SLEs', 'Insight', 'Insights', 
                       'Anomaly', 'Ticket', 'Webhook', 'Webhooks', 'Log'],
        'Security': ['NAC', 'IDP', 'SecIntel', 'Antivirus', 'Security', 'Firewall', 'Anti Malware'],
        'Stats': ['Stats -', 'Stats'],  # "Stats -" must come first
        'Wired/Network': ['Network', 'Networks', 'VPN', 'EVPN', 'Gateway', 'Switch', 'Virtual Chassis'],
        'Location': ['Map', 'Maps', 'Zone', 'Zones', 'Location', 'Asset', 'RSSI'],
        'Clients': ['Clients'],
        'Core': ['Sites', 'Devices', 'Inventory', 'Licenses', 'Setting', 'Settings'],
        'Edge': ['MxEdge', 'MxTunnel', 'MxCluster'],
        'Config': ['Template', 'Profile', 'Policy'],
    }
    
    # Classify categories
    for cat_name, count in categories.items():
        # Strip scope prefix for matching
        category = strip_scope_prefix(cat_name)
        assigned = False
        
        # Try to match against themes in order
        for theme, patterns in theme_patterns.items():
            if matches_theme(category, patterns):
                # Store with stripped prefix
                themes[theme][category] = count
                assigned = True
                break
        
        if not assigned:
            themes['Other'][category] = count
    
    # Remove empty themes
    return {k: v for k, v in themes.items() if v}


def _detect_auth_pattern(spec: dict) -> str:
    """Auto-detect authentication pattern from /self or /me endpoints."""
    paths = spec.get('paths', {})
    
    # Check for /self, /me, /current_user type endpoints
    # Look for simple user context endpoints (not nested under other resources)
    auth_endpoints = []
    
    for path in paths.keys():
        path_lower = path.lower()
        parts = path.strip('/').split('/')
        
        # Look for /api/v1/self, /api/v1/me, /api/v1/current_user etc
        # (should be at level 3, not nested deeper)
        if len(parts) == 3:  # /api/v1/something
            if any(keyword in parts[2] for keyword in ['self', 'me', 'current_user', 'current-user']):
                auth_endpoints.append(path)
    
    if auth_endpoints:
        # Sort by path length (prefer shorter paths)
        auth_endpoints.sort(key=len)
        example = auth_endpoints[0]
        return f"Token-based. Use {example} to get user context/privileges."
    
    # Fallback: check for any /self or /me in path
    for path in paths.keys():
        if '/self' in path.lower() or '/me' in path.lower():
            return f"Token-based. Use {path} to get user context."
    
    # Check security schemes
    security = spec.get('components', {}).get('securitySchemes', {})
    if security:
        schemes = list(security.keys())
        return f"Auth schemes: {', '.join(schemes)}. Check spec.components.securitySchemes for details."
    
    return "Auth pattern not auto-detected. Check spec.security and spec.components.securitySchemes."


def _detect_pagination(spec: dict) -> str:
    """Detect common pagination patterns from query parameters."""
    pagination_params = defaultdict(int)
    
    paths = spec.get('paths', {})
    for methods in paths.values():
        for method, op in methods.items():
            if method not in {'get', 'post', 'put', 'delete', 'patch'}:
                continue
            
            params = op.get('parameters', [])
            for param in params:
                param_name = param.get('name', '').lower()
                if param_name in {'limit', 'page', 'start', 'end', 'offset', 'cursor'}:
                    pagination_params[param_name] += 1
    
    if not pagination_params:
        return "No standard pagination params detected."
    
    # Sort by frequency
    common = sorted(pagination_params.items(), key=lambda x: -x[1])[:3]
    params_str = ', '.join(f"{name} ({count} endpoints)" for name, count in common)
    return f"Common params: {params_str}"


def _detect_response_patterns(spec: dict) -> list[str]:
    """Detect common response patterns from schemas."""
    patterns = []
    
    # Check for array responses
    array_count = 0
    object_count = 0
    paginated_count = 0
    
    paths = spec.get('paths', {})
    for methods in paths.values():
        for method, op in methods.items():
            if method not in {'get', 'post', 'put', 'delete', 'patch'}:
                continue
            
            responses = op.get('responses', {})
            for status, response in responses.items():
                if not status.startswith('2'):  # Only success responses
                    continue
                
                content = response.get('content', {})
                for media_type, media in content.items():
                    if 'application/json' not in media_type:
                        continue
                    
                    schema = media.get('schema', {})
                    schema_type = schema.get('type')
                    
                    if schema_type == 'array':
                        array_count += 1
                    elif schema_type == 'object':
                        object_count += 1
                        # Check for pagination keys
                        props = schema.get('properties', {})
                        if any(k in props for k in ['results', 'total', 'items', 'data']):
                            paginated_count += 1
    
    if array_count > 0:
        patterns.append(f"• Array responses: {array_count} endpoints return arrays directly")
    if paginated_count > 0:
        patterns.append(f"• Paginated responses: {paginated_count} endpoints return {{results[], total}}")
    if object_count > 0:
        patterns.append(f"• Single object responses: {object_count} endpoints")
    
    if not patterns:
        patterns.append("• Response patterns vary. Check spec.paths[path][method].responses")
    
    return patterns


if __name__ == "__main__":
    """Generate and print index for the Mist spec."""
    import sys
    from pathlib import Path
    
    # Try to find the spec
    spec_path = Path(__file__).parent.parent.parent / "spec" / "mist.resolved.json"
    if not spec_path.exists():
        spec_path = Path(__file__).parent.parent.parent / "spec" / "mist.openapi.json"
    
    if not spec_path.exists():
        print("Error: Could not find mist spec file", file=sys.stderr)
        sys.exit(1)
    
    print(f"Generating index from: {spec_path}\n")
    index = generate_index_from_file(str(spec_path))
    print(index)
    print(f"\n--- Stats ---")
    print(f"Total characters: {len(index)}")
    print(f"Estimated tokens: ~{len(index) // 4}")
