"""
Response formatting and summarization utilities
"""
from typing import Any


def summarize_devices(data: list[dict[str, Any]]) -> str:
    """
    Summarize device list with counts by type, status, and site
    
    Example output:
    "12 devices across 3 sites:
     - 8 APs (7 connected, 1 disconnected)
     - 3 switches (all connected)
     - 1 gateway (connected)"
    """
    if not data:
        return "No devices found"
    
    total = len(data)
    
    # Count by type
    by_type: dict[str, dict[str, int]] = {}
    by_site: dict[str, int] = {}
    
    for device in data:
        device_type = device.get("type", "unknown")
        status = device.get("status", "unknown")
        site_name = device.get("site_name") or device.get("site_id", "unknown")
        
        # Count by type and status
        if device_type not in by_type:
            by_type[device_type] = {}
        by_type[device_type][status] = by_type[device_type].get(status, 0) + 1
        
        # Count by site
        by_site[site_name] = by_site.get(site_name, 0) + 1
    
    # Build summary
    lines = [f"{total} device{'s' if total != 1 else ''} across {len(by_site)} site{'s' if len(by_site) != 1 else ''}:"]
    
    for device_type, statuses in sorted(by_type.items()):
        type_total = sum(statuses.values())
        status_parts = []
        for status, count in sorted(statuses.items()):
            status_parts.append(f"{count} {status}")
        status_str = ", ".join(status_parts)
        lines.append(f"  - {type_total} {device_type}{'s' if type_total != 1 else ''} ({status_str})")
    
    return "\n".join(lines)


def summarize_sites(data: list[dict[str, Any]]) -> str:
    """
    Summarize site list with count and names
    
    Example output:
    "5 sites: HQ-Office, SF-Branch, NYC-Office, Denver-Lab, Austin-Warehouse"
    """
    if not data:
        return "No sites found"
    
    total = len(data)
    names = [site.get("name", "Unnamed") for site in data]
    
    if total <= 10:
        return f"{total} site{'s' if total != 1 else ''}: {', '.join(names)}"
    else:
        first_five = ", ".join(names[:5])
        return f"{total} sites (showing first 5): {first_five}, ..."


def summarize_clients(data: list[dict[str, Any]]) -> str:
    """
    Summarize client list with count by type and top talkers
    
    Example output:
    "47 clients (32 wireless, 15 wired)
     Top talkers: user-laptop-42 (2.3 GB), conference-tv (1.8 GB)"
    """
    if not data:
        return "No clients found"
    
    total = len(data)
    
    # Count by type
    by_type: dict[str, int] = {}
    for client in data:
        client_type = "wireless" if client.get("is_wireless") else "wired"
        by_type[client_type] = by_type.get(client_type, 0) + 1
    
    # Find top talkers by data usage
    clients_with_usage = [
        (c.get("hostname") or c.get("mac", "unknown"), 
         c.get("tx_bytes", 0) + c.get("rx_bytes", 0))
        for c in data
    ]
    top_talkers = sorted(clients_with_usage, key=lambda x: x[1], reverse=True)[:3]
    
    # Build summary
    type_parts = [f"{count} {type_}" for type_, count in sorted(by_type.items())]
    summary = f"{total} client{'s' if total != 1 else ''} ({', '.join(type_parts)})"
    
    if top_talkers and top_talkers[0][1] > 0:
        talker_parts = []
        for name, bytes_used in top_talkers:
            gb = bytes_used / (1024**3)
            if gb >= 0.1:  # Only show if > 100 MB
                talker_parts.append(f"{name} ({gb:.1f} GB)")
        if talker_parts:
            summary += f"\nTop talkers: {', '.join(talker_parts)}"
    
    return summary


def truncate_response(data: Any, max_items: int = 50) -> tuple[Any, dict[str, Any]]:
    """
    Truncate response data to max_items and return pagination info
    
    Returns: (truncated_data, pagination_info)
    """
    pagination = {"truncated": False, "total": 0, "returned": 0}
    
    if isinstance(data, list):
        total = len(data)
        pagination["total"] = total
        
        if total > max_items:
            pagination["truncated"] = True
            pagination["returned"] = max_items
            return data[:max_items], pagination
        else:
            pagination["returned"] = total
            return data, pagination
    
    elif isinstance(data, dict) and "results" in data:
        results = data["results"]
        total = len(results)
        pagination["total"] = total
        
        if total > max_items:
            pagination["truncated"] = True
            pagination["returned"] = max_items
            data["results"] = results[:max_items]
            return data, pagination
        else:
            pagination["returned"] = total
            return data, pagination
    
    # Not a list or paginated response
    return data, pagination


def format_error(status_code: int, message: str) -> dict[str, Any]:
    """
    Format an error response in a friendly way
    
    Returns a structured error dict suitable for MCP tool responses
    """
    error_type = "error"
    friendly_message = message
    
    # Map common status codes to friendly messages
    if status_code == 401:
        error_type = "authentication_error"
        friendly_message = "Authentication failed. Please check your API token."
    elif status_code == 403:
        error_type = "permission_error"
        friendly_message = "Permission denied. You may not have access to this resource."
    elif status_code == 404:
        error_type = "not_found"
        friendly_message = "Resource not found. Please check the ID or name."
    elif status_code == 429:
        error_type = "rate_limit"
        friendly_message = "Rate limit exceeded. Please wait a moment and try again."
    elif status_code >= 500:
        error_type = "server_error"
        friendly_message = f"Mist API server error: {message}"
    
    return {
        "success": False,
        "error": {
            "type": error_type,
            "status_code": status_code,
            "message": friendly_message,
            "detail": message,
        }
    }
