"""
mist_devices tool - Device management and firmware operations
"""
import json
import logging
from typing import Any, Optional

from mcp.types import Tool, TextContent

from mistmind.server import get_server, get_client, get_context, handle_tool_error
from mistmind.formatter import summarize_devices, truncate_response

logger = logging.getLogger(__name__)


@get_server().tool()
async def mist_devices(
    action: str = "inventory",
    org_id: Optional[str] = None,
    site_id: Optional[str] = None,
    device_id: Optional[str] = None,
    device_type: Optional[str] = None,
    limit: int = 50
) -> list[TextContent]:
    """
    Device inventory, firmware management, and configuration operations.
    
    WHEN TO USE:
    - To get complete device inventory with serial numbers
    - To search for specific devices
    - To check firmware versions across the network
    - To see available firmware updates
    - To view upgrade status
    - To review device configuration history
    
    EXAMPLES:
    
    Q: "Show me all device inventory"
    A: mist_devices(action="inventory")
    
    Q: "Find all switches"
    A: mist_devices(action="search", device_type="switch")
    
    Q: "What firmware versions are available for APs?"
    A: mist_devices(action="available_versions", device_type="ap")
    
    Q: "Check upgrade status for device xyz"
    A: mist_devices(action="upgrades", device_id="xyz")
    
    Q: "Show configuration history for device abc"
    A: mist_devices(action="config_history", device_id="abc")
    
    Args:
        action: What to do
            - "inventory": Complete device inventory with serial numbers
            - "search": Search for devices (by type, site, etc.)
            - "config_history": Configuration change history for a device
            - "last_config": Most recent configuration for a device
            - "available_versions": List available firmware versions
            - "upgrades": Check upgrade status
        
        org_id: Organization ID (auto-resolved if omitted)
        site_id: Filter to specific site
        device_id: Specific device ID (required for some actions)
        device_type: Filter by device type (ap, switch, gateway)
        limit: Maximum items to return (default: 50)
    
    Returns:
        Structured response with _summary field for human-readable overview
    """
    try:
        client = get_client()
        context = get_context()
        
        # Auto-resolve org_id if not provided
        if not org_id:
            org_id = await context.get_org_id()
        
        response: dict[str, Any] = {
            "success": True,
            "action": action,
        }
        
        if action == "inventory":
            # Get complete inventory
            endpoint = f"/api/v1/orgs/{org_id}/inventory"
            result = await client.get(endpoint)
            
            devices = result if isinstance(result, list) else result.get("results", [])
            
            # Filter by type if specified
            if device_type:
                devices = [d for d in devices if d.get("type") == device_type]
            
            # Filter by site if specified
            if site_id:
                devices = [d for d in devices if d.get("site_id") == site_id]
            
            truncated_devices, pagination = truncate_response(devices, limit)
            
            response["data"] = truncated_devices
            response["pagination"] = pagination
            
            # Build summary
            total = len(devices)
            by_type = {}
            for d in devices:
                dtype = d.get("type", "unknown")
                by_type[dtype] = by_type.get(dtype, 0) + 1
            
            summary_parts = [f"{total} device(s) in inventory:"]
            for dtype, count in sorted(by_type.items()):
                summary_parts.append(f"  - {count} {dtype}(s)")
            
            response["_summary"] = "\n".join(summary_parts)
        
        elif action == "search":
            # Search for devices
            if site_id:
                endpoint = f"/api/v1/sites/{site_id}/devices/search"
            else:
                endpoint = f"/api/v1/orgs/{org_id}/devices/search"
            
            params = {}
            if device_type:
                params["type"] = device_type
            if limit:
                params["limit"] = limit
            
            result = await client.get(endpoint, params=params)
            devices = result.get("results", [])
            
            truncated_devices, pagination = truncate_response(devices, limit)
            
            response["data"] = truncated_devices
            response["pagination"] = pagination
            response["_summary"] = summarize_devices(truncated_devices)
        
        elif action == "config_history":
            # Get configuration history
            if not device_id:
                return handle_tool_error(ValueError("device_id required for config_history action"))
            
            endpoint = f"/api/v1/sites/{site_id}/devices/{device_id}/config_cmd" if site_id else f"/api/v1/devices/{device_id}/config_cmd"
            
            result = await client.get(endpoint)
            
            response["data"] = result
            response["_summary"] = "Configuration history retrieved"
        
        elif action == "last_config":
            # Get most recent configuration
            if not device_id:
                return handle_tool_error(ValueError("device_id required for last_config action"))
            
            # Get device info which includes last config
            endpoint = f"/api/v1/sites/{site_id}/devices/{device_id}" if site_id else f"/api/v1/devices/{device_id}"
            
            result = await client.get(endpoint)
            
            response["data"] = {
                "device_id": device_id,
                "name": result.get("name"),
                "model": result.get("model"),
                "last_config": result.get("last_config"),
            }
            response["_summary"] = f"Last configuration for {result.get('name', device_id)}"
        
        elif action == "available_versions":
            # List available firmware versions
            endpoint = f"/api/v1/orgs/{org_id}/ocdevices/versions"
            
            params = {}
            if device_type:
                params["type"] = device_type
            
            result = await client.get(endpoint, params=params)
            
            versions = result if isinstance(result, list) else result.get("results", [])
            
            response["data"] = versions
            
            # Summarize versions
            if versions:
                version_list = [v.get("version", "unknown") for v in versions[:10]]
                summary = f"Available firmware versions:\n  " + "\n  ".join(version_list)
                if len(versions) > 10:
                    summary += f"\n  ... and {len(versions) - 10} more"
                response["_summary"] = summary
            else:
                response["_summary"] = "No firmware versions available"
        
        elif action == "upgrades":
            # Check upgrade status
            if device_id:
                # Specific device upgrade status
                endpoint = f"/api/v1/sites/{site_id}/devices/{device_id}/upgrade" if site_id else f"/api/v1/devices/{device_id}/upgrade"
                result = await client.get(endpoint)
                
                response["data"] = result
                response["_summary"] = (
                    f"Upgrade status: {result.get('status', 'unknown')}\n"
                    f"Current version: {result.get('current_version', 'unknown')}\n"
                    f"Target version: {result.get('target_version', 'unknown')}"
                )
            else:
                # Org-wide upgrade status
                endpoint = f"/api/v1/orgs/{org_id}/deviceupgrades"
                result = await client.get(endpoint)
                
                upgrades = result if isinstance(result, list) else result.get("results", [])
                
                response["data"] = upgrades
                response["_summary"] = f"{len(upgrades)} device upgrade(s) in progress"
        
        else:
            return handle_tool_error(ValueError(f"Unknown action: {action}"))
        
        return [TextContent(
            type="text",
            text=json.dumps(response, indent=2, default=str)
        )]
    
    except Exception as e:
        return handle_tool_error(e)
