"""
mist_sites tool - Site management and insights
"""
import json
import logging
from typing import Any, Optional

from mcp.types import Tool, TextContent

from mistmind.server import get_server, get_client, get_context, handle_tool_error
from mistmind.formatter import summarize_sites, truncate_response

logger = logging.getLogger(__name__)


@get_server().tool()
async def mist_sites(
    action: str = "list",
    site_id: Optional[str] = None,
    site_name: Optional[str] = None,
    limit: int = 50
) -> list[TextContent]:
    """
    Manage and explore Mist sites (locations where devices are deployed).
    
    Sites are logical groupings of devices by physical location (offices, branches, warehouses).
    This tool provides site inventory, detailed info, statistics, and health metrics.
    
    WHEN TO USE:
    - To see all available sites/locations
    - To get detailed info about a specific site
    - To check site health and SLE (Service Level Expectation) metrics
    - To view site statistics (client count, device count, throughput)
    - To investigate radio resource management (RRM) or rogue APs
    
    EXAMPLES:
    
    Q: "What sites do we have?"
    A: mist_sites(action="list")
    
    Q: "Show me details about the SF Office site"
    A: mist_sites(action="info", site_name="SF Office")
    
    Q: "What are the current stats for site abc-123?"
    A: mist_sites(action="stats", site_id="abc-123")
    
    Q: "Are there any rogue APs at HQ?"
    A: mist_sites(action="rogues", site_name="HQ")
    
    Args:
        action: What to do
            - "list": List all sites in the organization
            - "info": Get detailed info about a specific site
            - "stats": Get current site statistics
            - "sles": Get Service Level Expectations (health metrics)
            - "rrm": Get Radio Resource Management info
            - "rogues": Get rogue AP detections
        
        site_id: Site ID (UUID) - can be omitted if site_name is provided
        site_name: Site name - will be resolved to ID automatically
        limit: Maximum items to return (default: 50)
    
    Returns:
        Structured response with _summary field for human-readable overview
    """
    try:
        client = get_client()
        context = get_context()
        
        response: dict[str, Any] = {"success": True, "action": action}
        
        # Resolve site if needed
        resolved_site_id = None
        if site_id:
            resolved_site_id = site_id
        elif site_name:
            resolved_site_id = await context.resolve_site(site_name)
        
        if action == "list":
            # List all sites
            org_id = await context.get_org_id()
            result = await client.get(f"/api/v1/orgs/{org_id}/sites")
            
            # Handle both list and dict responses
            sites = result if isinstance(result, list) else result.get("results", [])
            
            # Truncate and summarize
            truncated_sites, pagination = truncate_response(sites, limit)
            
            response["data"] = truncated_sites
            response["pagination"] = pagination
            response["_summary"] = summarize_sites(truncated_sites)
        
        elif action == "info":
            # Get detailed site info
            if not resolved_site_id:
                return handle_tool_error(ValueError("site_id or site_name is required for 'info' action"))
            
            site_data = await client.get(f"/api/v1/sites/{resolved_site_id}")
            
            response["data"] = site_data
            response["_summary"] = (
                f"Site: {site_data.get('name')}\n"
                f"ID: {site_data.get('id')}\n"
                f"Address: {site_data.get('address', 'Not set')}\n"
                f"Timezone: {site_data.get('timezone', 'UTC')}\n"
                f"Created: {site_data.get('created_time')}"
            )
        
        elif action == "stats":
            # Get site statistics
            if not resolved_site_id:
                return handle_tool_error(ValueError("site_id or site_name is required for 'stats' action"))
            
            stats_data = await client.get(f"/api/v1/sites/{resolved_site_id}/stats")
            
            # Build summary from stats
            num_clients = stats_data.get("num_clients", 0)
            num_devices = stats_data.get("num_devices", {})
            
            response["data"] = stats_data
            response["_summary"] = (
                f"Site Statistics:\n"
                f"Active clients: {num_clients}\n"
                f"Devices: {num_devices}\n"
                f"Uptime: {stats_data.get('uptime', 'N/A')}"
            )
        
        elif action == "sles":
            # Get Service Level Expectations
            if not resolved_site_id:
                return handle_tool_error(ValueError("site_id or site_name is required for 'sles' action"))
            
            sle_data = await client.get(f"/api/v1/sites/{resolved_site_id}/sle")
            
            response["data"] = sle_data
            response["_summary"] = "SLE (Service Level Expectation) metrics retrieved"
        
        elif action == "rrm":
            # Get Radio Resource Management info
            if not resolved_site_id:
                return handle_tool_error(ValueError("site_id or site_name is required for 'rrm' action"))
            
            rrm_data = await client.get(f"/api/v1/sites/{resolved_site_id}/rrm")
            
            response["data"] = rrm_data
            response["_summary"] = "RRM (Radio Resource Management) data retrieved"
        
        elif action == "rogues":
            # Get rogue AP detections
            if not resolved_site_id:
                return handle_tool_error(ValueError("site_id or site_name is required for 'rogues' action"))
            
            rogues_data = await client.get(f"/api/v1/sites/{resolved_site_id}/rogues")
            
            rogues = rogues_data if isinstance(rogues_data, list) else rogues_data.get("results", [])
            
            response["data"] = rogues
            response["_summary"] = (
                f"{len(rogues)} rogue AP(s) detected" if rogues
                else "No rogue APs detected"
            )
        
        else:
            return handle_tool_error(ValueError(f"Unknown action: {action}"))
        
        return [TextContent(
            type="text",
            text=json.dumps(response, indent=2, default=str)
        )]
    
    except Exception as e:
        return handle_tool_error(e)
