"""
mist_query tool - The powerhouse for network data retrieval
"""
import json
import logging
from typing import Any, Optional

from mcp.types import Tool, TextContent

from mistmind.server import get_server, get_client, get_context, handle_tool_error
from mistmind.formatter import summarize_devices, summarize_clients, truncate_response

logger = logging.getLogger(__name__)


@get_server().tool()
async def mist_query(
    query_type: str,
    org_id: Optional[str] = None,
    site_id: Optional[str] = None,
    device_id: Optional[str] = None,
    filters: Optional[str] = None,
    start_time: Optional[int] = None,
    end_time: Optional[int] = None,
    duration: Optional[str] = None,
    limit: int = 50
) -> list[TextContent]:
    """
    Query network data - devices, clients, statistics, and more.
    
    This is the MAIN tool for retrieving network state and metrics.
    It intelligently routes to the right API endpoint based on query_type.
    
    WHEN TO USE:
    - To see device inventory and status
    - To find active clients (wireless/wired)
    - To get device or client statistics
    - To check port status on switches
    - To view BGP/OSPF neighbors
    - To analyze WAN usage
    
    EXAMPLES:
    
    Q: "Show me all devices"
    A: mist_query(query_type="devices")
    
    Q: "Find all disconnected APs"
    A: mist_query(query_type="devices", filters='{"type": "ap", "status": "disconnected"}')
    
    Q: "What clients are connected to SF Office?"
    A: mist_query(query_type="wireless_clients", site_id="<site-id>")
    
    Q: "Show me device stats for the last hour"
    A: mist_query(query_type="device_stats", duration="1h")
    
    Q: "Check BGP neighbors"
    A: mist_query(query_type="bgp")
    
    Args:
        query_type: What to query
            - "devices": Device inventory (APs, switches, gateways)
            - "device_stats": Device performance metrics
            - "clients": All clients (wireless + wired)
            - "wireless_clients": Wireless clients only
            - "wired_clients": Wired clients only
            - "ports": Switch port status
            - "bgp": BGP neighbor status
            - "ospf": OSPF neighbor status
            - "wan_usage": WAN link utilization
            - "org_stats": Organization-wide statistics
            - "site_stats": Site-level statistics
        
        org_id: Organization ID (auto-resolved if omitted)
        site_id: Filter to specific site
        device_id: Filter to specific device
        filters: JSON string of additional filters, e.g.:
            '{"type": "ap", "status": "connected"}'
            '{"model": "AP43", "mac": "aabbccddeeff"}'
        start_time: Unix timestamp for time range (seconds)
        end_time: Unix timestamp for time range (seconds)
        duration: Alternative to start/end time, e.g. "1h", "24h", "7d"
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
        
        # Parse filters if provided
        filter_dict = {}
        if filters:
            try:
                filter_dict = json.loads(filters)
            except json.JSONDecodeError:
                return handle_tool_error(ValueError("Invalid JSON in filters parameter"))
        
        response: dict[str, Any] = {
            "success": True,
            "query_type": query_type,
        }
        
        # Build query parameters
        params = {}
        if limit:
            params["limit"] = limit
        if start_time:
            params["start"] = start_time
        if end_time:
            params["end"] = end_time
        if duration:
            params["duration"] = duration
        
        # Add filters to params
        params.update(filter_dict)
        
        # Route to appropriate endpoint
        if query_type == "devices":
            # Device inventory
            if site_id:
                endpoint = f"/api/v1/sites/{site_id}/devices/search"
            else:
                endpoint = f"/api/v1/orgs/{org_id}/devices/search"
            
            result = await client.get(endpoint, params=params)
            devices = result.get("results", [])
            
            truncated_devices, pagination = truncate_response(devices, limit)
            
            response["data"] = truncated_devices
            response["pagination"] = pagination
            response["_summary"] = summarize_devices(truncated_devices)
        
        elif query_type == "device_stats":
            # Device statistics
            if device_id:
                endpoint = f"/api/v1/sites/{site_id}/stats/devices/{device_id}" if site_id else f"/api/v1/devices/{device_id}/stats"
            elif site_id:
                endpoint = f"/api/v1/sites/{site_id}/stats/devices"
            else:
                endpoint = f"/api/v1/orgs/{org_id}/stats/devices"
            
            result = await client.get(endpoint, params=params)
            
            response["data"] = result
            response["_summary"] = f"Device statistics retrieved for {query_type}"
        
        elif query_type in ["clients", "wireless_clients", "wired_clients"]:
            # Client data
            if site_id:
                endpoint = f"/api/v1/sites/{site_id}/stats/clients"
            else:
                endpoint = f"/api/v1/orgs/{org_id}/clients/search"
            
            # Add type filter for wireless/wired
            if query_type == "wireless_clients":
                params["type"] = "wireless"
            elif query_type == "wired_clients":
                params["type"] = "wired"
            
            result = await client.get(endpoint, params=params)
            clients = result if isinstance(result, list) else result.get("results", [])
            
            truncated_clients, pagination = truncate_response(clients, limit)
            
            response["data"] = truncated_clients
            response["pagination"] = pagination
            response["_summary"] = summarize_clients(truncated_clients)
        
        elif query_type == "ports":
            # Switch port status
            if device_id:
                endpoint = f"/api/v1/sites/{site_id}/stats/ports" if site_id else f"/api/v1/devices/{device_id}/ports"
                params["device_id"] = device_id
            elif site_id:
                endpoint = f"/api/v1/sites/{site_id}/stats/ports"
            else:
                return handle_tool_error(ValueError("site_id or device_id required for port query"))
            
            result = await client.get(endpoint, params=params)
            
            response["data"] = result
            response["_summary"] = "Switch port status retrieved"
        
        elif query_type == "bgp":
            # BGP neighbors
            if site_id:
                endpoint = f"/api/v1/sites/{site_id}/stats/bgp_peers"
            else:
                endpoint = f"/api/v1/orgs/{org_id}/stats/bgp_peers"
            
            result = await client.get(endpoint, params=params)
            peers = result if isinstance(result, list) else result.get("results", [])
            
            response["data"] = peers
            response["_summary"] = f"{len(peers)} BGP peer(s) found"
        
        elif query_type == "ospf":
            # OSPF neighbors
            if site_id:
                endpoint = f"/api/v1/sites/{site_id}/stats/ospf_neighbors"
            else:
                return handle_tool_error(ValueError("site_id required for OSPF query"))
            
            result = await client.get(endpoint, params=params)
            
            response["data"] = result
            response["_summary"] = "OSPF neighbors retrieved"
        
        elif query_type == "wan_usage":
            # WAN usage stats
            if site_id:
                endpoint = f"/api/v1/sites/{site_id}/stats/wan_usage"
            else:
                endpoint = f"/api/v1/orgs/{org_id}/stats/wan_usage"
            
            result = await client.get(endpoint, params=params)
            
            response["data"] = result
            response["_summary"] = "WAN usage statistics retrieved"
        
        elif query_type == "org_stats":
            # Organization-wide stats
            endpoint = f"/api/v1/orgs/{org_id}/stats"
            
            result = await client.get(endpoint, params=params)
            
            response["data"] = result
            response["_summary"] = (
                f"Organization statistics:\n"
                f"Total devices: {result.get('num_devices', 'N/A')}\n"
                f"Total clients: {result.get('num_clients', 'N/A')}"
            )
        
        elif query_type == "site_stats":
            # Site-level stats
            if not site_id:
                return handle_tool_error(ValueError("site_id required for site_stats query"))
            
            endpoint = f"/api/v1/sites/{site_id}/stats"
            
            result = await client.get(endpoint, params=params)
            
            response["data"] = result
            response["_summary"] = (
                f"Site statistics:\n"
                f"Active clients: {result.get('num_clients', 'N/A')}\n"
                f"Devices: {result.get('num_devices', 'N/A')}"
            )
        
        else:
            return handle_tool_error(ValueError(f"Unknown query_type: {query_type}"))
        
        return [TextContent(
            type="text",
            text=json.dumps(response, indent=2, default=str)
        )]
    
    except Exception as e:
        return handle_tool_error(e)
