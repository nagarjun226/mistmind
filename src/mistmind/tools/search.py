"""
mist_search tool - Universal search across all Mist objects
"""
import json
import logging
from typing import Any, Optional

from mcp.types import Tool, TextContent

from mistmind.server import get_server, get_client, get_context, handle_tool_error
from mistmind.formatter import truncate_response

logger = logging.getLogger(__name__)


@get_server().tool()
async def mist_search(
    query: str,
    search_type: str = "all",
    scope: str = "org",
    site_id: Optional[str] = None,
    start_time: Optional[int] = None,
    end_time: Optional[int] = None,
    limit: int = 50
) -> list[TextContent]:
    """
    Universal search across devices, clients, events, and alarms.
    
    Use this when you need flexible, keyword-based search across multiple object types.
    For structured queries with specific filters, use mist_query instead.
    
    WHEN TO USE:
    - To find anything by keyword (device name, MAC address, client name)
    - To search events/alarms by text
    - When you don't know exactly where the data lives
    - For troubleshooting with partial information
    
    EXAMPLES:
    
    Q: "Find anything related to 'AP-42'"
    A: mist_search(query="AP-42", search_type="all")
    
    Q: "Search for client with MAC aa:bb:cc:dd:ee:ff"
    A: mist_search(query="aa:bb:cc:dd:ee:ff", search_type="clients")
    
    Q: "Find all events mentioning 'auth failure'"
    A: mist_search(query="auth failure", search_type="events")
    
    Q: "Search for alarms in the last hour"
    A: mist_search(query="*", search_type="alarms", start_time=<timestamp>)
    
    Args:
        query: Search query string (supports wildcards and keywords)
        search_type: What to search
            - "all": Search everything (devices, clients, events)
            - "devices": Devices only
            - "clients": Clients only  
            - "events": System events
            - "alarms": Active alarms
        scope: Search scope
            - "org": Organization-wide (default)
            - "site": Site-specific (requires site_id)
        site_id: Site ID (required if scope="site")
        start_time: Unix timestamp for time range (for events/alarms)
        end_time: Unix timestamp for time range (for events/alarms)
        limit: Maximum items to return (default: 50)
    
    Returns:
        Structured response with _summary field for human-readable overview
    """
    try:
        client = get_client()
        context = get_context()
        
        # Auto-resolve org for org scope
        org_id = None
        if scope == "org":
            org_id = await context.get_org_id()
        elif scope == "site" and not site_id:
            return handle_tool_error(ValueError("site_id required when scope='site'"))
        
        response: dict[str, Any] = {
            "success": True,
            "query": query,
            "search_type": search_type,
            "scope": scope,
        }
        
        # Build search parameters
        params = {
            "query": query,
            "limit": limit,
        }
        if start_time:
            params["start"] = start_time
        if end_time:
            params["end"] = end_time
        
        results_by_type = {}
        
        if search_type in ["all", "devices"]:
            # Search devices
            if scope == "org":
                endpoint = f"/api/v1/orgs/{org_id}/devices/search"
            else:
                endpoint = f"/api/v1/sites/{site_id}/devices/search"
            
            result = await client.get(endpoint, params=params)
            devices = result.get("results", [])
            results_by_type["devices"] = devices
        
        if search_type in ["all", "clients"]:
            # Search clients
            if scope == "org":
                endpoint = f"/api/v1/orgs/{org_id}/clients/search"
            else:
                endpoint = f"/api/v1/sites/{site_id}/stats/clients/search"
            
            result = await client.get(endpoint, params=params)
            clients = result if isinstance(result, list) else result.get("results", [])
            results_by_type["clients"] = clients
        
        if search_type in ["all", "events"]:
            # Search events
            if scope == "org":
                endpoint = f"/api/v1/orgs/{org_id}/events/search"
            else:
                endpoint = f"/api/v1/sites/{site_id}/events/search"
            
            result = await client.get(endpoint, params=params)
            events = result.get("results", [])
            results_by_type["events"] = events
        
        if search_type in ["all", "alarms"]:
            # Search alarms
            if scope == "org":
                endpoint = f"/api/v1/orgs/{org_id}/alarms/search"
            else:
                endpoint = f"/api/v1/sites/{site_id}/alarms/search"
            
            result = await client.get(endpoint, params=params)
            alarms = result.get("results", [])
            results_by_type["alarms"] = alarms
        
        # Combine and truncate results
        if search_type == "all":
            # Combine all results
            all_results = []
            for result_type, items in results_by_type.items():
                for item in items:
                    item["_result_type"] = result_type
                    all_results.append(item)
            
            truncated_results, pagination = truncate_response(all_results, limit)
            
            response["data"] = truncated_results
            response["pagination"] = pagination
            
            # Build summary
            summary_parts = [f"Search results for '{query}':"]
            for result_type, items in results_by_type.items():
                if items:
                    summary_parts.append(f"  - {len(items)} {result_type}")
            
            response["_summary"] = "\n".join(summary_parts)
        
        else:
            # Single type search
            results = results_by_type.get(search_type, [])
            truncated_results, pagination = truncate_response(results, limit)
            
            response["data"] = truncated_results
            response["pagination"] = pagination
            response["_summary"] = f"Found {len(results)} {search_type} matching '{query}'"
        
        return [TextContent(
            type="text",
            text=json.dumps(response, indent=2, default=str)
        )]
    
    except Exception as e:
        return handle_tool_error(e)
