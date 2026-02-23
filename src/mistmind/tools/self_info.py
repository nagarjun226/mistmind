"""
mist_self tool - Get account and organization information
"""
import json
import logging
from typing import Any

from mcp.types import Tool, TextContent

from mistmind.server import get_server, get_client, get_context, handle_tool_error
from mistmind.client import MistAPIError

logger = logging.getLogger(__name__)


@get_server().tool()
async def mist_self(
    action: str = "user_info"
) -> list[TextContent]:
    """
    Get information about the current user, organization, and licensing.
    
    This is typically the FIRST tool you should use to understand the organization context.
    It provides:
    - User email, privileges, and roles
    - Organization name and ID (required for other tools)
    - License inventory and expiration dates
    - API feature availability
    
    WHEN TO USE:
    - At the start of any network management conversation
    - Before calling any tools that require org_id
    - To verify authentication and permissions
    - To check license status
    
    EXAMPLES:
    
    Q: "What organization am I managing?"
    A: mist_self(action="user_info")
    
    Q: "Do we have any licenses expiring soon?"
    A: mist_self(action="licenses")
    
    Q: "What API features are available?"
    A: mist_self(action="constants")
    
    Args:
        action: What information to retrieve
            - "user_info" (default): User email, privileges, org info
            - "org_details": Detailed organization settings
            - "licenses": License inventory and expiration
            - "constants": API constants and feature flags
    
    Returns:
        Structured response with _summary field for human-readable overview
    """
    try:
        client = get_client()
        context = get_context()
        
        response: dict[str, Any] = {"success": True, "action": action}
        
        if action == "user_info":
            # Get user info (also caches org_id in context)
            user_data = await context.get_user_info()
            if not user_data:
                # Not cached yet, fetch it
                user_data = await client.get("/api/v1/self")
            
            email = user_data.get("email", "Unknown")
            privileges = user_data.get("privileges", [])
            
            # Extract org info from first privilege
            org_name = "Unknown"
            org_id = None
            if privileges:
                org_name = privileges[0].get("org_name", "Unknown")
                org_id = privileges[0].get("org_id")
            
            response["data"] = {
                "email": email,
                "first_name": user_data.get("first_name"),
                "last_name": user_data.get("last_name"),
                "privileges": privileges,
            }
            response["_summary"] = (
                f"Authenticated as: {email}\n"
                f"Organization: {org_name}\n"
                f"Org ID: {org_id}\n"
                f"Privileges: {len(privileges)} organization(s)"
            )
        
        elif action == "org_details":
            # Get detailed org info
            org_id = await context.get_org_id()
            org_data = await client.get(f"/api/v1/orgs/{org_id}")
            
            response["data"] = org_data
            response["_summary"] = (
                f"Organization: {org_data.get('name')}\n"
                f"ID: {org_data.get('id')}\n"
                f"Created: {org_data.get('created_time')}\n"
                f"Session timeout: {org_data.get('session_expiry', 'default')} hours"
            )
        
        elif action == "licenses":
            # Get license information
            org_id = await context.get_org_id()
            license_data = await client.get(f"/api/v1/orgs/{org_id}/licenses")
            
            # Summarize licenses
            licenses = license_data if isinstance(license_data, list) else [license_data]
            summary_parts = [f"License inventory for org {org_id}:"]
            
            for lic in licenses:
                lic_type = lic.get("type", "unknown")
                quantity = lic.get("quantity", 0)
                expiry = lic.get("end_time")
                summary_parts.append(f"  - {lic_type}: {quantity} licenses (expires: {expiry})")
            
            response["data"] = license_data
            response["_summary"] = "\n".join(summary_parts)
        
        elif action == "constants":
            # Get API constants
            const_data = await client.get("/api/v1/const")
            
            # Summarize available categories
            categories = list(const_data.keys()) if isinstance(const_data, dict) else []
            
            response["data"] = const_data
            response["_summary"] = (
                f"API Constants loaded:\n"
                f"Categories: {', '.join(categories[:10])}\n"
                f"Total: {len(categories)} categories available"
            )
        
        else:
            return handle_tool_error(ValueError(f"Unknown action: {action}"))
        
        return [TextContent(
            type="text",
            text=json.dumps(response, indent=2, default=str)
        )]
    
    except Exception as e:
        return handle_tool_error(e)
