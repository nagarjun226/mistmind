"""
Session context for caching org/site/device lookups
"""
import logging
from threading import Lock
from typing import Any, Optional

from mistmind.client import MistAPIClient

logger = logging.getLogger(__name__)


class SessionContext:
    """
    Thread-safe session context that caches frequently accessed data
    to reduce API calls during a conversation.
    """
    
    def __init__(self, client: MistAPIClient):
        self.client = client
        self._lock = Lock()
        
        # Cached data
        self._org_id: Optional[str] = None
        self._org_name: Optional[str] = None
        self._site_cache: dict[str, str] = {}  # name -> id
        self._device_cache: dict[str, str] = {}  # name -> id
        self._user_info: Optional[dict[str, Any]] = None
    
    async def get_org_id(self) -> str:
        """
        Get the organization ID for the authenticated user.
        Fetches from /api/v1/self and caches the result.
        """
        with self._lock:
            if self._org_id:
                return self._org_id
        
        # Fetch user info
        logger.debug("Fetching org_id from /api/v1/self")
        user_info = await self.client.get("/api/v1/self")
        
        # Extract org privileges (user can belong to multiple orgs)
        privileges = user_info.get("privileges", [])
        
        if not privileges:
            raise ValueError("User has no organization privileges")
        
        # Use the first org (or we could make this configurable)
        org_privilege = privileges[0]
        org_id = org_privilege.get("org_id")
        org_name = org_privilege.get("org_name", "Unknown")
        
        if not org_id:
            raise ValueError("Could not determine organization ID")
        
        with self._lock:
            self._org_id = org_id
            self._org_name = org_name
            self._user_info = user_info
        
        logger.info(f"Cached org_id: {org_id} ({org_name})")
        return org_id
    
    async def get_org_name(self) -> str:
        """Get the organization name (fetches org_id if needed)"""
        if not self._org_name:
            await self.get_org_id()
        return self._org_name or "Unknown"
    
    async def get_user_info(self) -> dict[str, Any]:
        """Get cached user info (fetches if needed)"""
        if not self._user_info:
            await self.get_org_id()
        return self._user_info or {}
    
    async def resolve_site(self, name_or_id: str) -> str:
        """
        Resolve a site name or ID to a site ID.
        Returns the ID if it looks like a UUID, otherwise searches by name.
        """
        # If it looks like a UUID, return as-is
        if self._looks_like_uuid(name_or_id):
            return name_or_id
        
        # Check cache
        with self._lock:
            if name_or_id in self._site_cache:
                return self._site_cache[name_or_id]
        
        # Fetch sites and search
        org_id = await self.get_org_id()
        logger.debug(f"Searching for site: {name_or_id}")
        
        result = await self.client.get(f"/api/v1/orgs/{org_id}/sites")
        sites = result if isinstance(result, list) else result.get("results", [])
        
        # Search by name (case-insensitive)
        name_lower = name_or_id.lower()
        for site in sites:
            site_name = site.get("name", "").lower()
            if site_name == name_lower:
                site_id = site.get("id")
                if site_id:
                    with self._lock:
                        self._site_cache[name_or_id] = site_id
                    logger.debug(f"Resolved site '{name_or_id}' -> {site_id}")
                    return site_id
        
        raise ValueError(f"Site not found: {name_or_id}")
    
    async def resolve_device(self, name_or_id: str, site_id: Optional[str] = None) -> str:
        """
        Resolve a device name or ID to a device ID.
        Optionally scope to a specific site.
        """
        # If it looks like a UUID, return as-is
        if self._looks_like_uuid(name_or_id):
            return name_or_id
        
        # Check cache
        cache_key = f"{site_id or 'all'}:{name_or_id}"
        with self._lock:
            if cache_key in self._device_cache:
                return self._device_cache[cache_key]
        
        # Fetch devices and search
        org_id = await self.get_org_id()
        logger.debug(f"Searching for device: {name_or_id}")
        
        if site_id:
            result = await self.client.get(f"/api/v1/sites/{site_id}/devices/search")
        else:
            result = await self.client.get(f"/api/v1/orgs/{org_id}/devices/search")
        
        devices = result.get("results", [])
        
        # Search by name (case-insensitive)
        name_lower = name_or_id.lower()
        for device in devices:
            device_name = device.get("name", "").lower()
            if device_name == name_lower:
                device_id = device.get("id")
                if device_id:
                    with self._lock:
                        self._device_cache[cache_key] = device_id
                    logger.debug(f"Resolved device '{name_or_id}' -> {device_id}")
                    return device_id
        
        raise ValueError(f"Device not found: {name_or_id}")
    
    def clear_cache(self):
        """Clear all cached data"""
        with self._lock:
            self._org_id = None
            self._org_name = None
            self._site_cache.clear()
            self._device_cache.clear()
            self._user_info = None
        logger.info("Session context cache cleared")
    
    @staticmethod
    def _looks_like_uuid(value: str) -> bool:
        """Check if a string looks like a UUID"""
        # Simple heuristic: 32+ hex chars with dashes
        clean = value.replace("-", "")
        return len(clean) >= 32 and all(c in "0123456789abcdefABCDEF" for c in clean)
