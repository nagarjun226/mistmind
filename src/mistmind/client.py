"""
Mist API HTTP client with pagination support
"""
import logging
from typing import Any, Optional
from urllib.parse import urljoin

import httpx

from mistmind.config import ServerConfig

logger = logging.getLogger(__name__)


class MistAPIError(Exception):
    """Base exception for Mist API errors"""
    
    def __init__(self, status_code: int, message: str, detail: Optional[dict] = None):
        self.status_code = status_code
        self.message = message
        self.detail = detail or {}
        super().__init__(f"HTTP {status_code}: {message}")


class MistAPIClient:
    """Async HTTP client for Mist API with automatic pagination"""
    
    def __init__(self, config: ServerConfig):
        self.config = config
        self.base_url = config.api_host
        self._client: Optional[httpx.AsyncClient] = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self._ensure_client()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()
    
    async def _ensure_client(self):
        """Ensure HTTP client is initialized"""
        if self._client is None:
            headers = {
                "Authorization": f"Bearer {self.config.api_token}",
                "Content-Type": "application/json",
            }
            self._client = httpx.AsyncClient(
                headers=headers,
                timeout=self.config.request_timeout,
                follow_redirects=True,
            )
    
    async def close(self):
        """Close the HTTP client"""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    def _build_url(self, path: str) -> str:
        """Build full URL from path"""
        # Remove leading slash to avoid double slashes
        path = path.lstrip("/")
        return urljoin(self.base_url, path)
    
    async def _request(
        self,
        method: str,
        path: str,
        params: Optional[dict] = None,
        json: Optional[dict] = None,
    ) -> dict[str, Any]:
        """Make HTTP request with error handling"""
        await self._ensure_client()
        
        url = self._build_url(path)
        
        logger.debug(f"{method} {url}")
        if params:
            logger.debug(f"Params: {params}")
        if json:
            logger.debug(f"JSON: {json}")
        
        try:
            response = await self._client.request(
                method=method,
                url=url,
                params=params,
                json=json,
            )
            
            # Handle different status codes
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 204:
                return {}  # No content
            elif response.status_code == 401:
                raise MistAPIError(401, "Unauthorized - check API token")
            elif response.status_code == 403:
                raise MistAPIError(403, "Forbidden - insufficient permissions")
            elif response.status_code == 404:
                raise MistAPIError(404, "Resource not found")
            elif response.status_code == 429:
                raise MistAPIError(429, "Rate limit exceeded")
            else:
                # Try to get error details from response
                try:
                    error_data = response.json()
                    message = error_data.get("detail", str(error_data))
                except Exception:
                    message = response.text or "Unknown error"
                
                raise MistAPIError(response.status_code, message)
        
        except httpx.TimeoutException:
            raise MistAPIError(408, "Request timeout")
        except httpx.NetworkError as e:
            raise MistAPIError(503, f"Network error: {str(e)}")
        except MistAPIError:
            raise
        except Exception as e:
            raise MistAPIError(500, f"Unexpected error: {str(e)}")
    
    async def get(
        self,
        path: str,
        params: Optional[dict] = None,
        follow_pagination: bool = True,
    ) -> dict[str, Any]:
        """
        GET request with automatic pagination support
        
        If the response contains a 'next' field and follow_pagination is True,
        automatically fetch all pages and combine results.
        """
        result = await self._request("GET", path, params=params)
        
        # Check if response has pagination
        if not follow_pagination or "next" not in result:
            return result
        
        # Handle pagination
        results = result.get("results", [])
        next_url = result.get("next")
        
        while next_url:
            logger.debug(f"Following pagination: {next_url}")
            
            # Extract just the path and query from next URL
            # The next URL is typically a full URL, we need just the path
            if next_url.startswith("http"):
                from urllib.parse import urlparse
                parsed = urlparse(next_url)
                next_path = parsed.path
                # Parse query string manually
                next_params = {}
                if parsed.query:
                    for param in parsed.query.split("&"):
                        if "=" in param:
                            key, value = param.split("=", 1)
                            next_params[key] = value
            else:
                next_path = next_url
                next_params = {}
            
            next_result = await self._request("GET", next_path, params=next_params)
            
            if "results" in next_result:
                results.extend(next_result["results"])
            
            next_url = next_result.get("next")
        
        # Return combined results
        result["results"] = results
        if "next" in result:
            del result["next"]  # Remove pagination marker
        
        return result
    
    async def post(
        self,
        path: str,
        json: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> dict[str, Any]:
        """POST request"""
        return await self._request("POST", path, params=params, json=json)
    
    async def put(
        self,
        path: str,
        json: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> dict[str, Any]:
        """PUT request"""
        return await self._request("PUT", path, params=params, json=json)
    
    async def delete(
        self,
        path: str,
        params: Optional[dict] = None,
    ) -> dict[str, Any]:
        """DELETE request"""
        return await self._request("DELETE", path, params=params)
