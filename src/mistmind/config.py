"""
Configuration management for MistMind
"""
import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class ServerConfig:
    """Server configuration loaded from environment variables"""
    
    api_token: str
    api_host: str = "https://api.mist.com"
    debug: bool = False
    enable_writes: bool = False
    max_response_items: int = 50
    request_timeout: int = 30
    
    @classmethod
    def from_env(cls) -> "ServerConfig":
        """Create configuration from environment variables"""
        return cls(
            api_token=os.getenv("MIST_APITOKEN", ""),
            api_host=os.getenv("MIST_HOST", "https://api.mist.com").rstrip("/"),
            debug=os.getenv("MISTMIND_DEBUG", "").lower() in ("1", "true", "yes"),
            enable_writes=os.getenv("MISTMIND_ENABLE_WRITES", "").lower() in ("1", "true", "yes"),
            max_response_items=int(os.getenv("MISTMIND_MAX_ITEMS", "50")),
            request_timeout=int(os.getenv("MISTMIND_TIMEOUT", "30")),
        )
    
    def validate(self) -> list[str]:
        """Validate configuration and return list of errors"""
        errors = []
        
        if not self.api_token:
            errors.append("MIST_APITOKEN is required")
        
        if not self.api_host.startswith("http"):
            errors.append("MIST_HOST must be a valid URL")
        
        if self.max_response_items < 1:
            errors.append("MISTMIND_MAX_ITEMS must be positive")
        
        if self.request_timeout < 1:
            errors.append("MISTMIND_TIMEOUT must be positive")
        
        return errors
