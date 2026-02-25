"""Configuration management for MistMind server."""

import os
import shutil
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ServerConfig(BaseSettings):
    """Server configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    mist_apitoken: str = Field(..., description="Mist API token (required)")
    mist_host: str = Field(
        default="api.mist.com",
        description="Mist API host",
    )
    mistmind_debug: bool = Field(
        default=False,
        description="Enable debug logging",
    )
    deno_path: Optional[str] = Field(
        default=None,
        description="Path to Deno binary",
    )
    # Safety: restrict which HTTP methods the execute tool can use
    # Default: read-only (GET only). Set to "read-write" or "all" for full access.
    # Options: "readonly" (GET only), "readwrite" (GET+POST+PUT+PATCH), "all" (includes DELETE)
    mistmind_api_mode: str = Field(
        default="readonly",
        description="API access mode: readonly (GET), readwrite (GET+POST+PUT+PATCH), all (includes DELETE)",
    )
    # Rate limiting: max sandbox executions per minute (0 = unlimited)
    mistmind_rate_limit: int = Field(
        default=30,
        description="Max sandbox executions per minute (0 = unlimited)",
    )
    # Max concurrent sandbox processes
    mistmind_max_concurrent: int = Field(
        default=5,
        description="Max concurrent Deno sandbox processes",
    )
    # BUG 8: Make spec path configurable
    mistmind_spec_path: Optional[str] = Field(
        default=None,
        description="Path to resolved OpenAPI spec JSON file",
    )

    def __init__(self, **kwargs):
        """Initialize config and auto-detect Deno path if not provided."""
        super().__init__(**kwargs)
        
        if not self.deno_path:
            # Auto-detect Deno from PATH or ~/.deno/bin/deno
            deno_in_path = shutil.which("deno")
            if deno_in_path:
                self.deno_path = deno_in_path
            else:
                home_deno = Path.home() / ".deno" / "bin" / "deno"
                if home_deno.exists():
                    self.deno_path = str(home_deno)
                else:
                    raise ValueError(
                        "Deno not found in PATH or ~/.deno/bin/deno. "
                        "Please install Deno or set DENO_PATH environment variable."
                    )

    @classmethod
    def load_from_env_file(cls, env_file: str) -> "ServerConfig":
        """Load configuration from a specific .env file."""
        return cls(_env_file=env_file)
