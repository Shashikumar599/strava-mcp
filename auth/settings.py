"""Server settings, read once from the environment (.env) at startup."""

import os
from dataclasses import dataclass
from urllib.parse import urlparse

from dotenv import load_dotenv

from auth.stores import DEFAULT_DATABASE_URL
from strava.config import ENV_FILE

AUTH_MODES = ("embedded", "external")


@dataclass(frozen=True)
class Settings:
    # Public URL of this server. Every other URL is derived from it, so hosting it publicly
    # (e.g. https://<app>.fly.dev) only means changing BASE_URL. 127.0.0.1 rather than localhost:
    # "localhost" may resolve to IPv6 ::1 first, where the server isn't listening.
    base_url: str = "http://127.0.0.1:8000"
    database_url: str = DEFAULT_DATABASE_URL
    auth_mode: str = "embedded"  # "embedded": we are the OAuth server; "external": e.g. Descope

    @property
    def public_host(self) -> str:
        """Host part of BASE_URL as clients send it in the Host header (e.g. strava-mcp.fly.dev)."""
        return urlparse(self.base_url).netloc

    @property
    def mcp_url(self) -> str:
        """The protected resource: what tokens are issued for (RFC 8707 `resource`)."""
        return f"{self.base_url}/mcp"

    @property
    def strava_redirect_uri(self) -> str:
        return f"{self.base_url}/strava/callback"

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv(ENV_FILE)
        settings = cls(
            base_url=os.getenv("BASE_URL", cls.base_url).rstrip("/"),
            database_url=os.getenv("DATABASE_URL", cls.database_url),
            auth_mode=os.getenv("AUTH_MODE", cls.auth_mode),
        )
        if settings.auth_mode not in AUTH_MODES:
            raise ValueError(f"AUTH_MODE must be one of {AUTH_MODES}, got '{settings.auth_mode}'")
        return settings
