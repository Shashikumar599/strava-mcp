"""Decisions of our embedded authorization server: token format, lifetimes, scopes, and
which redirect URIs a client may register. Kept apart from storage (auth/stores) so every
backend follows the same policy."""

import secrets
from urllib.parse import urlparse

PENDING_TTL = 10 * 60  # while the user is on our consent page / Strava's login page
AUTH_CODE_TTL = 5 * 60
ACCESS_TOKEN_TTL = 60 * 60
REFRESH_TOKEN_TTL = 30 * 24 * 60 * 60

# Our own scopes: what an MCP client may do on THIS server (Strava's scopes are separate).
READ_SCOPE = "runs:read"
SCOPES = [READ_SCOPE]

# Strava permission our tools can't work without (private activities included).
REQUIRED_STRAVA_SCOPE = "activity:read_all"

# Where authorization codes may be sent. Blocks the "confused deputy" attack: a client
# registered with redirect_uri=https://evil.example could otherwise receive codes for your
# account, because Strava's consent screen only names our app, not the MCP client.
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}  # Claude Code, mcp-remote, MCP Inspector
ALLOWED_REDIRECT_URIS = {
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
}


def new_secret() -> str:
    """256 random bits, URL-safe: codes, tokens and state (the SDK requires >= 128)."""
    return secrets.token_urlsafe(32)


def is_allowed_redirect_uri(uri: str) -> bool:
    if uri in ALLOWED_REDIRECT_URIS:
        return True
    parsed = urlparse(uri)
    return parsed.scheme == "http" and parsed.hostname in LOOPBACK_HOSTS
