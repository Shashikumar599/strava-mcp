"""Strava URLs, project paths and the Strava app credentials (from the environment / .env)."""

import os
from pathlib import Path

from dotenv import load_dotenv

# Resolve paths from this file, not the current directory:
# Claude Desktop launches the server from an unrelated working directory.
PROJECT_ROOT = Path(__file__).parent.parent
ENV_FILE = PROJECT_ROOT / ".env"

AUTHORIZE_URL = "https://www.strava.com/oauth/authorize"
TOKEN_URL = "https://www.strava.com/oauth/token"
DEAUTHORIZE_URL = "https://www.strava.com/oauth/deauthorize"
ACTIVITIES_URL = "https://www.strava.com/api/v3/athlete/activities"
ACTIVITY_URL = "https://www.strava.com/api/v3/activities/{activity_id}"
STREAMS_URL = ACTIVITY_URL + "/streams"


def get_client_credentials() -> tuple[str, str]:
    """Return (client_id, client_secret) from .env."""
    load_dotenv(ENV_FILE)
    client_id = os.getenv("STRAVA_CLIENT_ID")
    client_secret = os.getenv("STRAVA_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise RuntimeError(f"Missing STRAVA_CLIENT_ID or STRAVA_CLIENT_SECRET in {ENV_FILE}")
    return client_id, client_secret
