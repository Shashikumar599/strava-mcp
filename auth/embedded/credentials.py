"""StravaCredentials for embedded mode: Strava tokens from our own store, refreshed on demand."""

import threading
import time

from auth.ports import StravaTokens, StravaTokenStore
from strava import oauth as strava_oauth

EXPIRY_BUFFER_SECONDS = 60


class EmbeddedStravaCredentials:
    def __init__(self, store: StravaTokenStore):
        self.store = store
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()

    def get_access_token(self, subject: str) -> str:
        """A valid Strava access token for this athlete, refreshing (and saving the rotated
        refresh token) when it expires within EXPIRY_BUFFER_SECONDS."""
        # Two tool calls can run at once. Without the lock both could refresh with the same
        # refresh token; after Strava rotates it, the second refresh may fail.
        with self._lock_for(subject):
            tokens = self.store.load_strava_tokens(subject)
            if tokens is None:
                raise RuntimeError("No Strava connection for this user. Reconnect the server in your MCP client.")
            if time.time() < tokens.expires_at - EXPIRY_BUFFER_SECONDS:
                return tokens.access_token
            try:
                data = strava_oauth.refresh(tokens.refresh_token)
            except RuntimeError as e:
                raise RuntimeError(f"{e}. Reconnect the server in your MCP client.") from e
            fresh = StravaTokens(data["access_token"], data["refresh_token"], data["expires_at"])
            self.store.save_strava_tokens(subject, fresh)
            return fresh.access_token

    def _lock_for(self, subject: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault(subject, threading.Lock())
