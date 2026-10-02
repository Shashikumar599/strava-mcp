"""Interfaces ("ports") the auth layer depends on, and the records they exchange.

Code that needs storage or credentials depends on these Protocols, never on a concrete
backend. Any class with matching methods qualifies (structural typing, no base class),
the same way the MCP SDK defines TokenVerifier and OAuthAuthorizationServerProvider.

Implementations:
  OAuthStore, StravaTokenStore -> auth/stores/ (SqliteStore; Postgres etc. can be added)
  StravaCredentials            -> auth/embedded/ (step 3); external vaults later
"""

from dataclasses import dataclass
from typing import Protocol


# ---------- Records ----------


@dataclass(frozen=True)
class Grant:
    """What a code or token stands for: `client_id` may act for `subject` with `scopes`."""

    client_id: str
    subject: str  # the resource owner; the Strava athlete id in embedded mode
    scopes: list[str]
    resource: str | None  # RFC 8707: the MCP server URL the token is meant for
    expires_at: float


@dataclass(frozen=True)
class AuthCode:
    grant: Grant
    code_challenge: str  # PKCE
    redirect_uri: str
    redirect_uri_explicit: bool


@dataclass(frozen=True)
class PendingAuth:
    """A client's /authorize request, parked while the user logs in upstream (at Strava)."""

    client_id: str
    params: dict
    expires_at: float


@dataclass(frozen=True)
class StravaTokens:
    access_token: str
    refresh_token: str
    expires_at: int


# ---------- Storage ports ----------


class OAuthStore(Protocol):
    """Persistence for our own authorization server.

    Codes and tokens are passed in raw; implementations must store only a hash.
    Reads return None for unknown or expired entries. `consume_*` methods are
    single use: atomic read-and-delete, so concurrent callers get at most one hit.
    """

    def save_client(self, client_id: str, info_json: str) -> None: ...
    def get_client(self, client_id: str) -> str | None: ...

    def save_pending(self, state: str, pending: PendingAuth) -> None: ...
    def get_pending(self, state: str) -> PendingAuth | None: ...  # look without using it up
    def consume_pending(self, state: str) -> PendingAuth | None: ...

    def save_auth_code(self, code: str, auth_code: AuthCode) -> None: ...
    def get_auth_code(self, code: str) -> AuthCode | None: ...
    def consume_auth_code(self, code: str) -> AuthCode | None: ...

    def save_access_token(self, token: str, grant: Grant) -> None: ...
    def get_access_token(self, token: str) -> Grant | None: ...

    def save_refresh_token(self, token: str, grant: Grant) -> None: ...
    def get_refresh_token(self, token: str) -> Grant | None: ...
    def consume_refresh_token(self, token: str, client_id: str) -> Grant | None: ...

    def revoke_token(self, token: str) -> None: ...
    def cleanup_expired(self) -> int: ...


class StravaTokenStore(Protocol):
    """Persistence for each athlete's Strava tokens (one row per athlete, latest pair wins)."""

    def save_strava_tokens(self, athlete_id: str, tokens: StravaTokens) -> None: ...
    def load_strava_tokens(self, athlete_id: str) -> StravaTokens | None: ...


class Store(OAuthStore, StravaTokenStore, Protocol):
    """A backend that provides both, like SqliteStore."""


# ---------- Credentials port ----------


class StravaCredentials(Protocol):
    """Gives tools a valid Strava access token for the authenticated user.

    Embedded mode: backed by StravaTokenStore + refresh. External mode (later): e.g. a
    Descope Connection or Keycloak's stored identity-provider token. Tools only see this.
    """

    def get_access_token(self, subject: str) -> str: ...
