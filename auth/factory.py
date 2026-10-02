"""Builds the auth pieces for the configured mode. The only place that picks concrete classes.

server.py calls build_auth(settings) and gets back:
  - mcp_kwargs:  what MCPServer(...) needs (auth settings + provider OR token verifier)
  - routes:      extra HTTP routes to register (e.g. /strava/callback)
  - credentials: StravaCredentials the tools use to get a Strava token for the caller
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from starlette.requests import Request
from starlette.responses import Response

from auth.embedded import policy
from auth.embedded.callback import PATH as STRAVA_CALLBACK_PATH
from auth.embedded.callback import StravaCallback
from auth.embedded.consent import PATH as CONSENT_PATH
from auth.embedded.consent import ConsentPage
from auth.embedded.credentials import EmbeddedStravaCredentials
from auth.embedded.provider import EmbeddedAuthProvider
from auth.ports import StravaCredentials
from auth.settings import Settings
from auth.stores import open_store


@dataclass
class Route:
    path: str
    methods: list[str]
    handler: Callable[[Request], Awaitable[Response]]


@dataclass
class AuthComponents:
    mcp_kwargs: dict
    credentials: StravaCredentials
    routes: list[Route] = field(default_factory=list)


def build_auth(settings: Settings) -> AuthComponents:
    if settings.auth_mode == "embedded":
        return _build_embedded(settings)
    if settings.auth_mode == "external":
        # Defined in auth/external/ (JwtTokenVerifier + DescopeStravaCredentials /
        # KeycloakStravaCredentials) but not implemented yet. When it is, this branch returns:
        #   AuthComponents(
        #       mcp_kwargs={"token_verifier": JwtTokenVerifier(...),
        #                   "auth": AuthSettings(issuer_url=<provider>, resource_server_url=settings.mcp_url,
        #                                        required_scopes=[...])},
        #       credentials=DescopeStravaCredentials(...),
        #   )
        raise NotImplementedError("AUTH_MODE=external is defined but not implemented yet; use embedded")
    raise ValueError(f"Unknown auth mode: {settings.auth_mode}")


def _build_embedded(settings: Settings) -> AuthComponents:
    store = open_store(settings.database_url)
    store.cleanup_expired()

    provider = EmbeddedAuthProvider(store, settings)
    auth_settings = AuthSettings(
        issuer_url=settings.base_url,
        resource_server_url=settings.mcp_url,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=policy.SCOPES,
            default_scopes=policy.SCOPES,
        ),
        revocation_options=RevocationOptions(enabled=True),
        required_scopes=[policy.READ_SCOPE],
        validate_token_resource=True,  # SDK rejects tokens issued for another resource (audience check)
    )
    callback = StravaCallback(oauth_store=store, strava_store=store, resource=settings.mcp_url)
    return AuthComponents(
        mcp_kwargs={"auth_server_provider": provider, "auth": auth_settings},
        credentials=EmbeddedStravaCredentials(store),
        routes=[
            Route(CONSENT_PATH, ["GET", "POST"], ConsentPage(store, settings).handle),
            Route(STRAVA_CALLBACK_PATH, ["GET"], callback.handle),
        ],
    )
