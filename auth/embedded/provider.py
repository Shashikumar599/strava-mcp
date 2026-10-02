"""Our authorization server's logic, plugged into the MCP SDK.

The SDK owns the HTTP endpoints (/register, /authorize, /token, /revoke, metadata) and
the protocol checks (PKCE, redirect_uri matching, code/refresh expiry, scope subsets).
This class makes the decisions and talks to storage, through the OAuthStore port only.

Login: authorize() parks the request and sends the browser to our consent page
(consent.py); after Approve it goes on to Strava, and StravaCallback (callback.py)
finishes it and issues our authorization code.
"""

import time

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from auth.embedded import policy
from auth.embedded.consent import PATH as CONSENT_PATH
from auth.ports import Grant, OAuthStore, PendingAuth
from auth.settings import Settings


class EmbeddedAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    def __init__(self, store: OAuthStore, settings: Settings):
        self.store = store
        self.settings = settings

    # ---------- Client registration (POST /register) ----------

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        for uri in client_info.redirect_uris or []:
            if not policy.is_allowed_redirect_uri(str(uri)):
                raise RegistrationError(
                    error="invalid_redirect_uri",
                    error_description=f"Redirect URI not allowed: {uri}",
                )
        self.store.save_client(client_info.client_id, client_info.model_dump_json())

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        info_json = self.store.get_client(client_id)
        return OAuthClientInformationFull.model_validate_json(info_json) if info_json else None

    # ---------- Authorization (GET /authorize) ----------

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        """Park the client's request (not yet approved) and send the browser to OUR consent page.
        Only after the user approves there does the browser go on to Strava (consent.py)."""
        our_state = policy.new_secret()
        self.store.save_pending(
            our_state,
            PendingAuth(
                client_id=client.client_id,
                params={
                    **params.model_dump(mode="json"),  # includes the client's own `state`
                    "approved": False,  # set only by an Approve on the consent page
                    "csrf": policy.new_secret(),  # ties the Approve POST to the page we served
                },
                expires_at=time.time() + policy.PENDING_TTL,
            ),
        )
        return construct_redirect_uri(f"{self.settings.base_url}{CONSENT_PATH}", state=our_state)

    # ---------- Code exchange (POST /token, grant_type=authorization_code) ----------

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        stored = self.store.get_auth_code(authorization_code)  # look only; don't use it up yet
        if stored is None or stored.grant.client_id != client.client_id:
            return None
        g = stored.grant
        return AuthorizationCode(
            code=authorization_code,
            scopes=g.scopes,
            expires_at=g.expires_at,
            client_id=g.client_id,
            code_challenge=stored.code_challenge,
            redirect_uri=stored.redirect_uri,
            redirect_uri_provided_explicitly=stored.redirect_uri_explicit,
            resource=g.resource,
            subject=g.subject,
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        # The SDK has checked PKCE and redirect_uri by now. Consuming is atomic: if two
        # requests race with the same code, only one gets past this line.
        stored = self.store.consume_auth_code(authorization_code.code)
        if stored is None:
            raise TokenError(error="invalid_grant", error_description="Authorization code already used or expired")
        return self._issue_tokens(stored.grant.client_id, stored.grant.subject, stored.grant.scopes, stored.grant.resource)

    # ---------- Refresh (POST /token, grant_type=refresh_token) ----------

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        grant = self.store.get_refresh_token(refresh_token)
        if grant is None or grant.client_id != client.client_id:
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=grant.client_id,
            scopes=grant.scopes,
            expires_at=int(grant.expires_at),
            resource=grant.resource,
            subject=grant.subject,
        )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]
    ) -> OAuthToken:
        # Rotation: the old refresh token dies here (atomically), then a new pair is issued.
        # The SDK has already rejected `scopes` wider than the original grant.
        old = self.store.consume_refresh_token(refresh_token.token, client.client_id)
        if old is None:
            raise TokenError(error="invalid_grant", error_description="Refresh token already used or expired")
        return self._issue_tokens(old.client_id, old.subject, scopes, old.resource)

    # ---------- Every MCP request (Authorization: Bearer ...) ----------

    async def load_access_token(self, token: str) -> AccessToken | None:
        grant = self.store.get_access_token(token)
        if grant is None:
            return None
        # The SDK then checks token.resource == our /mcp URL (validate_token_resource=True).
        return AccessToken(
            token=token,
            client_id=grant.client_id,
            scopes=grant.scopes,
            expires_at=int(grant.expires_at),
            resource=grant.resource,
            subject=grant.subject,
        )

    # ---------- Revocation (POST /revoke) ----------

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        self.store.revoke_token(token.token)

    # ---------- Helpers ----------

    def _issue_tokens(self, client_id: str, subject: str, scopes: list[str], resource: str | None) -> OAuthToken:
        now = time.time()
        access, refresh = policy.new_secret(), policy.new_secret()
        self.store.save_access_token(
            access, Grant(client_id, subject, scopes, resource, now + policy.ACCESS_TOKEN_TTL)
        )
        self.store.save_refresh_token(
            refresh, Grant(client_id, subject, scopes, resource, now + policy.REFRESH_TOKEN_TTL)
        )
        return OAuthToken(
            access_token=access,
            refresh_token=refresh,
            expires_in=policy.ACCESS_TOKEN_TTL,
            scope=" ".join(scopes),
        )
