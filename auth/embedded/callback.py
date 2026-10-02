"""GET /strava/callback: where Strava sends the browser after you approve (or deny).

Second half of the login that EmbeddedAuthProvider.authorize() started:
  1. find the parked client request by our `state` (single use)
  2. exchange Strava's code for Strava tokens, store them under the athlete id
  3. issue OUR authorization code for the MCP client, bound to that athlete
  4. redirect the browser to the client's redirect_uri with our code + the client's state
"""

import time

from mcp.server.auth.provider import construct_redirect_uri
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response

from auth.embedded import policy
from auth.ports import AuthCode, Grant, OAuthStore, StravaTokens, StravaTokenStore
from strava import oauth as strava_oauth

PATH = "/strava/callback"


class StravaCallback:
    def __init__(self, oauth_store: OAuthStore, strava_store: StravaTokenStore, resource: str):
        self.oauth_store = oauth_store
        self.strava_store = strava_store
        self.resource = resource  # our /mcp URL: the audience every token is bound to

    async def handle(self, request: Request) -> Response:
        query = request.query_params

        # 1. Which client request is this? (unknown/expired/replayed state -> stop here)
        pending = self.oauth_store.consume_pending(query.get("state", ""))
        if pending is None:
            return PlainTextResponse(
                "This login link has expired or was already used. Start again from your MCP client.",
                status_code=400,
            )
        params = pending.params
        # Only requests approved on our consent page get here legitimately. A Strava link built
        # by hand around the (unapproved) state from the consent page URL is refused.
        if not params.get("approved"):
            return PlainTextResponse(
                "This connection was not approved on the consent page. Start again from your MCP client.",
                status_code=400,
            )
        client_redirect = params["redirect_uri"]
        client_state = params["state"]

        def fail(error: str, description: str) -> Response:
            # Errors go back to the client (OAuth convention), so it can show them to the user.
            return RedirectResponse(
                construct_redirect_uri(client_redirect, error=error, error_description=description, state=client_state),
                status_code=302,
            )

        if "error" in query:  # e.g. you clicked Cancel on Strava's page
            return fail("access_denied", f"Strava authorization was not granted ({query['error']})")
        if policy.REQUIRED_STRAVA_SCOPE not in query.get("scope", ""):
            return fail("access_denied", "Please allow 'View data about your private activities' on Strava")

        # 2. Strava code -> Strava tokens, stored per athlete (one row per athlete)
        try:
            # blocking HTTP call: run it in a thread so the server keeps serving other requests
            data = await run_in_threadpool(strava_oauth.exchange_code, query.get("code", ""))
        except RuntimeError as e:
            return fail("server_error", str(e))
        athlete_id = str(data["athlete"]["id"])

        self.strava_store.save_strava_tokens(
            athlete_id, StravaTokens(data["access_token"], data["refresh_token"], data["expires_at"])
        )

        # 3. Our own authorization code for the MCP client, bound to this athlete
        code = policy.new_secret()
        self.oauth_store.save_auth_code(
            code,
            AuthCode(
                grant=Grant(
                    client_id=pending.client_id,
                    subject=athlete_id,
                    scopes=params["scopes"] or policy.SCOPES,
                    # Clients should send `resource` (RFC 8707); if one doesn't, bind to our
                    # /mcp anyway, since the SDK rejects tokens without a matching resource.
                    resource=params.get("resource") or self.resource,
                    expires_at=time.time() + policy.AUTH_CODE_TTL,
                ),
                code_challenge=params["code_challenge"],
                redirect_uri=client_redirect,
                redirect_uri_explicit=params["redirect_uri_provided_explicitly"],
            ),
        )

        # 4. Back to the MCP client, which will POST /token with this code + its PKCE verifier
        return RedirectResponse(construct_redirect_uri(client_redirect, code=code, state=client_state), status_code=302)
