"""Strava's OAuth endpoints as plain HTTP calls.

Stateless: these functions talk to Strava and return its responses. Where tokens are
stored (a file, a database, a vault) is the caller's decision.
"""

from urllib.parse import urlencode

import httpx

from strava.config import AUTHORIZE_URL, DEAUTHORIZE_URL, TOKEN_URL, get_client_credentials

SCOPE = "read,activity:read_all"


def authorize_url(redirect_uri: str, state: str | None = None, approval_prompt: str = "auto") -> str:
    """URL of Strava's consent page. Strava sends the browser back to redirect_uri?code=...&state=..."""
    client_id, _ = get_client_credentials()  # only the public client_id goes into a browser URL
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "approval_prompt": approval_prompt,  # "force" = always show the consent screen
        "scope": SCOPE,
    }
    if state is not None:
        params["state"] = state
    return f"{AUTHORIZE_URL}?{urlencode(params)}"


def exchange_code(code: str) -> dict:
    """Trade an authorization code for tokens. The response also includes the `athlete` (with id)."""
    return _token_request(grant_type="authorization_code", code=code)


def refresh(refresh_token: str) -> dict:
    """Get a fresh access token. Strava may return a NEW refresh token: always store the result."""
    return _token_request(grant_type="refresh_token", refresh_token=refresh_token)


def deauthorize(access_token: str) -> None:
    """Revoke the athlete's grant to our app (same as them clicking Revoke Access on Strava).
    Frees their athlete slot; their tokens stop working."""
    response = httpx.post(DEAUTHORIZE_URL, headers={"Authorization": f"Bearer {access_token}"})
    if response.is_error:
        raise RuntimeError(f"Strava deauthorize failed ({response.status_code}): {response.text}")


def _token_request(**grant: str) -> dict:
    client_id, client_secret = get_client_credentials()
    response = httpx.post(
        TOKEN_URL,
        data={"client_id": client_id, "client_secret": client_secret, **grant},
    )
    if response.is_error:
        raise RuntimeError(f"Strava token request failed ({response.status_code}): {response.text}")
    return response.json()
