"""End-to-end OAuth tests against the real ASGI app, in-process.

The test plays three parts: the MCP client (register / authorize / token / MCP calls),
the browser (following redirects by hand), and Strava (exchange_code is faked, so no
network and no real login). Every hop of the Connect flow is checked, plus attacks.
"""

import base64
import hashlib
import json
import re
import secrets
import time
from urllib.parse import parse_qs, urlparse

import pytest
from starlette.testclient import TestClient

import server
from auth.ports import Grant
from auth.settings import Settings
from auth.stores import open_store
from strava import oauth as strava_oauth

BASE = "http://127.0.0.1:8000"
MCP_URL = BASE + "/mcp"
CLIENT_REDIRECT = "http://127.0.0.1:33418/callback"  # a loopback callback, like Claude Code's
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


# ---------- Fixtures ----------


@pytest.fixture
def fake_strava(monkeypatch):
    calls = {"exchange": [], "fetch": []}

    def exchange_code(code):
        calls["exchange"].append(code)
        return {
            "access_token": "strava-access",
            "refresh_token": "strava-refresh",
            "expires_at": int(time.time()) + 6 * 3600,
            "athlete": {"id": 12345},
        }

    def iter_activities(access_token, after=None, before=None):
        calls["fetch"].append(access_token)
        yield {
            "id": 1, "name": "Test Run", "sport_type": "Run",
            "start_date": "2026-10-01T01:30:00Z", "start_date_local": "2026-10-01T07:00:00Z",
            "distance": 5000, "moving_time": 1500, "average_speed": 3.33, "total_elevation_gain": 10,
        }

    monkeypatch.setattr(strava_oauth, "exchange_code", exchange_code)
    monkeypatch.setattr(server, "iter_activities", iter_activities)
    return calls


@pytest.fixture
def db_url(tmp_path):
    return f"sqlite:///{tmp_path}/test.db"


@pytest.fixture
def client(db_url, fake_strava):
    app = server.create_server(Settings(base_url=BASE, database_url=db_url)).streamable_http_app()
    with TestClient(app, base_url=BASE) as c:  # `with` runs the app's startup (MCP session manager)
        yield c


# ---------- Helpers: what an MCP client + browser would do ----------


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


def query_of(url: str) -> dict:
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}


def register(c, redirect_uri=CLIENT_REDIRECT):
    return c.post("/register", json={
        "redirect_uris": [redirect_uri],
        "client_name": "test client",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",  # public client: PKCE instead of a secret
    })


def open_authorize(c, client_id, challenge) -> str:
    """GET /authorize; returns the consent page URL our server redirects the browser to."""
    r = c.get("/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": CLIENT_REDIRECT,
        "code_challenge": challenge, "code_challenge_method": "S256",
        "state": "client-state", "scope": "runs:read", "resource": MCP_URL,
    }, follow_redirects=False)
    assert r.status_code == 302, r.text
    return r.headers["location"]


def view_consent(c, consent_url):
    """GET the consent page like a browser (sets the CSRF cookie); returns (response, csrf)."""
    page = c.get(consent_url)
    match = re.search(r'name="csrf" value="([^"]+)"', page.text)
    return page, match.group(1) if match else None


def decide(c, consent_url, decision="approve", csrf=None):
    """POST the consent form; returns the redirect response."""
    page, page_csrf = view_consent(c, consent_url)
    return c.post("/consent", data={
        "state": query_of(consent_url)["state"], "csrf": csrf or page_csrf, "decision": decision,
    }, follow_redirects=False)


def start_login(c, client_id, challenge) -> str:
    """/authorize -> consent page -> Approve; returns the Strava URL the browser is sent to."""
    r = decide(c, open_authorize(c, client_id, challenge))
    assert r.status_code == 303, r.text
    return r.headers["location"]


def strava_redirects_back(c, strava_url, scope="read,activity:read_all", **extra):
    """Simulate Strava sending the browser to our callback after you click Authorize."""
    params = {"code": "strava-code", "state": query_of(strava_url)["state"], "scope": scope, **extra}
    return c.get("/strava/callback", params=params, follow_redirects=False)


def exchange(c, client_id, code, verifier):
    return c.post("/token", data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": CLIENT_REDIRECT,
        "client_id": client_id, "code_verifier": verifier, "resource": MCP_URL,
    })


def connect(c) -> tuple[str, dict]:
    """The whole Connect flow; returns (client_id, token response)."""
    client_id = register(c).json()["client_id"]
    verifier, challenge = pkce()
    r = strava_redirects_back(c, start_login(c, client_id, challenge))
    code = query_of(r.headers["location"])["code"]
    tokens = exchange(c, client_id, code, verifier)
    assert tokens.status_code == 200, tokens.text
    return client_id, tokens.json()


def mcp_post(c, access_token, body, session_id=None):
    headers = {**MCP_HEADERS, "Authorization": f"Bearer {access_token}"}
    if session_id:
        headers["mcp-session-id"] = session_id
    return c.post("/mcp", headers=headers, json=body)


def call_tool(c, access_token, name, arguments) -> dict:
    init = mcp_post(c, access_token, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}})
    assert init.status_code == 200, init.text
    session = init.headers["mcp-session-id"]
    mcp_post(c, access_token, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
    r = mcp_post(c, access_token, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                   "params": {"name": name, "arguments": arguments}}, session)
    data = next(line for line in r.text.splitlines() if line.startswith("data:"))
    return json.loads(data.removeprefix("data:"))["result"]


# ---------- Discovery ----------


def test_discovery_metadata(client):
    auth_meta = client.get("/.well-known/oauth-authorization-server").json()
    assert auth_meta["issuer"].rstrip("/") == BASE
    assert auth_meta["registration_endpoint"] == BASE + "/register"
    assert auth_meta["code_challenge_methods_supported"] == ["S256"]

    resource_meta = client.get("/.well-known/oauth-protected-resource/mcp").json()
    assert resource_meta["resource"].rstrip("/") == MCP_URL
    assert [u.rstrip("/") for u in resource_meta["authorization_servers"]] == [BASE]


def test_mcp_without_token_is_401_and_points_to_metadata(client):
    r = client.post("/mcp", headers=MCP_HEADERS, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 401
    assert "resource_metadata" in r.headers["www-authenticate"]


# ---------- The happy path ----------


def test_full_connect_flow_then_tool_call(client, fake_strava):
    client_id = register(client).json()["client_id"]
    verifier, challenge = pkce()

    # /authorize sends the browser to Strava, always with the consent screen
    strava_url = start_login(client, client_id, challenge)
    strava_query = query_of(strava_url)
    assert strava_url.startswith("https://www.strava.com/oauth/authorize")
    assert strava_query["redirect_uri"] == BASE + "/strava/callback"
    assert strava_query["approval_prompt"] == "force"
    assert strava_query["state"] != "client-state"  # our own state, not the client's

    # Strava -> our callback -> back to the client with OUR code and the CLIENT's state
    r = strava_redirects_back(client, strava_url)
    assert r.status_code == 302
    assert r.headers["location"].startswith(CLIENT_REDIRECT)
    back = query_of(r.headers["location"])
    assert back["state"] == "client-state"
    assert fake_strava["exchange"] == ["strava-code"]

    # Code + wrong PKCE verifier fails; the right one works; replaying the code fails
    assert exchange(client, client_id, back["code"], "wrong-verifier").status_code == 400
    tokens = exchange(client, client_id, back["code"], verifier)
    assert tokens.status_code == 200
    assert exchange(client, client_id, back["code"], verifier).status_code == 400

    # The access token works for MCP, and the tool got the athlete's Strava token
    result = call_tool(client, tokens.json()["access_token"], "get_runs", {"limit": 1})
    assert "Test Run" in result["content"][0]["text"]
    assert fake_strava["fetch"] == ["strava-access"]


def test_refresh_rotates_and_old_refresh_token_dies(client):
    client_id, tokens = connect(client)
    refresh = lambda token: client.post("/token", data={  # noqa: E731
        "grant_type": "refresh_token", "refresh_token": token, "client_id": client_id})

    new = refresh(tokens["refresh_token"])
    assert new.status_code == 200
    assert new.json()["refresh_token"] != tokens["refresh_token"]
    assert refresh(tokens["refresh_token"]).status_code == 400  # rotated: old one is dead
    assert refresh(new.json()["refresh_token"]).status_code == 200


def test_revoke_disconnects(client):
    client_id, tokens = connect(client)
    # client_secret="": the SDK's RevocationRequest declares `client_secret: str | None` with no
    # default, so the field must be present even for public (secret-less) clients.
    r = client.post("/revoke", data={"token": tokens["refresh_token"], "client_id": client_id, "client_secret": ""})
    assert r.status_code == 200
    r = mcp_post(client, tokens["access_token"], {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 401  # revoking the refresh token also killed the access token


# ---------- Attacks and failure paths ----------


def test_registration_rejects_foreign_redirect_uri(client):
    r = register(client, "https://evil.example/cb")
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_redirect_uri"


def test_callback_state_is_single_use(client):
    client_id = register(client).json()["client_id"]
    strava_url = start_login(client, client_id, pkce()[1])
    assert strava_redirects_back(client, strava_url).status_code == 302
    assert strava_redirects_back(client, strava_url).status_code == 400  # replay


def test_unknown_state_is_rejected(client):
    r = client.get("/strava/callback", params={"code": "x", "state": "made-up"}, follow_redirects=False)
    assert r.status_code == 400


def test_missing_private_activity_scope_fails_the_connect(client, fake_strava):
    client_id = register(client).json()["client_id"]
    r = strava_redirects_back(client, start_login(client, client_id, pkce()[1]), scope="read")
    back = query_of(r.headers["location"])
    assert back["error"] == "access_denied" and "code" not in back
    assert fake_strava["exchange"] == []  # never even exchanged the Strava code


def test_cancel_on_strava_is_reported_to_client(client):
    client_id = register(client).json()["client_id"]
    r = strava_redirects_back(client, start_login(client, client_id, pkce()[1]), error="access_denied")
    assert query_of(r.headers["location"])["error"] == "access_denied"


def test_token_for_another_resource_is_rejected(client, db_url):
    # A valid token in our store, but minted for a different server (audience mismatch)
    open_store(db_url).save_access_token(
        "foreign-token", Grant("someone", "12345", ["runs:read"], "http://other.example/mcp", time.time() + 3600)
    )
    r = mcp_post(client, "foreign-token", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 401


# ---------- Consent page ----------


def test_authorize_goes_to_our_consent_page_not_strava(client):
    client_id = register(client).json()["client_id"]
    consent_url = open_authorize(client, client_id, pkce()[1])
    assert consent_url.startswith(BASE + "/consent?state=")

    page, csrf = view_consent(client, consent_url)
    assert page.status_code == 200
    assert "test client" in page.text  # who is asking
    assert "an app on this computer (127.0.0.1:33418)" in page.text  # where you'll be sent back
    assert csrf and "consent_csrf" in page.headers["set-cookie"]


def test_consent_page_security_headers(client):
    client_id = register(client).json()["client_id"]
    page, _ = view_consent(client, open_authorize(client, client_id, pkce()[1]))
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert "script-src" not in page.headers["content-security-policy"]  # default-src 'none': no scripts
    assert page.headers["x-frame-options"] == "DENY"
    assert page.headers["cache-control"] == "no-store"
    assert "httponly" in page.headers["set-cookie"].lower() and "samesite=strict" in page.headers["set-cookie"].lower()


def test_client_name_is_escaped(client):
    r = client.post("/register", json={
        "redirect_uris": [CLIENT_REDIRECT], "client_name": "<script>alert(1)</script>",
        "token_endpoint_auth_method": "none", "grant_types": ["authorization_code"], "response_types": ["code"],
    })
    page, _ = view_consent(client, open_authorize(client, r.json()["client_id"], pkce()[1]))
    assert "<script>alert(1)</script>" not in page.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text


def test_deny_sends_client_access_denied_and_never_reaches_strava(client, fake_strava):
    client_id = register(client).json()["client_id"]
    r = decide(client, open_authorize(client, client_id, pkce()[1]), decision="deny")
    assert r.status_code == 303
    back = query_of(r.headers["location"])
    assert r.headers["location"].startswith(CLIENT_REDIRECT)
    assert (back["error"], back["state"]) == ("access_denied", "client-state")
    assert fake_strava["exchange"] == []


def test_approve_without_csrf_cookie_is_rejected(client):
    """A forged POST from another site: right state, but no cookie from our page."""
    client_id = register(client).json()["client_id"]
    consent_url = open_authorize(client, client_id, pkce()[1])
    _, csrf = view_consent(client, consent_url)
    client.cookies.clear()  # the victim's browser never sent our cookie (SameSite=Strict)
    r = client.post("/consent", data={"state": query_of(consent_url)["state"], "csrf": csrf, "decision": "approve"},
                    follow_redirects=False)
    assert r.status_code == 403


def test_approve_with_wrong_csrf_token_is_rejected(client):
    client_id = register(client).json()["client_id"]
    r = decide(client, open_authorize(client, client_id, pkce()[1]), csrf="guessed-token")
    assert r.status_code == 403


def test_skipping_consent_page_is_refused_at_callback(client, fake_strava):
    """The attacker knows the consent page's state and sends you straight to Strava with it."""
    client_id = register(client).json()["client_id"]
    consent_url = open_authorize(client, client_id, pkce()[1])
    r = client.get("/strava/callback", params={
        "code": "strava-code", "state": query_of(consent_url)["state"], "scope": "read,activity:read_all",
    }, follow_redirects=False)
    assert r.status_code == 400
    assert fake_strava["exchange"] == []  # no Strava exchange, no code issued


def test_consent_state_is_rotated_and_single_use(client):
    client_id = register(client).json()["client_id"]
    consent_url = open_authorize(client, client_id, pkce()[1])
    page_state = query_of(consent_url)["state"]
    first = decide(client, consent_url)
    assert first.status_code == 303
    assert query_of(first.headers["location"])["state"] != page_state  # Strava gets a NEW state
    second = decide(client, consent_url)  # submitting the same consent again
    assert second.status_code == 400
