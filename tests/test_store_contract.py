"""Contract tests for auth.ports.Store. They only use the protocol's methods, so every
backend in the `store` fixture (tests/conftest.py) must pass them."""

import time
from concurrent.futures import ThreadPoolExecutor

from auth.ports import AuthCode, Grant, PendingAuth, StravaTokens


def grant(expires_in: float = 3600, client_id: str = "claude", scopes=("read",)) -> Grant:
    return Grant(
        client_id=client_id,
        subject="12345",
        scopes=list(scopes),
        resource="http://127.0.0.1:8000/mcp",
        expires_at=time.time() + expires_in,
    )


def auth_code(expires_in: float = 300) -> AuthCode:
    return AuthCode(
        grant=grant(expires_in),
        code_challenge="challenge",
        redirect_uri="https://claude.ai/api/mcp/auth_callback",
        redirect_uri_explicit=True,
    )


# ---------- Clients ----------


def test_client_roundtrip(store):
    store.save_client("claude", '{"client_name": "Claude"}')
    assert store.get_client("claude") == '{"client_name": "Claude"}'
    assert store.get_client("unknown") is None


# ---------- Pending authorizations ----------


def test_pending_is_single_use(store):
    store.save_pending("state-1", PendingAuth("claude", {"scopes": ["read"]}, time.time() + 600))
    pending = store.consume_pending("state-1")
    assert (pending.client_id, pending.params) == ("claude", {"scopes": ["read"]})
    assert store.consume_pending("state-1") is None


def test_get_pending_does_not_consume(store):
    store.save_pending("state-1", PendingAuth("claude", {"a": 1}, time.time() + 600))
    assert store.get_pending("state-1").params == {"a": 1}
    assert store.get_pending("state-1") is not None  # still there
    assert store.consume_pending("state-1") is not None
    assert store.get_pending("state-1") is None


def test_pending_expires(store):
    store.save_pending("state-1", PendingAuth("claude", {}, time.time() - 1))
    assert store.consume_pending("state-1") is None


# ---------- Authorization codes ----------


def test_auth_code_get_does_not_consume_but_consume_is_single_use(store):
    store.save_auth_code("code-1", auth_code())
    loaded = store.get_auth_code("code-1")
    assert loaded.grant.subject == "12345"
    assert loaded.redirect_uri_explicit is True
    assert store.get_auth_code("code-1") is not None  # still there
    assert store.consume_auth_code("code-1").grant.scopes == ["read"]
    assert store.consume_auth_code("code-1") is None  # second use fails
    assert store.get_auth_code("code-1") is None


def test_auth_code_race_has_exactly_one_winner(store):
    """20 threads try to use the same code at the same moment; only one may succeed."""
    store.save_auth_code("code-1", auth_code())
    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(lambda _: store.consume_auth_code("code-1"), range(20)))
    assert sum(r is not None for r in results) == 1


def test_auth_code_expires(store):
    store.save_auth_code("code-1", auth_code(expires_in=-1))
    assert store.get_auth_code("code-1") is None
    assert store.consume_auth_code("code-1") is None


# ---------- Access & refresh tokens ----------


def test_tokens_roundtrip_and_are_not_interchangeable(store):
    saved = grant()
    store.save_access_token("access-1", saved)
    store.save_refresh_token("refresh-1", grant(expires_in=30 * 86400))
    assert store.get_access_token("access-1") == saved  # every field survives the roundtrip
    assert store.get_refresh_token("refresh-1").resource == "http://127.0.0.1:8000/mcp"
    assert store.get_access_token("refresh-1") is None
    assert store.get_refresh_token("access-1") is None
    assert store.get_access_token("made-up") is None


def test_expired_access_token_is_rejected(store):
    store.save_access_token("access-1", grant(expires_in=-1))
    assert store.get_access_token("access-1") is None


def test_refresh_token_is_single_use(store):
    store.save_refresh_token("refresh-1", grant())
    assert store.consume_refresh_token("refresh-1", "claude").subject == "12345"
    assert store.consume_refresh_token("refresh-1", "claude") is None


def test_refresh_by_wrong_client_fails_and_keeps_token(store):
    store.save_refresh_token("refresh-1", grant())
    assert store.consume_refresh_token("refresh-1", "other-client") is None
    assert store.get_refresh_token("refresh-1") is not None


def test_revoking_refresh_token_also_revokes_access_tokens(store):
    store.save_access_token("access-1", grant())
    store.save_refresh_token("refresh-1", grant())
    store.revoke_token("refresh-1")
    assert store.get_refresh_token("refresh-1") is None
    assert store.get_access_token("access-1") is None


def test_cleanup_removes_only_expired_rows(store):
    store.save_pending("state-1", PendingAuth("claude", {}, time.time() - 1))
    store.save_auth_code("old-code", auth_code(expires_in=-1))
    store.save_auth_code("live-code", auth_code())
    assert store.cleanup_expired() == 2
    assert store.get_auth_code("live-code") is not None


# ---------- Strava tokens ----------


def test_strava_tokens_upsert_keeps_latest(store):
    assert store.load_strava_tokens("12345") is None
    store.save_strava_tokens("12345", StravaTokens("a1", "r1", 1000))
    store.save_strava_tokens("12345", StravaTokens("a2", "r2", 2000))  # e.g. after Strava rotated
    assert store.load_strava_tokens("12345") == StravaTokens("a2", "r2", 2000)
