"""Serving from a public domain (BASE_URL=https://<app>.fly.dev): the DNS-rebinding protection
must accept that Host header, and still reject any other."""

import time

from starlette.testclient import TestClient

import server
from auth.ports import Grant
from auth.settings import Settings
from auth.stores import open_store

PUBLIC = "https://strava-mcp.fly.dev"
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}


def test_local_settings_allow_only_loopback():
    security = server.transport_security(Settings())
    assert security.allowed_hosts == ["127.0.0.1:*", "localhost:*", "[::1]:*"]


def test_public_base_url_adds_its_host():
    security = server.transport_security(Settings(base_url=PUBLIC))
    assert "strava-mcp.fly.dev" in security.allowed_hosts
    assert PUBLIC in security.allowed_origins


def test_requests_to_public_host_pass_and_others_are_rejected(tmp_path):
    settings = Settings(base_url=PUBLIC, database_url=f"sqlite:///{tmp_path}/test.db")
    app = server.create_server(settings).streamable_http_app(transport_security=server.transport_security(settings))
    # A valid token, so auth (which runs first) passes and only the Host header differs.
    open_store(settings.database_url).save_access_token(
        "valid-token", Grant("client", "12345", ["runs:read"], settings.mcp_url, time.time() + 3600)
    )
    headers = {**MCP_HEADERS, "Authorization": "Bearer valid-token"}
    with TestClient(app, base_url=PUBLIC) as client:
        ours = client.post("/mcp", headers=headers, json=LIST_TOOLS)
        assert ours.status_code != 421  # passes the Host check (then 400: no MCP session yet)
        evil = client.post("/mcp", headers={**headers, "Host": "evil.example.com"}, json=LIST_TOOLS)
        assert evil.status_code == 421  # another domain pointed at our server is refused


def test_health_needs_no_auth(tmp_path):
    app = server.create_server(Settings(database_url=f"sqlite:///{tmp_path}/test.db")).streamable_http_app()
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        r = client.get("/health")
    assert (r.status_code, r.text) == (200, "ok")


def test_access_log_redacts_query_strings():
    import logging

    record = logging.LogRecord(
        "uvicorn.access", logging.INFO, __file__, 0, '%s - "%s %s HTTP/%s" %d',
        ("1.2.3.4:5678", "GET", "/strava/callback?code=SECRET&state=S2", "1.1", 302), None,
    )
    assert server.RedactQueryStrings().filter(record) is True  # never drops the line
    assert "SECRET" not in record.getMessage()
    assert '"GET /strava/callback?[redacted] HTTP/1.1" 302' in record.getMessage()

    plain = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 0, '%s - "%s %s HTTP/%s" %d',
                              ("1.2.3.4:5678", "GET", "/health", "1.1", 200), None)
    server.RedactQueryStrings().filter(plain)
    assert '"GET /health HTTP/1.1" 200' in plain.getMessage()
