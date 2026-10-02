"""SQLite implementation of the storage ports (auth/ports.py): OAuthStore + StravaTokenStore.

- Only SHA-256 hashes of codes/tokens are stored; callers pass and receive raw values.
- Expired rows are treated as missing on read (SQLite has no TTL); cleanup_expired() purges them.
- consume_* use DELETE ... RETURNING: read and delete in one atomic statement.
- A new connection per operation: cheap for SQLite and safe across server threads.
"""

import hashlib
import json
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from auth.ports import AuthCode, Grant, PendingAuth, StravaTokens

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id  TEXT PRIMARY KEY,
    info_json  TEXT NOT NULL,              -- full registration (OAuthClientInformationFull)
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_auth (
    state       TEXT PRIMARY KEY,          -- sent upstream, comes back on the callback
    client_id   TEXT NOT NULL,
    params_json TEXT NOT NULL,
    expires_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash             TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL,
    subject               TEXT NOT NULL,
    scopes                TEXT NOT NULL,   -- space-separated, OAuth style
    resource              TEXT,
    expires_at            REAL NOT NULL,
    code_challenge        TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    redirect_uri_explicit INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS access_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id  TEXT NOT NULL,
    subject    TEXT NOT NULL,
    scopes     TEXT NOT NULL,
    resource   TEXT,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id  TEXT NOT NULL,
    subject    TEXT NOT NULL,
    scopes     TEXT NOT NULL,
    resource   TEXT,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS strava_tokens (
    athlete_id    TEXT PRIMARY KEY,
    access_token  TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    expires_at    INTEGER NOT NULL,
    updated_at    REAL NOT NULL
);
"""


def hash_secret(value: str) -> str:
    """Codes/tokens are long random strings, so a fast hash is enough (unlike passwords)."""
    return hashlib.sha256(value.encode()).hexdigest()


class SqliteStore:
    def __init__(self, path: Path):
        self.path = path
        with self._transaction() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """Open a connection; commit if the block succeeds, roll back if it raises, always close."""
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row  # rows behave like dicts: row["column"]
        conn.execute("PRAGMA journal_mode=WAL")  # readers don't block while someone writes
        try:
            with conn:  # sqlite3's context manager commits / rolls back, but does not close
                yield conn
        finally:
            conn.close()

    # ---------- Clients ----------

    def save_client(self, client_id: str, info_json: str) -> None:
        with self._transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO clients (client_id, info_json, created_at) VALUES (?, ?, ?)",
                (client_id, info_json, time.time()),
            )

    def get_client(self, client_id: str) -> str | None:
        with self._transaction() as conn:
            row = conn.execute("SELECT info_json FROM clients WHERE client_id = ?", (client_id,)).fetchone()
        return row["info_json"] if row else None

    # ---------- Pending authorizations ----------

    def save_pending(self, state: str, pending: PendingAuth) -> None:
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO pending_auth (state, client_id, params_json, expires_at) VALUES (?, ?, ?, ?)",
                (state, pending.client_id, json.dumps(pending.params), pending.expires_at),
            )

    def get_pending(self, state: str) -> PendingAuth | None:
        with self._transaction() as conn:
            row = conn.execute("SELECT * FROM pending_auth WHERE state = ?", (state,)).fetchone()
        if not _is_live(row):
            return None
        return PendingAuth(row["client_id"], json.loads(row["params_json"]), row["expires_at"])

    def consume_pending(self, state: str) -> PendingAuth | None:
        with self._transaction() as conn:
            row = conn.execute("DELETE FROM pending_auth WHERE state = ? RETURNING *", (state,)).fetchone()
        if not _is_live(row):
            return None
        return PendingAuth(row["client_id"], json.loads(row["params_json"]), row["expires_at"])

    # ---------- Authorization codes ----------

    def save_auth_code(self, code: str, auth_code: AuthCode) -> None:
        g = auth_code.grant
        with self._transaction() as conn:
            conn.execute(
                "INSERT INTO auth_codes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (hash_secret(code), g.client_id, g.subject, " ".join(g.scopes), g.resource, g.expires_at,
                 auth_code.code_challenge, auth_code.redirect_uri, int(auth_code.redirect_uri_explicit)),
            )

    def get_auth_code(self, code: str) -> AuthCode | None:
        with self._transaction() as conn:
            row = conn.execute("SELECT * FROM auth_codes WHERE code_hash = ?", (hash_secret(code),)).fetchone()
        return _to_auth_code(row) if _is_live(row) else None

    def consume_auth_code(self, code: str) -> AuthCode | None:
        with self._transaction() as conn:
            row = conn.execute(
                "DELETE FROM auth_codes WHERE code_hash = ? RETURNING *", (hash_secret(code),)
            ).fetchone()
        return _to_auth_code(row) if _is_live(row) else None

    # ---------- Access & refresh tokens ----------

    def save_access_token(self, token: str, grant: Grant) -> None:
        self._save_grant("access_tokens", token, grant)

    def get_access_token(self, token: str) -> Grant | None:
        return self._get_grant("access_tokens", token)

    def save_refresh_token(self, token: str, grant: Grant) -> None:
        self._save_grant("refresh_tokens", token, grant)

    def get_refresh_token(self, token: str) -> Grant | None:
        return self._get_grant("refresh_tokens", token)

    def consume_refresh_token(self, token: str, client_id: str) -> Grant | None:
        """Single use, and only by the client it was issued to (another client deletes nothing)."""
        with self._transaction() as conn:
            row = conn.execute(
                "DELETE FROM refresh_tokens WHERE token_hash = ? AND client_id = ? RETURNING *",
                (hash_secret(token), client_id),
            ).fetchone()
        return _to_grant(row) if _is_live(row) else None

    def revoke_token(self, token: str) -> None:
        """Delete an access or refresh token. Revoking a refresh token also revokes the
        access tokens that client holds for the same subject."""
        token_hash = hash_secret(token)
        with self._transaction() as conn:
            conn.execute("DELETE FROM access_tokens WHERE token_hash = ?", (token_hash,))
            row = conn.execute(
                "DELETE FROM refresh_tokens WHERE token_hash = ? RETURNING client_id, subject", (token_hash,)
            ).fetchone()
            if row:
                conn.execute(
                    "DELETE FROM access_tokens WHERE client_id = ? AND subject = ?",
                    (row["client_id"], row["subject"]),
                )

    def cleanup_expired(self) -> int:
        now = time.time()
        removed = 0
        with self._transaction() as conn:
            for table in ("pending_auth", "auth_codes", "access_tokens", "refresh_tokens"):
                removed += conn.execute(f"DELETE FROM {table} WHERE expires_at <= ?", (now,)).rowcount
        return removed

    def _save_grant(self, table: str, token: str, grant: Grant) -> None:
        with self._transaction() as conn:
            conn.execute(
                f"INSERT INTO {table} VALUES (?, ?, ?, ?, ?, ?)",
                (hash_secret(token), grant.client_id, grant.subject, " ".join(grant.scopes),
                 grant.resource, grant.expires_at),
            )

    def _get_grant(self, table: str, token: str) -> Grant | None:
        with self._transaction() as conn:
            row = conn.execute(f"SELECT * FROM {table} WHERE token_hash = ?", (hash_secret(token),)).fetchone()
        return _to_grant(row) if _is_live(row) else None

    # ---------- Strava tokens ----------

    def save_strava_tokens(self, athlete_id: str, tokens: StravaTokens) -> None:
        """Upsert: one row per athlete, always overwritten with the latest (rotated) pair."""
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT INTO strava_tokens (athlete_id, access_token, refresh_token, expires_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (athlete_id) DO UPDATE SET
                    access_token = excluded.access_token,
                    refresh_token = excluded.refresh_token,
                    expires_at = excluded.expires_at,
                    updated_at = excluded.updated_at
                """,
                (athlete_id, tokens.access_token, tokens.refresh_token, tokens.expires_at, time.time()),
            )

    def load_strava_tokens(self, athlete_id: str) -> StravaTokens | None:
        with self._transaction() as conn:
            row = conn.execute("SELECT * FROM strava_tokens WHERE athlete_id = ?", (athlete_id,)).fetchone()
        return StravaTokens(row["access_token"], row["refresh_token"], row["expires_at"]) if row else None


# ---------- Row -> record helpers ----------


def _is_live(row) -> bool:
    return row is not None and row["expires_at"] > time.time()


def _to_grant(row) -> Grant:
    return Grant(
        client_id=row["client_id"],
        subject=row["subject"],
        scopes=row["scopes"].split(),
        resource=row["resource"],
        expires_at=row["expires_at"],
    )


def _to_auth_code(row) -> AuthCode:
    return AuthCode(
        grant=_to_grant(row),
        code_challenge=row["code_challenge"],
        redirect_uri=row["redirect_uri"],
        redirect_uri_explicit=bool(row["redirect_uri_explicit"]),
    )
