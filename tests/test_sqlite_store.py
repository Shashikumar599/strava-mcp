"""SQLite-specific tests: URL parsing and what actually lands on disk."""

import sqlite3

import pytest

import auth.stores
from auth.ports import Grant
from auth.stores import open_store
from auth.stores.sqlite import SqliteStore, hash_secret


def test_relative_and_absolute_sqlite_urls(tmp_path, monkeypatch):
    monkeypatch.setattr(auth.stores, "PROJECT_ROOT", tmp_path / "project")  # don't touch the real one
    (tmp_path / "project").mkdir()
    assert open_store("sqlite:///store.db").path == tmp_path / "project" / "store.db"
    assert open_store(f"sqlite:///{tmp_path}/x.db").path == tmp_path / "x.db"


def test_unsupported_or_invalid_urls():
    with pytest.raises(ValueError, match="Unsupported"):
        open_store("mysql://localhost/db")
    with pytest.raises(ValueError, match="Invalid"):
        open_store("store.db")


def test_raw_tokens_are_never_stored(tmp_path):
    store = SqliteStore(tmp_path / "test.db")
    store.save_access_token("raw-access-token", Grant("claude", "12345", ["read"], None, 9e9))
    dump = "\n".join(sqlite3.connect(tmp_path / "test.db").iterdump())
    assert "raw-access-token" not in dump
    assert hash_secret("raw-access-token") in dump
