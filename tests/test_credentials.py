import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from auth.embedded.credentials import EmbeddedStravaCredentials
from auth.ports import StravaTokens
from strava import oauth as strava_oauth


@pytest.fixture
def fake_refresh(monkeypatch):
    calls = []
    lock = threading.Lock()

    def refresh(refresh_token):
        with lock:
            calls.append(refresh_token)
            n = len(calls)
        time.sleep(0.05)  # widen the race window
        return {"access_token": f"access-{n}", "refresh_token": f"refresh-{n}", "expires_at": int(time.time()) + 21600}

    monkeypatch.setattr(strava_oauth, "refresh", refresh)
    return calls


def test_fresh_token_is_returned_without_refresh(store, fake_refresh):
    store.save_strava_tokens("12345", StravaTokens("access-0", "refresh-0", int(time.time()) + 3600))
    assert EmbeddedStravaCredentials(store).get_access_token("12345") == "access-0"
    assert fake_refresh == []


def test_expired_token_is_refreshed_and_rotated_pair_saved(store, fake_refresh):
    store.save_strava_tokens("12345", StravaTokens("access-0", "refresh-0", int(time.time()) + 30))  # < 60 s left
    assert EmbeddedStravaCredentials(store).get_access_token("12345") == "access-1"
    assert fake_refresh == ["refresh-0"]
    assert store.load_strava_tokens("12345").refresh_token == "refresh-1"


def test_concurrent_calls_refresh_only_once(store, fake_refresh):
    store.save_strava_tokens("12345", StravaTokens("access-0", "refresh-0", 0))  # expired
    credentials = EmbeddedStravaCredentials(store)
    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(lambda _: credentials.get_access_token("12345"), range(10)))
    assert fake_refresh == ["refresh-0"]  # one refresh; the other 9 reused its result
    assert set(results) == {"access-1"}


def test_unknown_user_has_no_connection(store):
    with pytest.raises(RuntimeError, match="No Strava connection"):
        EmbeddedStravaCredentials(store).get_access_token("99999")
