from datetime import date, datetime, timezone

import pytest

from strava import api
from strava.runs import parse_cursor, select_runs, start_epoch, strava_window


def activity(utc: str, local: str, sport: str = "Run", id: int = 0) -> dict:
    return {"id": id, "sport_type": sport, "start_date": utc, "start_date_local": local}


def epoch(s: str) -> int:
    return int(datetime.fromisoformat(s).replace(tzinfo=timezone.utc).timestamp())


# Newest first, as Strava returns them. Local time = UTC + 5:30 (India).
ACTIVITIES = [
    activity("2026-01-03T01:00:00Z", "2026-01-03T06:30:00Z", id=5),
    activity("2026-01-02T12:00:00Z", "2026-01-02T17:30:00Z", sport="Ride", id=4),
    activity("2026-01-02T01:00:00Z", "2026-01-02T06:30:00Z", id=3),
    activity("2025-12-31T23:30:00Z", "2026-01-01T05:00:00Z", id=2),  # 1 Jan locally, 31 Dec in UTC
    activity("2025-12-30T01:00:00Z", "2025-12-30T06:30:00Z", id=1),
]


def ids(page) -> list[int]:
    return [a["id"] for a in page.runs]


# ---------- Date filtering ----------


def test_filters_by_local_date_and_skips_non_runs():
    page = select_runs(ACTIVITIES, date(2026, 1, 1), date(2026, 1, 2), limit=10)
    assert ids(page) == [3, 2]  # 5 is after end, 4 is a ride, 1 is before start
    assert page.next_cursor is None


def test_run_just_after_local_midnight_counts_for_the_local_day():
    page = select_runs(ACTIVITIES, date(2026, 1, 1), date(2026, 1, 1), limit=10)
    assert ids(page) == [2]  # although its UTC date is 2025-12-31


def test_no_dates_means_newest_runs():
    assert ids(select_runs(ACTIVITIES, None, None, limit=2)) == [5, 3]


def test_strava_window_is_a_day_wider_and_cursor_tightens_before():
    after, before = strava_window(date(2026, 1, 1), date(2026, 1, 2), None)
    assert after == epoch("2025-12-31T00:00:00")
    assert before == epoch("2026-01-04T00:00:00")
    assert strava_window(None, None, None) == (None, None)
    cursor = epoch("2026-01-02T00:00:00")
    assert strava_window(date(2026, 1, 1), date(2026, 1, 2), cursor)[1] == cursor


# ---------- Pagination ----------


def test_pages_chain_with_cursor_until_end():
    first = select_runs(ACTIVITIES, None, None, limit=2)
    assert ids(first) == [5, 3]
    assert first.next_cursor == str(start_epoch(ACTIVITIES[2]))

    cursor = parse_cursor(first.next_cursor)
    older = [a for a in ACTIVITIES if start_epoch(a) < cursor]  # what Strava returns for before=cursor
    second = select_runs(older, None, None, limit=2, cursor=cursor)
    assert ids(second) == [2, 1]
    assert second.next_cursor is None  # exactly used up: no extra page


def test_cursor_skips_runs_already_shown_even_if_strava_repeats_them():
    cursor = start_epoch(ACTIVITIES[2])
    page = select_runs(ACTIVITIES, None, None, limit=10, cursor=cursor)  # Strava ignoring `before`
    assert ids(page) == [2, 1]


def test_invalid_cursor_is_rejected():
    with pytest.raises(ValueError):
        parse_cursor("not-a-number")
    assert parse_cursor(None) is None


def test_select_runs_stops_reading_once_it_knows_there_is_more():
    consumed = []

    def lazy():
        for a in ACTIVITIES:
            consumed.append(a["id"])
            yield a

    select_runs(lazy(), None, None, limit=1)
    assert consumed == [5, 4, 3]  # 1 run + 1 more run to know a next page exists; never read 2 or 1


# ---------- Strava paging (api.iter_activities) ----------


class FakeResponse:
    def __init__(self, data):
        self.data = data

    def json(self):
        return self.data


def test_iter_activities_always_sends_before_and_stops_on_short_page(monkeypatch):
    monkeypatch.setattr(api, "PER_PAGE", 2)
    pages = {1: [{"id": 1}, {"id": 2}], 2: [{"id": 3}]}
    requests = []

    def fake_get(url, token, params):
        requests.append(params)
        return FakeResponse(pages.get(params["page"], []))

    monkeypatch.setattr(api, "_get", fake_get)
    assert [a["id"] for a in api.iter_activities("token", after=100)] == [1, 2, 3]
    assert [r["page"] for r in requests] == [1, 2]  # page 2 was short, so no page 3
    assert all("before" in r and r["after"] == 100 for r in requests)  # keeps newest-first order


def test_iter_activities_is_lazy(monkeypatch):
    monkeypatch.setattr(api, "PER_PAGE", 1)
    requests = []
    monkeypatch.setattr(api, "_get", lambda url, token, params: requests.append(params) or FakeResponse([{"id": params["page"]}]))
    next(api.iter_activities("token"))
    assert len(requests) == 1  # only the first page was fetched


def test_iter_activities_refuses_endless_paging(monkeypatch):
    monkeypatch.setattr(api, "PER_PAGE", 1)
    monkeypatch.setattr(api, "_get", lambda url, token, params: FakeResponse([{"id": params["page"]}]))
    with pytest.raises(RuntimeError, match="narrow the dates"):
        list(api.iter_activities("token"))
