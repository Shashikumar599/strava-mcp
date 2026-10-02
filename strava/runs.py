"""Selecting runs by date range, with cursor-based pagination. Pure functions, no I/O.

Dates are the athlete's LOCAL dates (a 05:00 run on 1 Jan in India is "1 Jan", even though
it is still 31 Dec in UTC). Strava filters by UTC timestamps, so we ask Strava for a window
one day wider on each side, then filter exactly on start_date_local.

The cursor is the UTC start time (epoch seconds) of the last run on the previous page; the
next page asks Strava for activities before it. Stateless: nothing is stored on the server.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone

from strava.api import is_run


@dataclass
class RunsPage:
    runs: list[dict]
    next_cursor: str | None  # None = no more runs in the range


def parse_cursor(cursor: str | None) -> int | None:
    if cursor is None:
        return None
    if not cursor.isdigit():
        raise ValueError(f"Invalid cursor '{cursor}'. Use the cursor value from the previous get_runs result.")
    return int(cursor)


def strava_window(start: date | None, end: date | None, cursor: int | None) -> tuple[int | None, int | None]:
    """UTC (after, before) epoch bounds to send to Strava, one day wider than the local dates."""
    after = _epoch(start - timedelta(days=1)) if start else None
    before = _epoch(end + timedelta(days=2)) if end else None  # end is inclusive: +1 day, +1 buffer
    if cursor is not None:
        before = cursor if before is None else min(before, cursor)
    return after, before


def select_runs(
    activities: Iterable[dict], start: date | None, end: date | None, limit: int, cursor: int | None = None
) -> RunsPage:
    """Take up to `limit` runs (newest first) whose local date is within [start, end].

    `activities` must be newest-first (as api.iter_activities yields them). Reads one item
    past `limit` to know whether another page exists, then stops: lazy iterables are not
    exhausted, so Strava isn't asked for pages nobody needs.
    """
    runs: list[dict] = []
    for activity in activities:
        if not is_run(activity):
            continue
        if cursor is not None and start_epoch(activity) >= cursor:
            continue  # already shown on an earlier page
        local_day = date.fromisoformat(activity["start_date_local"][:10])
        if end and local_day > end:
            continue
        if start and local_day < start:
            continue  # not `break`: after time-zone travel, local dates aren't strictly ordered
                      # (the Strava window already ends a day before `start`, so this is cheap)
        if len(runs) == limit:
            return RunsPage(runs, next_cursor=str(start_epoch(runs[-1])))
        runs.append(activity)
    return RunsPage(runs, next_cursor=None)


def start_epoch(activity: dict) -> int:
    """UTC start time of an activity as epoch seconds (from its `start_date`, which is UTC)."""
    return int(datetime.fromisoformat(activity["start_date"]).timestamp())


def _epoch(day: date) -> int:
    return int(datetime.combine(day, time.min, tzinfo=timezone.utc).timestamp())
