"""Calls to the Strava REST API.

All functions raise httpx.HTTPStatusError on 4xx/5xx and httpx.RequestError if Strava
is unreachable; callers decide how to present those.
"""

import time
from collections.abc import Iterator

import httpx

from strava.config import ACTIVITIES_URL, ACTIVITY_URL, STREAMS_URL

RUN_TYPES = {"Run", "TrailRun", "VirtualRun"}
PER_PAGE = 200  # Strava's maximum
MAX_PAGES = 10  # per call: protects the rate limit (100 read requests / 15 min)

# Per-sample series used for run analysis. heartrate/cadence only come back if recorded.
STREAM_KEYS = ["time", "distance", "velocity_smooth", "altitude", "grade_smooth", "heartrate", "cadence"]


def _get(url: str, access_token: str, params: dict | None = None) -> httpx.Response:
    response = httpx.get(
        url,
        params=params,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=30,
    )
    response.raise_for_status()
    return response


def iter_activities(access_token: str, after: int | None = None, before: int | None = None) -> Iterator[dict]:
    """Yield activities (all sport types) started between `after` and `before`, newest first.

    `after`/`before` are UTC epoch seconds. Pages are fetched lazily, so a caller that stops
    early (e.g. after 20 runs) never requests the rest.

    `before` is always sent: Strava returns OLDEST first when only `after` is given, but
    newest first whenever `before` is present. Sending it keeps the order predictable.
    """
    params = {"per_page": PER_PAGE, "before": before if before is not None else int(time.time()) + 86400}
    if after is not None:
        params["after"] = after
    for page in range(1, MAX_PAGES + 1):
        batch = _get(ACTIVITIES_URL, access_token, {**params, "page": page}).json()
        yield from batch
        if len(batch) < PER_PAGE:  # a short page is the last one
            return
    raise RuntimeError(
        f"More than {MAX_PAGES * PER_PAGE} activities in this date range; please narrow the dates."
    )


def fetch_activity(access_token: str, activity_id: int) -> dict:
    """Fetch one activity in detail: includes splits_metric, laps and best_efforts."""
    return _get(ACTIVITY_URL.format(activity_id=activity_id), access_token).json()


def fetch_streams(access_token: str, activity_id: int) -> dict[str, list]:
    """Fetch per-sample streams as {"time": [...], "distance": [...], ...}.

    Returns {} for activities without stream data (e.g. manually entered ones).
    """
    try:
        response = _get(
            STREAMS_URL.format(activity_id=activity_id),
            access_token,
            {"keys": ",".join(STREAM_KEYS), "key_by_type": "true"},
        )
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return {}
        raise
    return {key: stream["data"] for key, stream in response.json().items()}


def is_run(activity: dict) -> bool:
    return activity.get("sport_type") in RUN_TYPES
