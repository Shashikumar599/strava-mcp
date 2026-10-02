"""Run analysis over Strava streams. Pure functions: data in, numbers out, no I/O.

`streams` is the dict returned by api.fetch_streams(): parallel lists, one entry per sample
(roughly one per second), e.g. streams["time"][i] is seconds since start and
streams["distance"][i] is metres covered at that moment.

Paces are returned as seconds per km (float) or None when there is too little data.
"""

import statistics

BUCKET_CHOICES = [15, 30, 60, 120, 300, 600]  # seconds
PROFILE_TARGET_ROWS = 70
MIN_SEGMENT_SECONDS = 30
STEADY_SPEED_RATIO = 1.2  # fast/slow speed ratio below which a run counts as steady
PAUSE_GAP_SECONDS = 10  # a jump in the time stream bigger than this is a recording pause


def pace(moving_seconds: float, metres: float) -> float | None:
    """Seconds per km, e.g. 238 s over 775 m -> 307 (5:07 /km)."""
    if moving_seconds <= 0 or metres <= 0:
        return None
    return moving_seconds / (metres / 1000)


def moving_deltas(streams: dict) -> list[float]:
    """Seconds of moving time between sample i-1 and i (0 for the first sample and for pauses).

    Matches how Strava computes moving_time: elapsed time minus recording pauses (gaps in
    the time stream). Strava's per-sample `moving` stream is not used: it flags seconds as
    'not moving' even at running speeds.
    """
    times = streams["time"]
    deltas = [0.0]
    for i in range(1, len(times)):
        gap = times[i] - times[i - 1]
        deltas.append(gap if gap <= PAUSE_GAP_SECONDS else 0.0)
    return deltas


# ---------- Pacing overview ----------


def half_splits(streams: dict) -> tuple[float | None, float | None]:
    """Pace of the first and second half of the run, split by distance."""
    distance = streams["distance"]
    deltas = moving_deltas(streams)
    half = distance[-1] / 2
    mid = next(i for i, d in enumerate(distance) if d >= half)
    first = pace(sum(deltas[1 : mid + 1]), distance[mid] - distance[0])
    second = pace(sum(deltas[mid + 1 :]), distance[-1] - distance[mid])
    return first, second


def pace_variability(streams: dict) -> float | None:
    """Coefficient of variation of moving speed (stdev / mean). ~0.1 steady, 0.2+ intervals."""
    speeds = [v for v in streams["velocity_smooth"] if v > 0]
    if len(speeds) < 2:
        return None
    return statistics.stdev(speeds) / statistics.mean(speeds)


# ---------- Pace & elevation profile ----------


def choose_bucket_seconds(total_seconds: float) -> int:
    """Smallest bucket from BUCKET_CHOICES that keeps the profile at ~PROFILE_TARGET_ROWS rows."""
    for size in BUCKET_CHOICES:
        if total_seconds / size <= PROFILE_TARGET_ROWS:
            return size
    return BUCKET_CHOICES[-1]


def pace_profile(streams: dict) -> tuple[int, list[dict]]:
    """Summarise the run in fixed time buckets. Returns (bucket_seconds, rows).

    Each row: start (s), km (at bucket end), pace (s/km or None), paused (s),
    altitude (m, at bucket end), grade (avg %), heartrate / cadence (avg, or None).
    """
    times = streams["time"]
    deltas = moving_deltas(streams)
    size = choose_bucket_seconds(times[-1])

    # A bucket row spans sample `start` (last sample of the previous bucket) to sample i
    # (last sample of this bucket), so consecutive rows share a boundary and no time is lost.
    rows: list[dict] = []
    start = 0
    for i in range(1, len(times)):
        is_last = i == len(times) - 1
        if is_last or times[i + 1] // size != times[i] // size:
            rows.append(_profile_row(streams, deltas, start, i, size))
            start = i
    return size, rows


def _profile_row(streams: dict, deltas: list[float], a: int, b: int, size: int) -> dict:
    """Aggregate the samples between a and b into one profile row."""
    times, distance = streams["time"], streams["distance"]
    moving_s = sum(deltas[a + 1 : b + 1])
    return {
        "start": times[b] // size * size,
        "km": distance[b] / 1000,
        "pace": pace(moving_s, distance[b] - distance[a]),
        "paused": (times[b] - times[a]) - moving_s,
        "altitude": streams["altitude"][b] if "altitude" in streams else None,
        "grade": _mean(streams.get("grade_smooth"), a, b),
        "heartrate": _mean(streams.get("heartrate"), a, b),
        "cadence": _mean(streams.get("cadence"), a, b),
    }


def _mean(values: list | None, a: int, b: int) -> float | None:
    return statistics.mean(values[a : b + 1]) if values else None


# ---------- Work / recovery segments ----------


def detect_segments(streams: dict) -> tuple[float | None, list[dict]]:
    """Split the run into alternating 'work' / 'easy' segments by speed.

    Threshold = midpoint between the run's 20th and 80th percentile moving speeds, so it
    adapts to each runner and run. Segments shorter than MIN_SEGMENT_SECONDS (a brief
    slowdown at a crossing, a GPS blip) are merged into their neighbours.

    Returns (threshold_pace, segments); (None, []) for steady runs with no clear fast/slow split.
    """
    times, speeds = streams["time"], streams["velocity_smooth"]

    moving_speeds = [v for v in speeds if v > 0]
    if len(moving_speeds) < 10:
        return None, []
    deciles = statistics.quantiles(moving_speeds, n=10)
    slow, fast = deciles[1], deciles[7]  # 20th and 80th percentile
    if fast / slow < STEADY_SPEED_RATIO:
        return None, []
    threshold = (slow + fast) / 2

    # 1. Label every sample, then group consecutive equal labels: [label, first_index, end_index].
    #    A segment spans first_index..end_index, where end_index is the next segment's first_index.
    labels = ["work" if v >= threshold else "easy" for v in speeds]
    segments = []
    for i, label in enumerate(labels):
        if segments and segments[-1][0] == label:
            continue
        if segments:
            segments[-1][2] = i
        segments.append([label, i, None])
    segments[-1][2] = len(times) - 1

    # 2. Repeatedly absorb the shortest too-short segment into its neighbours.
    def duration(seg):
        return times[seg[2]] - times[seg[1]]

    while len(segments) > 1:
        i = min(range(len(segments)), key=lambda k: duration(segments[k]))
        if duration(segments[i]) >= MIN_SEGMENT_SECONDS:
            break
        lo, hi = max(i - 1, 0), min(i + 1, len(segments) - 1)
        label = segments[hi][0] if lo == i else segments[lo][0]  # take the neighbour's label
        segments[lo : hi + 1] = [[label, segments[lo][1], segments[hi][2]]]

    # 3. Measure each segment.
    deltas = moving_deltas(streams)
    distance = streams["distance"]
    result = []
    for label, a, b in segments:
        moving_s = sum(deltas[a + 1 : b + 1])
        metres = distance[b] - distance[a]
        result.append({
            "type": label,
            "start": times[a],
            "end": times[b],
            "metres": metres,
            "moving_seconds": moving_s,
            "pace": pace(moving_s, metres),
        })
    return 1000 / threshold, result


def summarize_reps(segments: list[dict]) -> dict | None:
    """Stats over the work reps and the recoveries between them. None if fewer than 3 reps."""
    work = [s for s in segments if s["type"] == "work"]
    if len(work) < 3:
        return None
    first, last = segments.index(work[0]), segments.index(work[-1])
    recoveries = [s for s in segments[first:last] if s["type"] == "easy"]  # excludes warm-up/cool-down

    work_s = sum(s["moving_seconds"] for s in work)
    work_m = sum(s["metres"] for s in work)
    rec_s = sum(s["end"] - s["start"] for s in recoveries)
    rec_moving_s = sum(s["moving_seconds"] for s in recoveries)
    rec_m = sum(s["metres"] for s in recoveries)
    paces = [s["pace"] for s in work if s["pace"]]
    return {
        "count": len(work),
        "avg_seconds": work_s / len(work),
        "avg_metres": work_m / len(work),
        "avg_pace": pace(work_s, work_m),
        "fastest_pace": min(paces),
        "slowest_pace": max(paces),
        "fade": paces[-1] - paces[0],  # s/km; positive = last rep slower than first
        "recovery_count": len(recoveries),
        "recovery_avg_seconds": rec_s / len(recoveries) if recoveries else None,
        "recovery_pace": pace(rec_moving_s, rec_m),
        "work_rest_ratio": work_s / rec_s if rec_s else None,
    }
