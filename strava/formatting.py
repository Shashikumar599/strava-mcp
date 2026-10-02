"""Turn raw Strava activity data into compact, readable text. Pure functions, no I/O."""

from datetime import datetime


def format_duration(seconds: int) -> str:
    """3725 -> '1:02:05'"""
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}"


def format_clock(seconds: float) -> str:
    """Compact duration: 108 -> '1:48', 3725 -> '1:02:05'."""
    hours, rest = divmod(round(seconds), 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes}:{secs:02d}"


def format_pace_per_km(seconds_per_km: float | None) -> str:
    """307.4 -> '5:07 /km'."""
    if not seconds_per_km:
        return "n/a"
    minutes, secs = divmod(round(seconds_per_km), 60)  # round first, so we never get '5:60'
    return f"{minutes}:{secs:02d} /km"


def format_pace(speed_mps: float) -> str:
    """Average speed in m/s -> pace like '5:30 /km'."""
    return format_pace_per_km(1000 / speed_mps) if speed_mps else "n/a"


def format_date(start_date_local: str) -> str:
    """'2026-09-30T07:15:00Z' -> 'Wed 30 Sep 2026 07:15'.

    Strava's start_date_local is already local time; the trailing 'Z' is misleading,
    so we just display the clock time as-is without any timezone conversion.
    """
    return datetime.fromisoformat(start_date_local).strftime("%a %d %b %Y %H:%M")


def format_run(activity: dict) -> str:
    """One run as two compact lines of text."""
    parts = [
        f"{activity['distance'] / 1000:.2f} km",
        format_duration(activity["moving_time"]),
        format_pace(activity["average_speed"]),
        f"{activity['total_elevation_gain']:.0f} m elev",
    ]
    heart_rate = activity.get("average_heartrate")
    if heart_rate:
        parts.append(f"{heart_rate:.0f} bpm avg")

    return format_title(activity) + "\n  " + " | ".join(parts)


def format_title(activity: dict) -> str:
    """'Morning Run - Mon 28 Sep 2026 08:00 (id 20359222603)'"""
    return f"{activity['name']} - {format_date(activity['start_date_local'])} (id {activity['id']})"
