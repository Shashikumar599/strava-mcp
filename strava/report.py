"""Build the text report for a single run: Strava's own numbers + our stream analysis.

Each section function returns a block of text, or None when there's nothing to show.
"""

from strava import analysis
from strava.formatting import (
    format_clock,
    format_duration,
    format_pace,
    format_pace_per_km,
    format_title,
)

MAX_SEGMENT_ROWS = 25


def run_report(activity: dict, streams: dict) -> str:
    sections = [
        summary_section(activity),
        pacing_section(streams) if streams else None,
        splits_section(activity),
        laps_section(activity),
        best_efforts_section(activity),
        segments_section(streams) if streams else None,
        profile_section(streams) if streams else "No per-second data for this activity (e.g. manual entry).",
    ]
    return "\n\n".join(s for s in sections if s)


def summary_section(activity: dict) -> str:
    stats = " | ".join([
        f"{activity['distance'] / 1000:.2f} km",
        f"moving {format_duration(activity['moving_time'])}",
        f"elapsed {format_duration(activity['elapsed_time'])}",
        f"avg {format_pace(activity['average_speed'])}",
        f"max {format_pace(activity['max_speed'])}",
        f"{activity['total_elevation_gain']:.0f} m elev gain",
    ])
    if activity.get("has_heartrate"):
        heart_rate = f"avg {activity['average_heartrate']:.0f} / max {activity['max_heartrate']:.0f} bpm"
    else:
        heart_rate = "not recorded"
    # Strava reports running cadence per leg; double it for steps per minute.
    cadence = activity.get("average_cadence")
    cadence = f"{cadence * 2:.0f} spm" if cadence else "not recorded"
    device = activity.get("device_name") or "unknown"
    return (
        f"{format_title(activity)}\n"
        f"{stats}\n"
        f"Device: {device} | heart rate: {heart_rate} | cadence: {cadence}"
    )


def pacing_section(streams: dict) -> str:
    first, second = analysis.half_splits(streams)
    lines = ["PACING"]
    if first and second:
        diff = second - first
        kind = "even" if abs(diff) <= 5 else ("negative split" if diff < 0 else "positive split")
        lines.append(
            f"  1st half {format_pace_per_km(first)} | 2nd half {format_pace_per_km(second)}"
            f" ({kind}, {diff:+.0f} s/km)"
        )
    variability = analysis.pace_variability(streams)
    if variability is not None:
        level = "low, steady" if variability < 0.10 else "moderate" if variability < 0.18 else "high, interval/fartlek-like"
        lines.append(f"  Pace variability: {variability:.0%} ({level})")
    return "\n".join(lines)


def splits_section(activity: dict) -> str | None:
    splits = activity.get("splits_metric") or []
    if not splits:
        return None
    lines = ["KM SPLITS (pace, elevation change)"]
    for s in splits:
        label = f"km {s['split']:>2}"
        if s["distance"] < 950:  # final partial km
            label += f" ({s['distance'] / 1000:.2f} km)"
        line = f"  {label}  {format_pace(s['average_speed'])}  {s.get('elevation_difference') or 0:+.0f} m"
        if s.get("average_heartrate"):
            line += f"  {s['average_heartrate']:.0f} bpm"
        lines.append(line)
    return "\n".join(lines)


def laps_section(activity: dict) -> str | None:
    laps = activity.get("laps") or []
    if len(laps) < 2:  # a single lap is just the whole run
        return None
    if all(980 <= lap["distance"] <= 1020 for lap in laps[:-1]):  # 1 km auto-laps = km splits again
        return None
    lines = ["LAPS"]
    for number, lap in enumerate(laps, start=1):
        line = (
            f"  lap {number:>2}  {lap['distance'] / 1000:.2f} km  "
            f"{format_clock(lap['moving_time'])}  {format_pace(lap['average_speed'])}"
        )
        if lap.get("average_heartrate"):
            line += f"  {lap['average_heartrate']:.0f} bpm"
        lines.append(line)
    return "\n".join(lines)


def best_efforts_section(activity: dict) -> str | None:
    efforts = activity.get("best_efforts") or []
    if not efforts:
        return None
    return "BEST EFFORTS (within this run)\n  " + " | ".join(
        f"{e['name']} {format_clock(e['elapsed_time'])}" for e in efforts
    )


def segments_section(streams: dict) -> str:
    threshold, segments = analysis.detect_segments(streams)
    if not segments:
        return "SEGMENTS\n  Steady effort: no distinct fast/slow segments detected."

    lines = [
        f"SEGMENTS (auto-detected; WORK = faster than {format_pace_per_km(threshold)}, "
        f"min {analysis.MIN_SEGMENT_SECONDS} s)"
    ]
    many = len(segments) > MAX_SEGMENT_ROWS
    work_label, easy_label = ("Fast stretches", "Slow stretches") if many else ("Reps", "Recoveries")
    if many:
        lines.append(
            f"  {len(segments)} segments: frequent fast/slow alternation (e.g. run/walk), too many to list."
        )
    else:
        for s in segments:
            lines.append(
                f"  {s['type'].upper() if s['type'] == 'work' else s['type']:4}  "
                f"{format_clock(s['start']):>7}-{format_clock(s['end']):<7}  "
                f"{s['metres']:5.0f} m  {format_pace_per_km(s['pace'])}"
            )

    reps = analysis.summarize_reps(segments)
    if reps:
        lines.append(
            f"  {work_label}: {reps['count']} x avg {format_clock(reps['avg_seconds'])} / {reps['avg_metres']:.0f} m"
            f" at {format_pace_per_km(reps['avg_pace'])}"
            f" (fastest {format_pace_per_km(reps['fastest_pace'])}, slowest {format_pace_per_km(reps['slowest_pace'])},"
            f" last vs first {reps['fade']:+.0f} s/km)"
        )
        if reps["recovery_count"]:
            lines.append(
                f"  {easy_label}: {reps['recovery_count']} x avg {format_clock(reps['recovery_avg_seconds'])}"
                f" at {format_pace_per_km(reps['recovery_pace'])} | work:rest {reps['work_rest_ratio']:.1f}:1"
            )
    return "\n".join(lines)


def profile_section(streams: dict) -> str:
    size, rows = analysis.pace_profile(streams)
    has_hr = rows[0]["heartrate"] is not None
    has_cadence = rows[0]["cadence"] is not None

    header = "     time      km   pace/km     alt   grade"
    header += "    hr" if has_hr else ""
    header += "   spm" if has_cadence else ""
    lines = [f"PACE & ELEVATION PROFILE (every {format_clock(size)}; pace excludes pauses)", header]
    for r in rows:
        pace_text = format_pace_per_km(r["pace"]).replace(" /km", "") if r["pace"] else "-"
        line = f"  {format_clock(r['start']):>7}  {r['km']:6.2f}  {pace_text:>8}"
        line += f"  {r['altitude']:5.0f} m" if r["altitude"] is not None else "        -"
        line += f"  {r['grade']:+5.1f}%" if r["grade"] is not None else "       -"
        if has_hr:
            line += f"  {r['heartrate']:4.0f}"
        if has_cadence:
            line += f"  {r['cadence'] * 2:4.0f}"
        if r["paused"] >= 1:
            line += f"  (paused {format_clock(r['paused'])})"
        lines.append(line)
    return "\n".join(lines)
