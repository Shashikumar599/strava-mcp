"""Strava MCP server: the MCP layer and composition root.

Strava logic lives in strava/, authentication in auth/. Start with `uv run server.py`,
then connect an MCP client to http://127.0.0.1:8000/mcp (it will run the OAuth login).
"""

import logging
import os
from contextlib import contextmanager
from datetime import date
from urllib.parse import urlparse

import httpx
from mcp.server.auth.middleware.auth_context import get_access_token as current_mcp_token
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from auth.factory import build_auth
from auth.ports import StravaCredentials
from auth.settings import Settings
from strava.api import fetch_activity, fetch_streams, is_run, iter_activities
from strava.formatting import format_run
from strava.report import run_report
from strava.runs import parse_cursor, select_runs, strava_window

# 127.0.0.1 locally: not reachable from other machines. In a container (Fly.io) HOST=0.0.0.0,
# so the platform's proxy, which connects from outside the container, can reach the server.
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def create_server(settings: Settings) -> MCPServer:
    """Wire settings -> auth -> MCP server -> tools. Nothing is created at import time."""
    auth = build_auth(settings)
    mcp = MCPServer("strava", **auth.mcp_kwargs)
    for route in auth.routes:
        mcp.custom_route(route.path, methods=route.methods)(route.handler)
    register_tools(mcp, auth.credentials)

    @mcp.custom_route("/health", methods=["GET"])
    async def health(request: Request) -> PlainTextResponse:
        """Liveness check for the hosting platform. No auth, reveals nothing."""
        return PlainTextResponse("ok")

    return mcp


@contextmanager
def strava_errors():
    """Turn failures from strava/ and auth/ into ToolErrors with a clear message for Claude."""
    try:
        yield
    except httpx.HTTPStatusError as e:
        status = e.response.status_code
        if status == 401:
            raise ToolError("Strava rejected the access token (401). Reconnect the server in your MCP client.")
        if status == 404:
            raise ToolError("Not found on Strava (404). Check the activity id (get it from get_runs).")
        if status == 429:
            raise ToolError("Strava rate limit reached (429). Limits reset every 15 minutes; try again later.")
        raise ToolError(f"Strava API error ({status}): {e.response.text[:200]}")
    except httpx.RequestError as e:
        raise ToolError(f"Could not reach Strava: {e}")
    except RuntimeError as e:  # missing Strava connection or failed refresh, from auth/
        raise ToolError(str(e))


def register_tools(mcp: MCPServer, credentials: StravaCredentials) -> None:
    def strava_token() -> str:
        """Strava access token for whoever made this MCP request."""
        token = current_mcp_token()  # set by the SDK after verifying the Bearer token
        if token is None or token.subject is None:
            raise ToolError("Not authenticated.")
        return credentials.get_access_token(token.subject)  # subject = Strava athlete id

    @mcp.tool()
    def get_runs(
        start_date: date | None = None,
        end_date: date | None = None,
        limit: int = 20,
        cursor: str | None = None,
    ) -> str:
        """List the user's runs from Strava, newest first, optionally within a date range.

        Only running activities are included (Run, TrailRun, VirtualRun). With no arguments,
        returns the most recent runs. Dates are the user's local dates (YYYY-MM-DD), both
        inclusive; leave start_date empty for "from the beginning" and end_date for "until today".
        The account may have gaps (years with no activities); an empty result is not an error.

        For each run: name, local start date/time, activity id, distance (km), moving time
        (h:mm:ss), average pace (min:ss per km), elevation gain (m), and average heart rate
        (bpm) when recorded. Pass an id to analyze_run for a detailed breakdown.

        Pagination: each call returns at most `limit` runs. If more runs exist in the range, the
        result ends with a cursor; call get_runs again with the same dates and that cursor to get
        the next (older) page. Repeat until the result says "End of results".

        Args:
            start_date: Earliest local date to include (YYYY-MM-DD). Default: no lower bound.
            end_date: Latest local date to include (YYYY-MM-DD). Default: today.
            limit: Runs per page, 1 to 100 (values outside are clamped). Default 20.
            cursor: Value from the previous page's result, to fetch the next page.
        """
        if start_date and end_date and start_date > end_date:
            raise ToolError(f"start_date {start_date} is after end_date {end_date}.")
        limit = max(1, min(limit, 100))
        try:
            cursor_epoch = parse_cursor(cursor)
        except ValueError as e:
            raise ToolError(str(e))

        with strava_errors():
            after, before = strava_window(start_date, end_date, cursor_epoch)
            activities = iter_activities(strava_token(), after=after, before=before)
            page = select_runs(activities, start_date, end_date, limit, cursor_epoch)

        span = f"{start_date or 'beginning'} to {end_date or 'today'}"
        if not page.runs:
            return f"No runs found from {span}" + (" after this cursor." if cursor else ".")
        header = f"Runs from {span}, newest first ({len(page.runs)} on this page):"
        body = "\n\n".join(format_run(run) for run in page.runs)
        if page.next_cursor:
            footer = f'More runs in this range: call get_runs again with the same dates and cursor="{page.next_cursor}".'
        else:
            footer = "End of results for this range."
        return f"{header}\n\n{body}\n\n{footer}"

    @mcp.tool()
    def analyze_run(activity_id: int) -> str:
        """Detailed analysis of one run, for questions about pacing, intervals, effort or terrain.

        Get activity_id from get_runs. Returns these sections (paces in min:ss per km):
        - Summary: distance, moving/elapsed time, avg and max pace, elevation gain, device,
          heart rate and cadence (steps/min) if recorded.
        - Pacing: 1st-half vs 2nd-half pace (even/negative/positive split) and pace variability.
        - Km splits: pace and elevation change per km (heart rate if recorded).
        - Laps (only if the run has more than one lap) and Strava's best efforts within the run.
        - Segments: auto-detected WORK (fast) / easy stretches with time range, distance and pace,
          plus a rep summary for interval sessions (rep count, avg/fastest/slowest pace, fade from
          first to last rep, recovery length/pace, work:rest ratio). Detection is a heuristic based
          on the run's own speed spread; steady runs report no segments.
        - Pace & elevation profile: one row per fixed time bucket (15 s to 10 min, chosen so a run
          has at most ~70 rows) with elapsed time, distance, pace, altitude, grade, and heart rate /
          cadence if recorded. Pauses are excluded from pace.
        """
        with strava_errors():
            token = strava_token()
            activity = fetch_activity(token, activity_id)
            if not is_run(activity):
                raise ToolError(f"Activity {activity_id} is a {activity.get('sport_type')}, not a run.")
            streams = fetch_streams(token, activity_id)

        return run_report(activity, streams)


class RedactQueryStrings(logging.Filter):
    """Strip query strings from uvicorn's access log lines.

    OAuth puts short-lived secrets in URLs (`/strava/callback?code=…&state=…`,
    `/consent?state=…`), and uvicorn logs every request path in full. Logs are kept and
    often widely readable, so they get `/strava/callback?[redacted]` instead.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # uvicorn: '%s - "%s %s HTTP/%s" %d' % (client, method, path_with_query, http_version, status)
        if isinstance(record.args, tuple) and len(record.args) == 5 and "?" in str(record.args[2]):
            args = list(record.args)
            args[2] = str(args[2]).split("?", 1)[0] + "?[redacted]"
            record.args = tuple(args)
        return True


def transport_security(settings: Settings) -> TransportSecuritySettings:
    """DNS-rebinding protection: only accept requests addressed to us by name.

    Always localhost; plus the public host from BASE_URL when the server is reached through
    a public domain or proxy (requests then carry e.g. `Host: strava-mcp.fly.dev`).
    """
    hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    origins = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]
    if urlparse(settings.base_url).hostname not in LOOPBACK_HOSTS:
        hosts.append(settings.public_host)
        origins.append(settings.base_url)
    return TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=origins)


if __name__ == "__main__":
    # Streamable HTTP: MCP messages are POSTed to http://HOST:PORT/mcp.
    settings = Settings.from_env()
    logging.getLogger("uvicorn.access").addFilter(RedactQueryStrings())
    create_server(settings).run(
        transport="streamable-http", host=HOST, port=PORT, transport_security=transport_security(settings)
    )
