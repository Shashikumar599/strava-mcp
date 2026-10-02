"""GET/POST /consent: our own consent page, shown BEFORE we forward the user to Strava.

Why: Strava's consent screen only names OUR app, never the MCP client behind the request.
Without this page, a link crafted by someone else's client could ride on your Strava login
(the "confused deputy"). Here you see which client is asking and where it will send you back.

Flow (one login attempt):
  /authorize   -> pending S1 {approved: false, csrf}         -> browser to /consent?state=S1
  GET  /consent -> show the page, set the CSRF cookie
  POST /consent -> Approve: consume S1, save S2 {approved: true} -> browser to Strava (state=S2)
                   Deny:    consume S1 -> browser back to the client with error=access_denied
  /strava/callback only accepts pending requests with approved: true (callback.py)

S1 is visible in the page URL, so the attacker who started the flow knows it; it is never
accepted by the callback. S2 only exists after a human clicked Approve in this browser.
"""

import html
import secrets
import time
from urllib.parse import urlparse

from mcp.server.auth.provider import construct_redirect_uri
from mcp.shared.auth import OAuthClientInformationFull
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from auth.embedded import policy
from auth.ports import OAuthStore, PendingAuth
from auth.settings import Settings
from strava import oauth as strava_oauth

PATH = "/consent"
CSRF_COOKIE = "consent_csrf"


class ConsentPage:
    def __init__(self, store: OAuthStore, settings: Settings):
        self.store = store
        self.settings = settings

    async def handle(self, request: Request) -> Response:
        if request.method == "GET":
            return self.show(request)
        return await self.decide(request)

    # ---------- GET: show the page ----------

    def show(self, request: Request) -> Response:
        state = request.query_params.get("state", "")
        pending = self.store.get_pending(state)  # look only: the decision consumes it
        if pending is None or pending.params.get("approved"):
            return _error_page("This connection request has expired or was already used. Start again from your app.")

        params = pending.params
        response = HTMLResponse(
            _render(
                client_name=self._client_name(pending.client_id),
                scopes=params.get("scopes") or policy.SCOPES,
                return_to=_describe_destination(params["redirect_uri"]),
                state=state,
                csrf=params["csrf"],
            ),
            headers=_security_headers(params["redirect_uri"]),
        )
        # The CSRF token goes into the page AND a cookie; the POST must present both.
        # SameSite=Strict: another site can't make the browser send it with a forged POST.
        response.set_cookie(
            CSRF_COOKIE,
            params["csrf"],
            max_age=policy.PENDING_TTL,
            path=PATH,
            httponly=True,
            samesite="strict",
            secure=self.settings.base_url.startswith("https://"),
        )
        return response

    # ---------- POST: Approve or Deny ----------

    async def decide(self, request: Request) -> Response:
        form = await request.form()
        state = str(form.get("state", ""))
        pending = self.store.get_pending(state)
        if pending is None or pending.params.get("approved"):
            return _error_page("This connection request has expired or was already used. Start again from your app.")

        # CSRF: the form token and the cookie must both match what we stored for this request.
        # A forged POST from another site has neither the cookie nor (usually) the token.
        expected = pending.params["csrf"]
        if not (
            secrets.compare_digest(str(form.get("csrf", "")), expected)
            and secrets.compare_digest(request.cookies.get(CSRF_COOKIE, ""), expected)
        ):
            return _error_page("Could not verify this request came from the consent page. Please try again.", 403)

        # Single use: only one Approve/Deny can win, even if the form is submitted twice.
        if self.store.consume_pending(state) is None:
            return _error_page("This connection request was already used. Start again from your app.")
        params = pending.params

        if form.get("decision") != "approve":
            response = RedirectResponse(
                construct_redirect_uri(
                    params["redirect_uri"], error="access_denied", error_description="You denied access", state=params["state"]
                ),
                status_code=303,
            )
        else:
            # New state for Strava: the S1 visible on this page can never reach the callback.
            approved_state = policy.new_secret()
            self.store.save_pending(
                approved_state,
                PendingAuth(
                    client_id=pending.client_id,
                    params={**params, "approved": True},
                    expires_at=time.time() + policy.PENDING_TTL,
                ),
            )
            # approval_prompt=force: Strava's own consent screen every time, never silent.
            response = RedirectResponse(
                strava_oauth.authorize_url(
                    self.settings.strava_redirect_uri, state=approved_state, approval_prompt="force"
                ),
                status_code=303,  # "see other": the browser follows with a GET
            )
        response.delete_cookie(CSRF_COOKIE, path=PATH)
        return response

    def _client_name(self, client_id: str) -> str:
        info_json = self.store.get_client(client_id)
        if info_json:
            name = OAuthClientInformationFull.model_validate_json(info_json).client_name
            if name:
                return name
        return "An unnamed application"


# ---------- Rendering ----------


def _describe_destination(redirect_uri: str) -> str:
    """Where the browser goes afterwards. The client NAME can be anything; this can't, because
    redirect URIs are restricted at registration (policy.is_allowed_redirect_uri)."""
    parsed = urlparse(redirect_uri)
    if parsed.hostname in policy.LOOPBACK_HOSTS:
        return f"an app on this computer ({parsed.netloc})"
    return parsed.netloc


def _security_headers(redirect_uri: str) -> dict[str, str]:
    client_origin = "{0.scheme}://{0.netloc}".format(urlparse(redirect_uri))
    return {
        # No scripts, no external resources. The form may only post here, and the redirects that
        # follow may only go to Strava (approve) or back to the client (deny).
        "Content-Security-Policy": (
            "default-src 'none'; style-src 'unsafe-inline'; "
            f"form-action 'self' https://www.strava.com {client_origin}; "
            "frame-ancestors 'none'; base-uri 'none'"
        ),
        "X-Frame-Options": "DENY",  # no clickjacking: the page can't be framed by another site
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    }


def _error_page(message: str, status_code: int = 400) -> HTMLResponse:
    return HTMLResponse(
        _PAGE.format(body=f"<h1>Can't continue</h1><p>{html.escape(message)}</p>"),
        status_code=status_code,
        headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"},
    )


def _render(client_name: str, scopes: list[str], return_to: str, state: str, csrf: str) -> str:
    # Everything shown is escaped: client_name comes from registration, which anyone can call.
    e = html.escape
    scope_items = "".join(f"<li>{e(_SCOPE_TEXT.get(s, s))} <code>{e(s)}</code></li>" for s in scopes)
    body = f"""
      <h1>Connect to Strava MCP</h1>
      <p class="client"><strong>{e(client_name)}</strong> wants to:</p>
      <ul>{scope_items}</ul>
      <p>Afterwards you will be sent back to: <strong>{e(return_to)}</strong></p>
      <p class="note">Only approve if you just started connecting this app yourself.
      Next, you'll sign in with Strava.</p>
      <form method="post" action="{PATH}">
        <input type="hidden" name="state" value="{e(state)}">
        <input type="hidden" name="csrf" value="{e(csrf)}">
        <button type="submit" name="decision" value="approve" class="approve">Approve</button>
        <button type="submit" name="decision" value="deny">Deny</button>
      </form>"""
    return _PAGE.format(body=body)


_SCOPE_TEXT = {policy.READ_SCOPE: "Read your runs"}

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connect to Strava MCP</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 28rem; margin: 3rem auto; padding: 0 1rem; color: #222; }}
  h1 {{ font-size: 1.3rem; }}
  .note {{ color: #555; font-size: .9rem; }}
  button {{ font-size: 1rem; padding: .5rem 1.2rem; margin-right: .5rem; cursor: pointer; }}
  .approve {{ background: #fc4c02; color: #fff; border: none; border-radius: 4px; }}
  code {{ color: #777; font-size: .8rem; }}
</style></head>
<body>{body}</body></html>"""
