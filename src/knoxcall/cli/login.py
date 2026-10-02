"""`knoxcall login` — auth-code+PKCE via loopback redirect, or device flow."""

from __future__ import annotations
import argparse
import base64
import hashlib
import secrets
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx

from ..auth.credentials_file import resolve_credentials_path, resolve_profile
from ..core import _default_base_url
from ._common import CLI_CLIENT_ID, CLIError, persist_login, post_form, token_error_message

_DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


# ── PKCE (RFC 7636, S256 only) ───────────────────────────────────────────────


def generate_pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) — S256, unpadded base64url."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def build_authorize_url(
    base_url: str,
    *,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    tenant: str | None = None,
) -> str:
    params = {
        "response_type": "code",
        "client_id": CLI_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if tenant:
        params["tenant"] = tenant
    return f"{base_url}/oauth/authorize?{urlencode(params)}"


# ── Loopback redirect receiver (RFC 8252 §7.3) ───────────────────────────────


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler API
        parts = urlsplit(self.path)
        if parts.path != "/callback":
            self.send_error(404)
            return
        query = parse_qs(parts.query)
        result = {k: v[0] for k, v in query.items() if v}
        failed = "error" in result or not result.get("code")
        page = (
            "<!doctype html><meta charset='utf-8'><title>KnoxCall CLI</title>"
            "<body style='font-family:system-ui;margin:4rem auto;max-width:28rem'>"
            + (
                "<h1>Sign-in failed</h1><p>Return to your terminal for details.</p>"
                if failed
                else "<h1>Signed in</h1><p>You can close this window and return to your terminal.</p>"
            )
            + "</body>"
        )
        body = page.encode("utf8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        server: Any = self.server
        server.callback_result = result
        server.callback_event.set()

    def log_message(self, *args: Any) -> None:  # silence request logging
        pass


class LoopbackServer:
    """One-shot loopback HTTP server on 127.0.0.1:0 for the authorize redirect."""

    def __init__(self, host: str = "127.0.0.1") -> None:
        self._httpd = HTTPServer((host, 0), _CallbackHandler)
        self._httpd.callback_result = None  # type: ignore[attr-defined]
        self._httpd.callback_event = threading.Event()  # type: ignore[attr-defined]
        self.port: int = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def wait_for_code(self, *, expected_state: str, timeout: float = 300.0) -> str:
        """Block until the browser hits /callback; validate state, return the code."""
        event: threading.Event = self._httpd.callback_event  # type: ignore[attr-defined]
        if not event.wait(timeout):
            raise CLIError("timed out waiting for the browser sign-in to complete")
        result: dict[str, str] = self._httpd.callback_result or {}  # type: ignore[attr-defined]
        if result.get("error"):
            detail = result.get("error_description") or result["error"]
            raise CLIError(f"authorization failed: {detail}")
        if not secrets.compare_digest(result.get("state", ""), expected_state):
            raise CLIError("state mismatch in the OAuth callback — possible CSRF, aborting")
        code = result.get("code")
        if not code:
            raise CLIError("no authorization code in the OAuth callback")
        return code

    def close(self) -> None:
        try:
            self._httpd.shutdown()
        finally:
            self._httpd.server_close()


# ── Flows ────────────────────────────────────────────────────────────────────


def auth_code_flow(
    base_url: str,
    *,
    tenant: str | None = None,
    http: httpx.Client | None = None,
    open_browser: Callable[[str], Any] = webbrowser.open,
    timeout: float = 300.0,
) -> dict[str, Any]:
    verifier, challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(24)
    server = LoopbackServer()
    try:
        redirect_uri = f"http://127.0.0.1:{server.port}/callback"
        url = build_authorize_url(
            base_url,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=challenge,
            tenant=tenant,
        )
        print(f"Opening your browser to sign in. If it does not open, visit:\n\n  {url}\n")
        try:
            open_browser(url)
        except Exception:
            pass  # URL is printed; a broken browser launcher is not fatal
        code = server.wait_for_code(expected_state=state, timeout=timeout)
    finally:
        server.close()

    status, body = post_form(
        f"{base_url}/oauth/token",
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": CLI_CLIENT_ID,
            "code_verifier": verifier,
        },
        http,
    )
    if status >= 400 or not body.get("access_token"):
        raise CLIError(token_error_message(status, body))
    return body


def poll_device_token(
    base_url: str,
    device_code: str,
    *,
    client_id: str = CLI_CLIENT_ID,
    interval: int = 5,
    expires_in: float = 900.0,
    http: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Poll the token endpoint per RFC 8628 §3.5, honoring interval + slow_down."""
    deadline = time.monotonic() + expires_in
    while True:
        if time.monotonic() > deadline:
            raise CLIError("device authorization expired — run `knoxcall login` again")
        sleep(interval)
        status, body = post_form(
            f"{base_url}/oauth/token",
            {"grant_type": _DEVICE_GRANT, "device_code": device_code, "client_id": client_id},
            http,
        )
        if status < 400 and body.get("access_token"):
            return body
        error = body.get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += 5
            continue
        if error == "expired_token":
            raise CLIError("the device code expired — run `knoxcall login` again")
        if error == "access_denied":
            raise CLIError("sign-in was denied")
        raise CLIError(token_error_message(status, body))


def device_flow(
    base_url: str,
    *,
    http: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    status, body = post_form(
        f"{base_url}/oauth/device_authorization", {"client_id": CLI_CLIENT_ID}, http
    )
    if status >= 400 or not body.get("device_code"):
        raise CLIError(token_error_message(status, body))

    verification_uri = body.get("verification_uri") or ""
    user_code = body.get("user_code") or ""
    print(f"To sign in, open:\n\n  {verification_uri}\n\nand enter the code:\n\n  {user_code}\n")
    complete = body.get("verification_uri_complete")
    if complete:
        print(f"(or open {complete} directly)\n")
    print("Waiting for approval…")

    try:
        interval = int(body.get("interval") or 5)
    except (TypeError, ValueError):
        interval = 5
    try:
        expires_in = float(body.get("expires_in") or 900)
    except (TypeError, ValueError):
        expires_in = 900.0
    return poll_device_token(
        base_url,
        body["device_code"],
        interval=interval,
        expires_in=expires_in,
        http=http,
        sleep=sleep,
    )


# ── Command entry ────────────────────────────────────────────────────────────


def run_login(
    args: argparse.Namespace,
    *,
    http: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
    open_browser: Callable[[str], Any] | None = None,
) -> int:
    base_url = (args.base_url or _default_base_url(args.sandbox)).rstrip("/")
    path = resolve_credentials_path()
    profile = resolve_profile(args.profile)

    if args.device or args.no_browser:
        token_body = device_flow(base_url, http=http, sleep=sleep)
    else:
        token_body = auth_code_flow(
            base_url,
            tenant=args.tenant,
            http=http,
            open_browser=open_browser or webbrowser.open,
        )

    record = persist_login(
        path=path,
        profile=profile,
        base_url=base_url,
        token_body=token_body,
        fallback_tenant=args.tenant,
    )
    tenant = record.get("tenant") or "(tenant not reported)"
    print(f"\nLogged in to {tenant} ({base_url})")
    scope = record.get("scope")
    if scope:
        print(f"Scopes: {scope}")
    print(f"Credentials written to {path} (profile '{profile}')")
    if not record.get("refresh_token"):
        print("Warning: no refresh token was issued — access will expire without renewal.")
    return 0
