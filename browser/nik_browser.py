"""Isolated browser sessions: Chromium (Playwright) driven by screenshots.

The analyst never runs the page: this worker does, and sends back a JPEG of
the viewport after every action (click, typing, a key, scroll, navigation).

**Network**, chosen per session:

- ``network=False`` (the default): the page is the attachment itself, served
  at ``https://attachment.nik.invalid/``; every other request (images,
  scripts, frames, navigations, form posts) is refused.
- ``network=True``: http and https requests go out, except to private,
  loopback, link-local or otherwise non-public addresses and internal names,
  so a page cannot reach the organisation's own network. Other schemes are
  refused.

**Submissions** (POST, PUT, PATCH, DELETE) of a session with network are
held by default: recorded, not sent, and the page shows "Submission held by
Nik". The analyst may release them for the session (``policy`` action).

Every request is recorded in the session's network log (``netlog.py``):
headers, bodies in clear, responses, server addresses, certificates,
timings, WebSocket messages, refused and held requests included. The log of
a closed or expired session stays readable for ``FINISHED_KEEP`` seconds.

Downloads are refused (and reported), dialogs (alert, confirm, prompt) are
dismissed and reported, permission prompts are denied, a page opened in a new
tab replaces the current one. Sessions end after ``IDLE`` seconds without an
action, or ``LIFETIME`` seconds in all.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import os
import socket
import threading
import time
import uuid
from html import escape as html_escape
from typing import Any
from urllib.parse import urlsplit

from netlog import NetworkLog, timing

ATTACHMENT_URL = "https://attachment.nik.invalid/"
WIDTH, HEIGHT = 1280, 800
IDLE = float(os.environ.get("BROWSER_IDLE", "300"))
LIFETIME = float(os.environ.get("BROWSER_LIFETIME", "1800"))
MAX_SESSIONS = int(os.environ.get("BROWSER_MAX_SESSIONS", "3"))
FINISHED_KEEP = 900
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
NAV_TIMEOUT = 20_000
SETTLE = 0.8
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
)
INTERNAL_SUFFIXES = (".local", ".lan", ".internal", ".intranet", ".corp", ".home", ".home.arpa", ".localdomain")


class BrowserError(Exception):
    """An action that could not be done; ``status`` is the HTTP status to answer."""

    def __init__(self, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.status = status


def _public_host(host: str) -> bool:
    """True when every address the host resolves to is public."""
    host = (host or "").lower().strip("[]").rstrip(".")
    if not host or "." not in host and ":" not in host or host.endswith(INTERNAL_SUFFIXES):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    addresses = {info[4][0].split("%")[0] for info in infos}
    return bool(addresses) and all(ipaddress.ip_address(a).is_global for a in addresses)


def _blocked_page(url: str, reason: str) -> str:
    safe = html_escape(url[:500])
    return (
        '<!doctype html><title>Blocked by Nik</title><body style="font:16px sans-serif;margin:3em;color:#222">'
        f'<h2>Navigation blocked by Nik</h2><p><code style="word-break:break-all">{safe}</code></p>'
        f"<p>Reason: {html_escape(reason)}.</p><p>Use Back to return to the previous page.</p></body>"
    )


def _held_page(url: str) -> str:
    safe = html_escape(url[:500])
    return (
        "<!doctype html><title>Submission held by Nik</title>"
        '<body style="font:16px sans-serif;margin:3em;color:#222"><h2>Submission held by Nik</h2>'
        f'<p>The page tried to send data to <code style="word-break:break-all">{safe}</code>.</p>'
        "<p>It was recorded (see the Network panel) and not sent. Use Back to return.</p></body>"
    )


class Session:
    def __init__(self, owner: str, network: bool) -> None:
        self.id = uuid.uuid4().hex
        self.owner = owner
        self.network = network
        # Submissions are held unless the analyst releases them for the session.
        self.hold = network
        self.created = self.used = time.monotonic()
        self.closed_at: float | None = None
        self.context = None
        self.page = None
        self.events: list[dict[str, Any]] = []
        self.blocked = 0
        self.log = NetworkLog()

    def note(self, kind: str, text: str) -> None:
        self.events.append({"kind": kind, "text": text[:300], "at": time.time()})
        del self.events[:-50]


class Browser:
    """One Chromium, many contexts; every call runs on the worker's event loop."""

    def __init__(self, executable: str | None = None) -> None:
        self.executable = executable or os.environ.get("BROWSER_EXECUTABLE") or None
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, name="browser-loop", daemon=True)
        self.thread.start()
        self.sessions: dict[str, Session] = {}
        self.finished: dict[str, Session] = {}
        self._playwright = None
        self._browser = None

    # -- plumbing ---------------------------------------------------------- #
    def call(self, coroutine, timeout: float = 60):
        return asyncio.run_coroutine_threadsafe(coroutine, self.loop).result(timeout)

    async def _chromium(self):
        if self._browser is None or not self._browser.is_connected():
            from playwright.async_api import async_playwright

            if self._playwright is None:
                self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                executable_path=self.executable,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-background-networking"],
            )
        return self._browser

    def _get(self, session_id: str, owner: str) -> Session:
        session = self.sessions.get(session_id)
        if session is None or session.owner != owner:
            raise BrowserError("No such session (it may have expired)", 404)
        session.used = time.monotonic()
        return session

    def _record(self, session: Session, request) -> dict[str, Any] | None:
        """The log entry of a request, created on first sight (event or route, whichever comes first)."""
        existing = session.log.get(request)
        if existing is not None:
            return existing
        try:
            main = request.frame == session.page.main_frame
        except Exception:  # noqa: BLE001 - a detached frame
            main = False
        previous = request.redirected_from
        entry = session.log.entry(
            request,
            method=request.method,
            url=request.url[:8000],
            resourceType=request.resource_type,
            navigation=request.is_navigation_request(),
            frame="main" if main else "sub",
            redirectedFrom=session.log.by_key.get(previous) if previous is not None else None,
        )
        if entry is not None:
            entry["request"] = {
                "headers": [[k, v] for k, v in request.headers.items()],
                **session.log.body(request.post_data_buffer),
            }
        return entry

    async def _finished(self, session: Session, request) -> None:
        entry = self._record(session, request)
        if entry is None or entry["state"] in ("blocked", "held"):
            return
        try:
            response = await request.response()
            headers = [[h["name"], h["value"]] for h in await request.headers_array()]
        except Exception:  # noqa: BLE001 - the page or context is gone
            return
        reply: dict[str, Any] = {}
        if response is not None:
            try:
                body = await response.body()
            except Exception:  # noqa: BLE001 - redirects and some responses have no body
                body = None
            server = await response.server_addr()
            tls = await response.security_details()
            reply = {
                "status": response.status,
                "statusText": response.status_text,
                "headers": [[h["name"], h["value"]] for h in await response.headers_array()],
                "mimeType": (response.headers.get("content-type") or "").split(";")[0].strip(),
                "serverIp": (server or {}).get("ipAddress"),
                "serverPort": (server or {}).get("port"),
                "tls": tls or None,
                **session.log.body(body),
            }
        session.log.update(
            request,
            state="local" if request.url.startswith(ATTACHMENT_URL) else "done",
            request={**entry["request"], "headers": headers},
            response=reply,
            timing=timing(request.timing),
            endedAt=time.time() * 1000,
        )

    def _failed(self, session: Session, request) -> None:
        entry = self._record(session, request)
        if entry is not None and entry["state"] == "pending":
            session.log.update(request, state="failed", error=(request.failure or "")[:300], endedAt=time.time() * 1000)

    async def _allowed(self, session: Session, url: str, schemes: tuple[str, ...]) -> str | None:
        """None when the request may go out, else why not."""
        if not session.network:
            return "no network in this session"
        parts = urlsplit(url)
        if parts.scheme not in schemes:
            return f"{parts.scheme or 'this'} scheme not allowed"
        public = await asyncio.get_running_loop().run_in_executor(None, _public_host, parts.hostname or "")
        return None if public else "not a public address"

    async def _route(self, session: Session, html: bytes | None, route) -> None:
        request = route.request
        url = request.url
        self._record(session, request)
        if url.startswith(ATTACHMENT_URL) and html is not None:
            await route.fulfill(status=200, content_type="text/html; charset=utf-8", body=html)
            return
        reason = await self._allowed(session, url, ("http", "https"))
        main_navigation = request.is_navigation_request() and request.frame == session.page.main_frame
        if reason is None and session.hold and request.method not in SAFE_METHODS:
            session.log.update(request, state="held", reason="submission held by Nik", endedAt=time.time() * 1000)
            session.note("held", f"{request.method} to {url[:200]} held (not sent)")
            if main_navigation:
                await route.fulfill(status=200, content_type="text/html; charset=utf-8", body=_held_page(url))
            else:
                await route.abort("blockedbyclient")
            return
        if reason is None:
            await route.continue_()
            return
        session.blocked += 1
        session.log.update(request, state="blocked", reason=reason, endedAt=time.time() * 1000)
        if main_navigation:
            session.note("blocked", f"navigation to {url[:200]} refused ({reason})")
            # A page saying so, instead of the browser's error page.
            await route.fulfill(status=200, content_type="text/html; charset=utf-8", body=_blocked_page(url, reason))
            return
        await route.abort("blockedbyclient")

    async def _websocket(self, session: Session, socket_route) -> None:
        log = session.log
        log.entry(socket_route, method="GET", url=socket_route.url[:8000], resourceType="websocket", frame="main")
        reason = await self._allowed(session, socket_route.url, ("ws", "wss"))
        if reason is not None:
            session.blocked += 1
            log.update(socket_route, state="blocked", reason=reason, endedAt=time.time() * 1000)
            await socket_route.close(code=1008, reason="Blocked by Nik")
            return
        server = socket_route.connect_to_server()

        def outgoing(message) -> None:
            log.frame(socket_route, "sent", message)
            server.send(message)

        def incoming(message) -> None:
            log.frame(socket_route, "received", message)
            socket_route.send(message)

        socket_route.on_message(outgoing)
        server.on_message(incoming)
        log.update(socket_route, state="done", response={"status": 101, "statusText": "Switching Protocols"})

    def _watch(self, session: Session, page) -> None:
        page.on("dialog", lambda dialog: self._dialog(session, dialog))
        page.on(
            "download", lambda download: session.note("download", f"download refused: {download.suggested_filename}")
        )
        page.on("popup", lambda popup: self._popup(session, popup))

    def _dialog(self, session: Session, dialog) -> None:
        session.note("dialog", f"{dialog.type}: {dialog.message}")
        asyncio.ensure_future(dialog.dismiss())

    def _popup(self, session: Session, popup) -> None:
        session.note("popup", "a new tab opened: shown here instead")
        session.page = popup
        self._watch(session, popup)

    async def _state(self, session: Session) -> dict[str, Any]:
        await asyncio.sleep(SETTLE)
        page = session.page
        try:
            await page.wait_for_load_state("load", timeout=3000)
        except Exception:  # noqa: BLE001 - a page still loading is shown as it is
            pass
        try:
            title = await page.title()
        except Exception:  # noqa: BLE001
            title = ""
        shot = await page.screenshot(type="jpeg", quality=70, timeout=10_000)
        return {
            "id": session.id,
            "url": "" if page.url.startswith(ATTACHMENT_URL) else page.url,
            "attachment": page.url.startswith(ATTACHMENT_URL),
            "title": title[:300],
            "network": session.network,
            "width": WIDTH,
            "height": HEIGHT,
            "screenshot": base64.b64encode(shot).decode(),
            "blocked": session.blocked,
            "releasePosts": session.network and not session.hold,
            "log": session.log.counts(),
            "events": session.events[-10:],
        }

    # -- API --------------------------------------------------------------- #
    async def _open(self, session: Session, html: bytes | None, url: str | None) -> dict[str, Any]:
        browser = await self._chromium()
        context = await browser.new_context(
            viewport={"width": WIDTH, "height": HEIGHT},
            user_agent=USER_AGENT,
            accept_downloads=False,
            service_workers="block",
            java_script_enabled=True,
            locale="en-US",
        )
        session.context = context
        context.on("request", lambda request: self._record(session, request))
        context.on("requestfinished", lambda request: self._finished(session, request))
        context.on("requestfailed", lambda request: self._failed(session, request))
        await context.route("**/*", lambda route: self._route(session, html, route))
        await context.route_web_socket("**/*", lambda socket_route: self._websocket(session, socket_route))
        session.page = await context.new_page()
        self._watch(session, session.page)
        target = ATTACHMENT_URL if html is not None else url
        try:
            await session.page.goto(target, timeout=NAV_TIMEOUT, wait_until="load")
        except Exception as exc:  # noqa: BLE001 - shown as an event, the session stays open
            session.note("error", f"loading stopped: {str(exc).splitlines()[0][:200]}")
        return await self._state(session)

    def open(self, owner: str, network: bool, html: bytes | None = None, url: str | None = None) -> dict[str, Any]:
        self.expire()
        if len(self.sessions) >= MAX_SESSIONS:
            raise BrowserError("Too many open browser sessions; close one first", 503)
        if url is not None and urlsplit(url).scheme not in ("http", "https"):
            raise BrowserError("Only http and https addresses can be opened")
        session = Session(owner, network)
        self.sessions[session.id] = session
        try:
            return self.call(self._open(session, html, url))
        except Exception:
            self.close(session.id, owner)
            raise

    async def _act(self, session: Session, action: dict[str, Any]) -> dict[str, Any]:
        page = session.page
        kind = action.get("type")
        if kind in ("click", "dblclick", "move"):
            x, y = float(action.get("x", 0)), float(action.get("y", 0))
            if not (0 <= x <= WIDTH and 0 <= y <= HEIGHT):
                raise BrowserError("The point is outside the page")
            if kind == "move":
                await page.mouse.move(x, y)
            else:
                await page.mouse.click(x, y, click_count=2 if kind == "dblclick" else 1)
        elif kind == "type":
            await page.keyboard.type(str(action.get("text", ""))[:2000], delay=10)
        elif kind == "key":
            key = str(action.get("key", ""))
            if key not in ALLOWED_KEYS:
                raise BrowserError("Unsupported key")
            await page.keyboard.press(key)
        elif kind == "scroll":
            await page.mouse.wheel(0, max(-5000, min(5000, float(action.get("dy", 0)))))
        elif kind == "navigate":
            url = str(action.get("url", ""))
            if urlsplit(url).scheme not in ("http", "https"):
                raise BrowserError("Only http and https addresses can be opened")
            try:
                await page.goto(url, timeout=NAV_TIMEOUT, wait_until="load")
            except Exception as exc:  # noqa: BLE001
                session.note("error", f"loading stopped: {str(exc).splitlines()[0][:200]}")
        elif kind in ("back", "forward", "reload"):
            try:
                await getattr(page, {"back": "go_back", "forward": "go_forward", "reload": "reload"}[kind])(
                    timeout=NAV_TIMEOUT
                )
            except Exception as exc:  # noqa: BLE001
                session.note("error", f"{kind}: {str(exc).splitlines()[0][:200]}")
        elif kind == "policy":
            if not session.network:
                raise BrowserError("A session without network sends nothing: there is nothing to release")
            session.hold = not bool(action.get("releasePosts"))
            session.note("policy", "submissions are now " + ("held" if session.hold else "SENT"))
        elif kind != "refresh":
            raise BrowserError("Unknown action")
        return await self._state(session)

    def act(self, session_id: str, owner: str, action: dict[str, Any]) -> dict[str, Any]:
        session = self._get(session_id, owner)
        return self.call(self._act(session, action))

    async def _close(self, session: Session) -> None:
        if session.context is not None:
            try:
                await session.context.close()
            except Exception:  # noqa: BLE001 - already gone
                pass

    def close(self, session_id: str, owner: str) -> None:
        session = self.sessions.get(session_id)
        if session is None or session.owner != owner:
            raise BrowserError("No such session (it may have expired)", 404)
        self._finish(session)

    def _finish(self, session: Session) -> None:
        """Close the browser context; the network log stays readable for a while."""
        self.sessions.pop(session.id, None)
        session.closed_at = time.monotonic()
        self.finished[session.id] = session
        self.call(self._close(session))

    def expire(self) -> int:
        now = time.monotonic()
        stale = [s for s in self.sessions.values() if now - s.used > IDLE or now - s.created > LIFETIME]
        for session in stale:
            self._finish(session)
        for old in [s for s in self.finished.values() if now - (s.closed_at or now) > FINISHED_KEEP]:
            self.finished.pop(old.id, None)
        return len(stale)

    async def _network(self, session: Session, since: int, bodies: bool) -> dict[str, Any]:
        return {
            "cursor": session.log.seq,
            "entries": session.log.since(since, bodies),
            "closed": session.closed_at is not None,
            "counts": session.log.counts(),
        }

    def network(self, session_id: str, owner: str, since: int = 0, bodies: bool = False) -> dict[str, Any]:
        """The entries changed since ``since`` (open, closed or expired sessions)."""
        session = self.sessions.get(session_id) or self.finished.get(session_id)
        if session is None or session.owner != owner:
            raise BrowserError("No such session (it may have expired)", 404)
        return self.call(self._network(session, since, bodies))


ALLOWED_KEYS = {
    "Enter", "Tab", "Backspace", "Delete", "Escape", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight",
    "Home", "End", "PageUp", "PageDown", "Shift+Tab", "Space",
}  # fmt: skip
