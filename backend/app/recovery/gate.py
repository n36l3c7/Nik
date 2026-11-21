"""The step of the entrypoint that decides whether this server serves.

Run by the API container before the migrations (``python -m
app.recovery.gate``). Three answers:

- **It is a standby** (its database replays the log of another server). It
  must not migrate, serve, fetch or run anything. The container stays up and
  answers every request with a sentence that says what it is, as a server
  that did not start does (``app/stopped.py``), while it takes in what the
  first host sends (``standby.py``). The health check passes with the word
  ``standby``: the web container comes up to show the sentence, and the
  automation worker, which waits for a backend that says ``ok``, runs
  nothing. When the standby is promoted (``deploy/standby.sh promote``) this
  step sees it within seconds, waits until that command has finished making
  this server the server (a database that left recovery is not yet one: it
  has no generation of its own and the old server was not told), and
  returns: the entrypoint goes on, and the server starts in the same
  container.

- **It was replaced**: a promotion happened while it was away and it has
  learned it (``role.py``). It answers every request with that, for good.

- **It is the server.** When it sends copies to a second host, it first lets
  the process that can reach that host ask whether a standby was promoted
  meanwhile, and waits a moment for the answer: a server that was replaced
  while it was down must find out before it serves, not a minute after. With
  no answer in time (the other host is unreachable, or this stack runs no
  automation worker) it serves: see ``role.py`` for why.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import config, role, standby

logger = logging.getLogger("nik.recovery")

PORT = 8000
INTAKE_EVERY = 5
GUIDE = " The administrator of the server finds what to do in the deployment guide (A standby host)."

STANDBY = [
    "This server is the standby: it follows the first host and serves nothing.",
    "It becomes the server when an operator runs deploy/standby.sh promote on this host.",
]
CHECKING = ["Nik is starting: it asks the second host whether this server was replaced while it was away."]
PROMOTING = [
    "This standby is being promoted: it starts as the server as soon as deploy/standby.sh promote has finished.",
    "If that command was interrupted, or the database was promoted by hand, run it again on this host.",
]


class Answering:
    """Answers every request with a sentence, in the place of the server; the health check passes
    with a word that says which state this is."""

    def __init__(self, word: str, sentences: list[str], reason: str, port: int = PORT) -> None:
        self.word = word
        self.payload = json.dumps({"detail": " ".join(sentences) + GUIDE, "stopped": {"reason": reason}}).encode(
            "utf-8"
        )
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self) -> None:
                healthy = self.path.split("?")[0] == "/api/health"
                sent = json.dumps({"status": outer.word}).encode("ascii") if healthy else outer.payload
                self.send_response(200 if healthy else 503)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(sent)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(sent)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _answer  # noqa: N815

            def log_message(self, *_args) -> None:
                return

        self._server = ThreadingHTTPServer(("0.0.0.0", port), Handler)  # noqa: S104 - inside the container, as the server binds
        self._thread = threading.Thread(target=self._server.serve_forever, name="nik-gate", daemon=True)

    def __enter__(self) -> Answering:
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._server.shutdown()
        self._server.server_close()


def _say(lines: list[str], title: str) -> None:
    sys.stderr.write("\n".join(["", "=" * 78, title, "", *(f"  {line}" for line in lines), "=" * 78, ""]) + "\n")
    sys.stderr.flush()


def _role() -> tuple[str, dict]:
    """The role of this server and what replaced it. A database with no tables yet (a new
    install) is the server."""
    from ..core.db import SessionLocal

    with SessionLocal() as db:
        if role.in_recovery(db):
            return role.STANDBY, {}
        try:
            found = role.superseded(db)
        except Exception:  # noqa: BLE001 - no table of settings yet: nothing was ever promoted
            db.rollback()
            return role.PRIMARY, {}
        return (role.SUPERSEDED, found) if found else (role.PRIMARY, {})


def promoted_since(started: float) -> bool:
    """Whether ``deploy/standby.sh promote`` made this server the server after ``started``."""
    from ..core.db import SessionLocal

    try:
        with SessionLocal() as db:
            return float(role.state(db).get("promotedAt") or 0) >= started
    except Exception:  # noqa: BLE001 - asked again
        return False


def wait_for_the_promotion(sleep=time.sleep, passes: int | None = None) -> None:
    """A database that left recovery is not yet a server: the command that promotes also gives
    this server its generation, tells the old one, and says so here by removing its mark."""
    done = 0
    while standby.promoting() and (passes is None or done < passes):
        done += 1
        sleep(1)


def follow(sleep=time.sleep, passes: int | None = None) -> None:
    """Be a standby until the database stops being one."""
    _say(STANDBY, "THIS IS THE STANDBY: IT SERVES NOTHING UNTIL IT IS PROMOTED")
    done = 0
    while passes is None or done < passes:
        done += 1
        try:
            if _role()[0] != role.STANDBY:
                logger.warning("The database is no longer a standby: this server starts")
                return
            standby.intake()
        except Exception as error:  # noqa: BLE001 - the database restarts, a file is damaged: the next pass
            logger.warning("A pass of the standby failed: %s: %s", type(error).__name__, error)
        sleep(INTAKE_EVERY)


def copies_on() -> bool:
    """Whether this server sends copies to a second host (it then is, or may be, one of a pair)."""
    from ..core.db import SessionLocal

    try:
        with SessionLocal() as db:
            return bool(config.held(db, config.SHIP_SETTINGS_ID).get("on"))
    except Exception:  # noqa: BLE001 - a database with no tables yet
        return False


def wait_for_the_answer(started: float, wait: float = role.ASK_WAIT, sleep=time.sleep) -> str:
    """Wait for the process that has a way out to say what the second host holds about this
    server. Returns ``superseded``, ``asked`` or ``unanswered``."""
    from ..core.db import SessionLocal

    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        try:
            with SessionLocal() as db:
                if role.superseded(db):
                    return "superseded"
                asked = role.state(db).get("asked") or {}
                if float(asked.get("at") or 0) >= started:
                    return "asked"
        except Exception:  # noqa: BLE001 - asked again in a moment
            pass
        sleep(1)
    return "unanswered"


def main() -> None:
    from ..backups import database, upgrade
    from ..core.config import settings

    logging.basicConfig(level=logging.WARNING, format="recovery: %(message)s", stream=sys.stderr)
    logger.setLevel(logging.INFO)
    url = database.live_url()
    if not database.is_postgres(url):
        return
    upgrade.wait_for_database(url)
    found, by = _role()
    if found == role.STANDBY:
        since = time.time()
        with Answering("standby", STANDBY, "standby"):
            follow()
        # Its database left recovery. The command that promotes left a mark before that and removes
        # it when this server has been made the server; a database promoted by hand has no mark
        # and nothing was done for it: it waits for the command too.
        if not standby.promoting() and not promoted_since(since):
            standby.mark_promoting()
    if standby.promoting():
        _say(PROMOTING, "THIS STANDBY IS BEING PROMOTED")
        with Answering("promoting", PROMOTING, "promoting"):
            wait_for_the_promotion()
        found, by = _role()
    if found == role.PRIMARY and settings.AUTOMATION_WORKER == "container" and settings.WAL_ARCHIVE_DIR and copies_on():
        started = time.time()
        with Answering("checking", CHECKING, "checking"):
            answer = wait_for_the_answer(started)
        if answer == "unanswered":
            logger.warning(
                "Nobody could say whether this server was replaced (the second host was not reached in %s seconds): "
                "it starts. If the standby was promoted, stop this stack: deploy/standby.sh rejoin",
                role.ASK_WAIT,
            )
        found, by = _role()
    if found == role.SUPERSEDED:
        lines = role.sentences(by)
        _say(lines, "NIK DID NOT START: THIS SERVER WAS REPLACED")
        with Answering("superseded", lines, "superseded") as answering:
            answering._thread.join()


if __name__ == "__main__":
    main()
