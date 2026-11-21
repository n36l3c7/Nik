"""A server that does not start, and says why to whoever asks.

When a key of the server is missing, is given twice, cannot be read, or is
not the one the store of files is sealed under, starting anyway would be the
worst answer: files written under a key nobody keeps, or a store nothing can
open. Exiting is the second worst: the container would restart for ever and
the page would show a blank error.

So the container stays up and answers every request with the sentence that
says what is wrong (``serve``), as a stopped upgrade does
(``backups/upgrade.py``), until an operator acts. The health check passes, so
that the web container comes up to show the sentence.

The sentence names variables and files, never a value.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8000
PREFIX = "Nik did not start: "


def body(sentences: list[str]) -> dict:
    return {
        "detail": PREFIX + " ".join(sentences) + " The administrator of the server finds the same lines in the log "
        "of the api container, and what to do in the deployment guide (Keys of the server).",
        "stopped": {"reason": "keys"},
    }


def explain(sentences: list[str]) -> str:
    lines = ["", "=" * 78, "NIK DID NOT START: A KEY OF THE SERVER IS MISSING OR IS NOT THE RIGHT ONE", ""]
    lines += [f"  - {sentence}" for sentence in sentences]
    lines += [
        "",
        "Nothing was changed. Until this is set right the container answers every request with these lines.",
        "=" * 78,
        "",
    ]
    return "\n".join(lines)


def server(sentences: list[str], port: int = PORT) -> ThreadingHTTPServer:
    """What answers every request in the place of the server that did not start."""
    payload = json.dumps(body(sentences)).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def _answer(self) -> None:
            healthy = self.path.split("?")[0] == "/api/health"
            sent = b'{"status":"stopped"}' if healthy else payload
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

    return ThreadingHTTPServer(("0.0.0.0", port), Handler)  # noqa: S104 - inside the container, as the server binds


def serve(sentences: list[str]) -> None:
    """Say why in the log, then answer every request with it, for ever."""
    sys.stderr.write(explain(sentences))
    sys.stderr.flush()
    server(sentences).serve_forever()
