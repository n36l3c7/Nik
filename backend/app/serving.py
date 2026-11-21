"""How the API process is served, and how it stops.

    gunicorn -k app.serving.Worker app.main:app --graceful-timeout 30

The worker is uvicorn's, with one thing set: how long a process that is asked
to stop (SIGTERM: ``docker compose restart``, ``up -d --build``, the host
shutting down) waits for the requests in flight. For ``API_STOP_GRACE``
seconds it takes no new connection and lets the requests finish; then the ones
that are not over are cut (an upload that was still arriving fails in the
browser with a sentence that says to send it again, and the transfers tray
offers to), the shutdown of the application runs (``main.on_shutdown``: work
handed back, leases given back) and the process exits.

Without this the process waited for its requests with no limit of its own, an
analysis started by a request counted as one, and gunicorn killed the process
at the end of its own timeout before anything was handed back.

The three numbers nest: ``API_STOP_GRACE`` (20 s) is less than gunicorn's
``--graceful-timeout`` (30 s), which is less than the ``stop_grace_period``
of the container (40 s). A kill, or the power, skips all of it: the work is
then found by its heartbeat (``work.py``) and the leases run out.
"""

from __future__ import annotations

import os

from uvicorn.workers import UvicornWorker

STOP_GRACE = int(os.environ.get("API_STOP_GRACE", "20"))


class Worker(UvicornWorker):
    CONFIG_KWARGS = {**UvicornWorker.CONFIG_KWARGS, "timeout_graceful_shutdown": STOP_GRACE}
