"""Observability: request ids, structured access logs, and Prometheus metrics.

Wired in ``main.py`` via one HTTP middleware plus the ``/api/metrics`` and
``/api/ready`` endpoints. Kept dependency-light (prometheus-client only).
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from contextvars import ContextVar

# The server runs several API processes, and a scrape reaches one of them. With
# PROMETHEUS_MULTIPROC_DIR set (the image sets it, to a directory of the memory-backed /tmp),
# every process writes its counts there and whichever answers a scrape adds them up. The
# directory has to be there before the first metric is made.
_SHARED = os.environ.get("PROMETHEUS_MULTIPROC_DIR", "")
if _SHARED:
    os.makedirs(_SHARED, exist_ok=True)

from prometheus_client import (  # noqa: E402
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
    multiprocess,
)
from starlette.requests import Request  # noqa: E402
from starlette.responses import Response  # noqa: E402

# Current request id, available to log records anywhere in the request.
request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")

REQUEST_ID_HEADER = "X-Request-ID"

_logger = logging.getLogger("nik.access")

# --- Prometheus metrics --------------------------------------------------- #
REQUESTS = Counter(
    "nik_http_requests_total",
    "HTTP requests",
    ["method", "path", "status"],
)
LATENCY = Histogram(
    "nik_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "path"],
)


class _RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        record.request_id = request_id_ctx.get()
        return True


def setup_logging(level: str = "INFO") -> None:
    """Configure a single structured stream handler for the app loggers."""
    handler = logging.StreamHandler()
    handler.addFilter(_RequestIdFilter())
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(request_id)s] %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())


def _templates(routes, prefix: str = "") -> dict[int, str]:
    """Every route of the application by identity, with its whole path: a route of a router that
    was included under a prefix knows only its own part (``/incidents/{incident_id}``)."""
    found: dict[int, str] = {}
    for route in routes:
        inner = getattr(route, "original_router", None)
        if inner is not None:
            context = getattr(route, "include_context", None)
            found.update(_templates(inner.routes, prefix + (getattr(context, "prefix", "") or "")))
        elif hasattr(route, "path"):
            found[id(route)] = prefix + route.path
    return found


def _route_template(request: Request) -> str:
    """Low-cardinality path label: the matched route as it is written in the API
    (``/api/incidents/{incident_id}``), never the concrete URL.

    A request that matches no route is counted under one label, so a scanner
    asking for random paths cannot grow the metrics without bound.
    """
    route = request.scope.get("route")
    if route is None:
        return "unmatched"
    state = request.app.state
    known = getattr(state, "nik_route_templates", None)
    if known is None or id(route) not in known:
        known = _templates(request.app.routes)
        state.nik_route_templates = known
    return known.get(id(route)) or getattr(route, "path", "unmatched")


async def observability_middleware(request: Request, call_next):
    """Assign/propagate a request id, time the request, log it, count metrics."""
    rid = request.headers.get(REQUEST_ID_HEADER) or uuid.uuid4().hex[:12]
    token = request_id_ctx.set(rid)
    start = time.perf_counter()
    status_code = 500
    try:
        response: Response = await call_next(request)
        status_code = response.status_code
        response.headers[REQUEST_ID_HEADER] = rid
        return response
    finally:
        elapsed = time.perf_counter() - start
        path = _route_template(request)
        method = request.method
        try:
            REQUESTS.labels(method, path, str(status_code)).inc()
            LATENCY.labels(method, path).observe(elapsed)
        except Exception:  # pragma: no cover - metrics must never break a request
            pass
        # Skip the noisy metrics scrape from the access log.
        if path != "/api/metrics":
            _logger.info("%s %s -> %s (%.1f ms)", method, request.url.path, status_code, elapsed * 1000)
        request_id_ctx.reset(token)
        # The response object exists only on the success path; header set there.


def request_metrics() -> bytes:
    """The requests this server answered, in the Prometheus exposition format: those of every
    API process when they share a directory, those of this one otherwise."""
    if _SHARED:
        registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(registry)
        return generate_latest(registry)
    return generate_latest()


def metrics_response(body: bytes) -> Response:
    return Response(body, media_type=CONTENT_TYPE_LATEST)
