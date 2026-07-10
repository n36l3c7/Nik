"""Observability: request ids, structured access logs, and Prometheus metrics.

Wired in ``main.py`` via one HTTP middleware plus the ``/api/metrics`` and
``/api/ready`` endpoints. Kept dependency-light (prometheus-client only).
"""

from __future__ import annotations

import logging
import time
import uuid
from contextvars import ContextVar

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.requests import Request
from starlette.responses import Response

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
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s [%(request_id)s] %(name)s: %(message)s")
    )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())


def _route_template(request: Request) -> str:
    """Low-cardinality path label (the matched route, not the concrete URL)."""
    route = request.scope.get("route")
    return getattr(route, "path", request.url.path)


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


def metrics_response() -> Response:
    """Render the Prometheus exposition format."""
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
