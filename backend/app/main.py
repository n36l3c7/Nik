"""FastAPI application entry point.

Creates the app, ensures database tables exist on startup, and mounts all
routers under the ``/api`` prefix. A lightweight health endpoint is exposed at
``/api/health``.

The interactive API documentation (Swagger UI) is served under ``/api/docs``
(nginx only proxies ``/api`` to the backend; root paths hit the SPA). It is
public to view; calling the write endpoints requires an ``X-API-Key`` header
(use the *Authorize* button) or a browser session.
"""

from __future__ import annotations

import hmac

from fastapi import Depends, FastAPI, HTTPException, Request
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from .artifacts import backfill as backfill_artifacts

# Import models so their tables are registered on the shared metadata before
# create_all runs. (The routers already import the models, but importing here
# makes the dependency explicit and order-independent.)
from .core import (
    models,  # noqa: F401
    vault,
)
from .core.config import settings as app_settings
from .core.db import Base, SessionLocal, engine, get_db
from .core.observability import metrics_response, observability_middleware, setup_logging
from .core.ratelimit import limiter
from .enrichment import worker as enrichment_worker
from .iocs import backfill as backfill_iocs
from .malware.samples import repair_store_permissions
from .routers import (
    annotations,
    artifacts,
    audit,
    auth,
    backup,
    capa_rules,
    enrichment,
    flirt,
    incidents,
    iocs,
    jobs,
    keys,
    mails,
    network,
    previews,
    report,
    samples,
    search,
    settings,
    urls,
    users,
    webhooks,
    yara_rules,
)

setup_logging(app_settings.LOG_LEVEL)

API_DESCRIPTION = """
Nik is a forensic analysis platform. This REST API lets external clients drive
it without the browser: create / edit / delete incidents, add and remove notes,
and upload raw artifact files (parsed server-side).

**Authentication.** Write endpoints accept either a logged-in browser session
or an **API key**. Send the key in the `X-API-Key` header. Create keys in the
app under *Settings → API keys* (admin only), then click **Authorize** above to
try the endpoints here.

**Key permissions.** Each key is created with a role and scopes bound to it:
an *analyst* key can work with incidents, notes and uploads; an *admin* key can
also manage users and backups. A read-only key (`scopes: ["read"]`) cannot
mutate anything. Keys may carry an expiry.
""".strip()

TAGS_METADATA = [
    {"name": "incidents", "description": "Create, read, edit and delete incidents."},
    {"name": "incidents/notes", "description": "Add, edit and remove incident notes."},
    {"name": "incidents/upload", "description": "Upload raw artifact files; parsed server-side (optionally async)."},
    {"name": "jobs", "description": "Status of async jobs (e.g. background uploads)."},
    {"name": "yara-rules", "description": "Admin-managed YARA rules, compiled with the built-in set (admin only)."},
    {
        "name": "flirt-signatures",
        "description": "Admin-uploaded FLIRT signatures applied by the analyzer worker (admin to change).",
    },
    {"name": "capa-rules", "description": "Admin capa rules, checked by the capa worker (admin to change)."},
    {
        "name": "samples",
        "description": "Malware samples: stored on the server, analysed statically, downloaded as a protected zip.",
    },
    {
        "name": "artifacts",
        "description": "Files, e-mails and captures analysed on their own, then linked to incidents.",
    },
    {"name": "webhooks", "description": "Outbound event subscriptions (admin session or admin key)."},
    {"name": "settings", "description": "Shared detection rules and business hours (read via key)."},
    {
        "name": "api-keys",
        "description": "Manage API keys (admin session or admin key). Set each key's role/scopes/expiry.",
    },
    {"name": "auth", "description": "Session login/logout (browser)."},
    {"name": "users", "description": "User management (admin session or admin key)."},
    {"name": "audit", "description": "Global audit log."},
    {"name": "backup", "description": "Full platform export/restore (admin session or admin key)."},
    {"name": "health", "description": "Liveness probe."},
]

app = FastAPI(
    title="Nik API",
    version="3.3.3",
    description=API_DESCRIPTION,
    openapi_tags=TAGS_METADATA,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# Request ids + structured access logs + Prometheus metrics.
app.middleware("http")(observability_middleware)

# Per-IP rate limiting (blanket default; login adds a stricter limit).
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


@app.on_event("startup")
def on_startup() -> None:
    """Create all tables when not using migrations, repair the sample store, index IOCs.

    In production run Alembic (``alembic upgrade head``, see backend/alembic).
    ``RUN_CREATE_ALL=false`` disables this so migrations own the schema. The
    store pass makes samples saved by older releases readable by the workers.
    """
    if app_settings.RUN_CREATE_ALL:
        Base.metadata.create_all(bind=engine)
    # SECRET_KEY was changed: move what the old one encrypted to the new one.
    vault.reencrypt(SessionLocal)
    # Samples stored by releases before 2.7.0 are 0o440: the workers could not read them.
    repair_store_permissions()
    # Incidents saved before 2.12.0 have no indicator index yet.
    backfill_iocs(SessionLocal)
    # Samples, e-mails and captures stored before 2.19.0 have no artifact entry yet.
    backfill_artifacts(SessionLocal)
    # Automatic threat-intelligence lookups (one process at a time, see worker.py).
    if app_settings.ENRICHMENT_WORKER:
        enrichment_worker.start()


@app.get("/api/health", tags=["health"])
def health() -> dict:
    """Liveness probe (process is up)."""
    return {"status": "ok"}


@app.get("/api/ready", tags=["health"])
def ready(db: OrmSession = Depends(get_db)) -> dict:
    """Readiness probe: also checks the database is reachable."""
    db.execute(text("SELECT 1"))
    return {"status": "ready"}


@app.get("/api/metrics", tags=["health"], include_in_schema=False)
def metrics(request: Request):
    """Prometheus metrics exposition (with ``METRICS_TOKEN`` set, for its bearer only)."""
    token = app_settings.METRICS_TOKEN
    sent = request.headers.get("Authorization", "")
    if token and not hmac.compare_digest(sent.encode(), f"Bearer {token}".encode()):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return metrics_response()


# Mount routers under /api. Each router declares its own sub-prefix.
app.include_router(auth.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(keys.router, prefix="/api")
app.include_router(incidents.router, prefix="/api")
app.include_router(iocs.router, prefix="/api")
app.include_router(search.router, prefix="/api")
app.include_router(report.router, prefix="/api")
app.include_router(jobs.router, prefix="/api")
app.include_router(samples.router, prefix="/api")
app.include_router(mails.router, prefix="/api")
app.include_router(previews.router, prefix="/api")
app.include_router(network.router, prefix="/api")
app.include_router(artifacts.router, prefix="/api")
app.include_router(urls.router, prefix="/api")
app.include_router(enrichment.router, prefix="/api")
app.include_router(annotations.router, prefix="/api")
app.include_router(yara_rules.router, prefix="/api")
app.include_router(flirt.router, prefix="/api")
app.include_router(capa_rules.router, prefix="/api")
app.include_router(webhooks.router, prefix="/api")
app.include_router(audit.router, prefix="/api")
app.include_router(settings.router, prefix="/api")
app.include_router(backup.router, prefix="/api")
