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

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as OrmSession

from . import artifact_jobs, key_rotation, store_seal, urlscan_queue, worker_watch
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
from .core.security import Refused
from .core.store import SealError
from .enrichment import worker as enrichment_worker
from .iocs import backfill as backfill_iocs
from .query import QueryError, QueryForbidden
from .routers import (
    annotations,
    artifacts,
    audit,
    auth,
    automation,
    backup,
    backups,
    capa_rules,
    connectors,
    context,
    credentials,
    dashboards,
    enrichment,
    fetch,
    fields,
    filters,
    flirt,
    incident_page,
    incident_types,
    incidents,
    ioc_library,
    iocs,
    jobs,
    keys,
    lists,
    mailboxes,
    mails,
    mappers,
    mirror,
    network,
    packs,
    playground,
    preprocess,
    previews,
    query,
    report,
    samples,
    script_signatures,
    search,
    settings,
    storage,
    system_keys,
    tasks,
    urls,
    users,
    war_room,
    webhooks,
    yara_rules,
)
from .routers import (
    health as health_details,
)
from .routers import workers as worker_status

setup_logging(app_settings.LOG_LEVEL)
# The store asks this whether files in clear may still be there, and tells it of a damaged one.
store_seal.install()

API_DESCRIPTION = """
Nik is a forensic analysis platform. This REST API lets external clients drive
it without the browser: create / edit / delete incidents, add and remove notes,
and upload raw artifact files (parsed server-side).

**Authentication.** Write endpoints accept either a logged-in browser session
or an **API key**. Send the key in the `X-API-Key` header. Create keys in the
app under *Settings → API keys* (admin only), then click **Authorize** above to
try the endpoints here.

**Roles.** An account or a key holds one or more roles, and may do what they
grant together: `viewer` reads; `analyst` reads, changes, uploads and analyses;
`rules` manages the YARA, capa and FLIRT rule sets; `audit` reads the audit
log; `admin` does everything, and alone manages accounts, keys, storage,
backups and the settings that decide what leaves the server. `playbooks`,
`connectors` and `dashboards` belong to features of later 4.x releases. A
read-only key is a key with the role `viewer`. Keys may carry an expiry.
`GET /api/auth/me` answers with the roles and the permissions they grant.
""".strip()

TAGS_METADATA = [
    {"name": "incidents", "description": "Create, read, edit and delete incidents."},
    {"name": "incidents/notes", "description": "Add, edit and remove incident notes."},
    {"name": "incidents/upload", "description": "Upload raw artifact files; parsed server-side (optionally async)."},
    {"name": "jobs", "description": "Status of async jobs (e.g. background uploads)."},
    {"name": "automation", "description": "Playbooks, their versions, runs and the general switch."},
    {
        "name": "query",
        "description": "One query language over incidents, artifacts, indicators and the audit log.",
    },
    {"name": "yara-rules", "description": "YARA rules added to the built-in set (rules.manage to change)."},
    {
        "name": "flirt-signatures",
        "description": "Uploaded FLIRT signatures applied by the analyzer worker (rules.manage to change).",
    },
    {"name": "capa-rules", "description": "Added capa rules, checked by the capa worker (rules.manage to change)."},
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
        "description": "Manage API keys (admin session or admin key). Set each key's roles and expiry.",
    },
    {
        "name": "auth",
        "description": "Signing in and out (browser), the second factor, the sessions, the sign-in policy.",
    },
    {"name": "users", "description": "User management (admin session or admin key)."},
    {"name": "audit", "description": "Global audit log (the audit.read permission)."},
    {
        "name": "backup",
        "description": "The backups Nik takes by itself, and the export of content as one file (admins).",
    },
    {
        "name": "keys",
        "description": "The keys of the server: where each comes from, what it protects, changing one (admins).",
    },
    {"name": "health", "description": "Liveness probe; for administrators, the health page of the server."},
]

app = FastAPI(
    title="Nik API",
    version="6.8.0",
    description=API_DESCRIPTION,
    openapi_tags=TAGS_METADATA,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# Request ids + structured access logs + Prometheus metrics.
app.middleware("http")(observability_middleware)

# What a browser sends on behalf of another site is refused before anything
# else looks at it. The session cookie is SameSite=Lax, which already keeps it
# out of another site's requests that change something; this does not depend
# on the cookie, and also covers a page of a sibling host of the same site.
# Browsers say where a request comes from in Sec-Fetch-Site; a client that is
# not a browser (an API key, a webhook) does not send it and is not concerned.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_HOOKS = "/api/automation/hooks/"


@app.middleware("http")
async def same_origin_only(request: Request, call_next):
    path = request.url.path
    # A webhook is called with its own secret address, by whatever the sender is.
    if request.method not in _SAFE_METHODS and path.startswith("/api/") and not path.startswith(_HOOKS):
        site = request.headers.get("sec-fetch-site")
        if site is not None and site not in ("same-origin", "none"):
            return JSONResponse(
                status_code=403,
                content={"detail": "This request was sent by another site and is refused", "code": "cross_site"},
            )
    return await call_next(request)


# Per-IP rate limiting (blanket default; login adds a stricter limit).
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


@app.on_event("startup")
def on_startup() -> None:
    """Create all tables when not using migrations, index IOCs, start the loops of the process.

    In production run Alembic (``alembic upgrade head``, see backend/alembic).
    ``RUN_CREATE_ALL=false`` disables this so migrations own the schema.
    """
    if app_settings.RUN_CREATE_ALL:
        Base.metadata.create_all(bind=engine)
    # SECRET_KEY was changed: move what the old one encrypted to the new one (the key of the client
    # certificate the audit log is forwarded with is among it: core/vault.py lists every place).
    vault.reencrypt(SessionLocal)
    # Incidents saved before 2.12.0 have no indicator index yet.
    backfill_iocs(SessionLocal)
    # Samples, e-mails and captures stored before 2.19.0 have no artifact entry yet.
    backfill_artifacts(SessionLocal)
    # The system fields of the registry (a release may add some).
    from . import fields as field_registry
    from . import incident_types as type_registry

    with SessionLocal() as db:
        try:
            # The types Nik ships too, each added once.
            from . import dashboards as boards
            from . import jsanalysis
            from . import lists as named_lists
            from .core.security import now_iso as stamp

            seeded = field_registry.seed(db) + type_registry.seed(db) + named_lists.seed(db) + boards.seed(db)
            # The script signatures Nik ships (those nobody changed here follow a release).
            if seeded + jsanalysis.seed(db, stamp()):
                db.commit()
        except IntegrityError:
            db.rollback()  # another process of the server added them at the same moment
    # Automatic threat-intelligence lookups (one process at a time, see worker.py).
    if app_settings.ENRICHMENT_WORKER:
        enrichment_worker.start()
    # The administrators are told when a worker stops answering (one process at a time, see worker_watch.py).
    if app_settings.API_BACKGROUND:
        worker_watch.start()
        # A store from before 6.8 is sealed file by file, and a key that was changed is followed to
        # its end (one process at a time, see store_seal.py and key_rotation.py).
        key_rotation.start()
        # Backups are taken and tested here (one process at a time, see backups/scheduler.py).
        from .backups import scheduler as backup_scheduler

        backup_scheduler.start()
        # Their copies off the server leave from the process that runs playbooks: this one only when it does.
        if app_settings.AUTOMATION_WORKER == "inline":
            backup_scheduler.start_shipper()
        # The chain of the audit log is walked here every few minutes (one process at a time, see
        # auditlog/chain.py); the log leaves for syslog from the process that runs playbooks.
        from .auditlog import chain as audit_chain
        from .auditlog import forward as audit_forward

        audit_chain.start()
        if app_settings.AUTOMATION_WORKER == "inline":
            audit_forward.start()
        # The health of the server is looked at once a minute, and the administrators told (health/watch.py).
        from .health import watch as health_watch

        health_watch.start()
    # What this process does outside a request is held, and what lost its holder is found (work.py):
    # the analyses, the scans, the mailboxes, what playbooks ask about files.
    from . import work
    from .automation import worker as automation_loop

    work.starting()
    automation_loop._stopping.clear()
    if app_settings.API_BACKGROUND:
        work.start()
    # The scans of addresses that playbooks ask for run here: the automation worker cannot reach the isolated browser.
    if app_settings.API_BACKGROUND and app_settings.AUTOMATION_WORKER != "off":
        urlscan_queue.start()
        # So does what playbooks ask about files: the worker cannot write to the store nor reach the analysis workers.
        artifact_jobs.start()
    # The scripts and the connectors Nik ships are there (a release may bring new versions),
    # and the playbooks it ships were added once.
    if app_settings.AUTOMATION_WORKER != "off":
        from .automation import connector_actions, shipped
        from .automation import scripts as automation_scripts

        with SessionLocal() as db:
            try:
                # All three, so that none is skipped when another has nothing new. The playbooks
                # last: they are checked against the scripts and the connectors that are there.
                changed = automation_scripts.seed(db) + connector_actions.seed(db)
                db.flush()
                # The mappers the shipped connectors come with (those nobody changed follow a release).
                from . import mapping

                changed += mapping.seed(db)
                changed += shipped.seed(db)
                # The SMTP server the e-mail node of 4.x used becomes an instance of the Mail connector.
                changed += int(connector_actions.adopt_smtp(db))
                if changed:
                    db.commit()
            except IntegrityError:
                # Another process of the server added them at the same moment.
                db.rollback()
    # What Nik ships is written down as packs, once everything above is there.
    from . import packs as content_packs

    with SessionLocal() as db:
        try:
            # What came inside Nik before 6.0 and is a vendor's becomes the pack it is from now on.
            if content_packs.register_builtin(db) + content_packs.adopt_legacy(db):
                db.commit()
        except IntegrityError:
            db.rollback()  # another process of the server wrote them at the same moment
        # The packs of the folder an administrator filled, for a Nik without the catalogue.
        if app_settings.PACKS_DIR:
            from pathlib import Path

            content_packs.install_folder(db, Path(app_settings.PACKS_DIR))
        # The API keys the look-ups kept before 6.5 become keys of instances of the connectors that are here.
        from .enrichment import old_keys

        try:
            old_keys.adopt(db)
            db.commit()
        except IntegrityError:
            db.rollback()  # another process of the server made the instances at the same moment
    # Playbooks: the loop runs here only when there is no automation container.
    if app_settings.AUTOMATION_WORKER == "inline":
        from .automation import worker as automation_worker

        automation_worker.start_inline()


@app.on_event("shutdown")
def on_shutdown() -> None:
    """The process was asked to stop and its requests are over (or were given their time,
    app/serving.py): the loops take nothing new, the work this process holds is handed back as
    wanted, and every lease it took is given back. The process that starts next, here or on
    another host, takes all of it at once instead of waiting for it to run out."""
    from . import work
    from .automation import worker as automation_worker
    from .core import leases

    automation_worker._stopping.set()
    work.release_all()
    leases.release_all()


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
def metrics(request: Request, db: OrmSession = Depends(get_db)):
    """Prometheus metrics, for the bearer of the scrape token and nobody else (``health/metrics.py``):
    a session cookie or an API key gets 401 like no credential at all."""
    from .health import metrics as health_metrics

    if not health_metrics.allowed(db, request.headers.get("Authorization", "")):
        raise HTTPException(status_code=401, detail="Not authenticated", headers={"WWW-Authenticate": "Bearer"})
    return metrics_response(health_metrics.exposition(db))


@app.exception_handler(QueryError)
def _query_error(_request: Request, error: QueryError) -> JSONResponse:
    """A query that cannot be read: where, and why, in fixed sentences."""
    return JSONResponse(status_code=422, content={"detail": error.message, "query": error.as_dict()})


@app.exception_handler(Refused)
def _refused(_request: Request, error: Refused) -> JSONResponse:
    """A refusal the interface tells apart by its code (a second factor to set up, a network not allowed)."""
    return JSONResponse(
        status_code=error.status_code, content={"detail": error.detail, "code": error.code}, headers=error.headers
    )


@app.exception_handler(SealError)
def _damaged_file(_request: Request, error: SealError) -> JSONResponse:
    """A file of the store that does not open is never served as if it were fine: the sentence names
    it and says why. The audit log and the administrators were told where it was found."""
    return JSONResponse(status_code=500, content={"detail": str(error), "code": "file_damaged"})


@app.exception_handler(QueryForbidden)
def _query_forbidden(_request: Request, _error: QueryForbidden) -> JSONResponse:
    return JSONResponse(status_code=403, content={"detail": "You do not have the permission this needs"})


# Mount routers under /api. Each router declares its own sub-prefix.
app.include_router(auth.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(keys.router, prefix="/api")
app.include_router(incidents.router, prefix="/api")
app.include_router(ioc_library.router, prefix="/api")
app.include_router(mailboxes.router, prefix="/api")
app.include_router(iocs.router, prefix="/api")
app.include_router(search.router, prefix="/api")
app.include_router(query.router, prefix="/api")
app.include_router(automation.router, prefix="/api")
app.include_router(automation.incident_router, prefix="/api")
app.include_router(connectors.router, prefix="/api")
app.include_router(credentials.router, prefix="/api")
app.include_router(fields.router, prefix="/api")
app.include_router(fields.incident_router, prefix="/api")
app.include_router(incident_types.router, prefix="/api")
app.include_router(incident_page.router, prefix="/api")
app.include_router(context.router, prefix="/api")
app.include_router(war_room.router, prefix="/api")
app.include_router(playground.router, prefix="/api")
app.include_router(tasks.router, prefix="/api")
app.include_router(lists.router, prefix="/api")
app.include_router(mappers.router, prefix="/api")
app.include_router(fetch.router, prefix="/api")
app.include_router(preprocess.router, prefix="/api")
app.include_router(mirror.router, prefix="/api")
app.include_router(dashboards.router, prefix="/api")
app.include_router(filters.router, prefix="/api")
app.include_router(packs.router, prefix="/api")
app.include_router(script_signatures.router, prefix="/api")
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
app.include_router(system_keys.router, prefix="/api")
app.include_router(system_keys.internal, prefix="/api")
app.include_router(backup.router, prefix="/api")
app.include_router(backups.router, prefix="/api")
app.include_router(storage.router, prefix="/api")
app.include_router(worker_status.router, prefix="/api")
app.include_router(health_details.router, prefix="/api")
