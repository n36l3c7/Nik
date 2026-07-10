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

from fastapi import FastAPI

from .db import Base, engine
from .routers import audit, auth, backup, incidents, keys, settings, users

# Import models so their tables are registered on the shared metadata before
# create_all runs. (The routers already import the models, but importing here
# makes the dependency explicit and order-independent.)
from . import models  # noqa: F401

API_DESCRIPTION = """
Nik is a forensic analysis platform. This REST API lets external clients drive
it without the browser: create / edit / delete incidents, add and remove notes,
and upload raw artifact files (parsed server-side).

**Authentication.** Write endpoints accept either a logged-in browser session
or an **API key**. Send the key in the `X-API-Key` header. Create keys in the
app under *Settings → API keys* (admin only), then click **Authorize** above to
try the endpoints here.
""".strip()

TAGS_METADATA = [
    {"name": "incidents", "description": "Create, read, edit and delete incidents."},
    {"name": "incidents/notes", "description": "Add, edit and remove incident notes."},
    {"name": "incidents/upload", "description": "Upload raw artifact files; parsed server-side."},
    {"name": "settings", "description": "Shared detection rules and business hours (read via key)."},
    {"name": "api-keys", "description": "Manage API keys (admin session only)."},
    {"name": "auth", "description": "Session login/logout (browser)."},
    {"name": "users", "description": "User management (admin session only)."},
    {"name": "audit", "description": "Global audit log."},
    {"name": "backup", "description": "Full platform export/restore (admin session only)."},
    {"name": "health", "description": "Liveness probe."},
]

app = FastAPI(
    title="Nik API",
    version="1.0.0",
    description=API_DESCRIPTION,
    openapi_tags=TAGS_METADATA,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)


@app.on_event("startup")
def on_startup() -> None:
    """Create all tables on first run (no Alembic needed for v1)."""
    Base.metadata.create_all(bind=engine)


@app.get("/api/health", tags=["health"])
def health() -> dict:
    """Simple liveness probe."""
    return {"status": "ok"}


# Mount routers under /api. Each router declares its own sub-prefix.
app.include_router(auth.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(keys.router, prefix="/api")
app.include_router(incidents.router, prefix="/api")
app.include_router(audit.router, prefix="/api")
app.include_router(settings.router, prefix="/api")
app.include_router(backup.router, prefix="/api")
