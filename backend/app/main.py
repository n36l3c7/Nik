"""FastAPI application entry point.

Creates the app, ensures database tables exist on startup, and mounts all
routers under the ``/api`` prefix. A lightweight health endpoint is exposed at
``/api/health``.
"""

from __future__ import annotations

from fastapi import FastAPI

from .db import Base, engine
from .routers import audit, auth, backup, incidents, settings, users

# Import models so their tables are registered on the shared metadata before
# create_all runs. (The routers already import the models, but importing here
# makes the dependency explicit and order-independent.)
from . import models  # noqa: F401

app = FastAPI(title="CSAP API", version="1.0.0")


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
app.include_router(incidents.router, prefix="/api")
app.include_router(audit.router, prefix="/api")
app.include_router(settings.router, prefix="/api")
app.include_router(backup.router, prefix="/api")
