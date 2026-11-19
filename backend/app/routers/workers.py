"""The workers Nik leans on, and whether each one answers."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session as OrmSession

from .. import worker_watch
from ..core.db import get_db
from ..core.security import Principal, admin_principal

router = APIRouter(prefix="/workers", tags=["workers"])


@router.get("")
def read_workers(_: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Every worker (the automation worker and the analysis workers): whether
    it is configured, and what the last check found (``up``, ``failing`` since
    its first check without an answer, ``down`` once the administrators were
    told). Admins only."""
    return worker_watch.out(db)
