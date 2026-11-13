"""The disk of the file store: how large, how full, and with what."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session as OrmSession

from .. import storage
from ..core.db import get_db
from ..core.security import Principal, admin_principal

router = APIRouter(prefix="/storage", tags=["storage"])


@router.get("")
def read_storage(_: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)) -> dict:
    """The disk that holds the file store (total, used, free), Nik's share of
    it by kind of file, and its largest objects. Admins only."""
    return storage.usage(db)
