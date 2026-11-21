"""The keys of the server, the encryption of the store, and the files handed to the automation worker.

``/api/system/keys`` is what *Settings → Keys* reads: where each key comes
from, its fingerprint, when it last changed, what it protects, and where a
change stands. Asking for a change is done by a signed-in administrator who
gives the password again (and a code, with a second factor): never by an API
key. No route here returns or takes the value of a key.

``/api/storage/encryption`` is the state of the conversion of a store from
before 6.8, shown on the Storage screen, with its pause.

``/api/internal/store/…`` is not for people: see ``app/store_handover.py``.
"""

from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from .. import key_rotation, signin, store_handover, store_seal
from ..core.db import get_db
from ..core.files import stored_response
from ..core.models import User
from ..core.security import Principal, admin_principal, admin_session, current_user
from ..malware.samples import is_sha256, mail_path, sample_path

router = APIRouter(tags=["keys"])
internal = APIRouter(prefix="/internal", tags=["keys"], include_in_schema=False)


class Confirmed(BaseModel):
    """Who asks, proved again: the password, and a code when the account has a second factor."""

    password: str = Field(default="", max_length=1024)
    code: Optional[str] = Field(default=None, max_length=32)
    recoveryCode: Optional[str] = Field(default=None, max_length=64)


class EncryptionAction(BaseModel):
    action: Literal["pause", "resume", "check"]


def _name(name: str) -> str:
    if name not in key_rotation.ASKED:
        raise HTTPException(status_code=404, detail="Nik does not change this key by itself.")
    return name


@router.get("/system/keys")
def read_keys(_: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Every key of the server: where it comes from (a file, the environment), its fingerprint, since
    when it is in use, what it protects, which containers hold it, and where a change of it stands.
    Never a value, never a part of one. Admins only."""
    return key_rotation.overview(db)


@router.get("/system/keys/{name}/rotation")
def read_rotation_plan(name: str, _: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)) -> dict:
    """What a change of this key would put under the new one, counted now, the containers that
    restart, and the command that does it on the host."""
    return key_rotation.plan(db, _name(name))


@router.post("/system/keys/{name}/rotation")
def request_rotation(
    name: str,
    body: Confirmed,
    request: Request,
    caller: Principal = Depends(admin_session),
    user: User = Depends(current_user),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Ask for this key to be changed. The caller gives the password again, and a code when the
    account has a second factor. The answer says what will be put under the new key and the command
    to run on the host within a day: the server cannot write where its own keys are kept."""
    name = _name(name)
    signin.confirm_identity(db, request, user, body.password, body.code, body.recoveryCode)
    asked = key_rotation.request(db, name, caller.actor)
    db.commit()
    return asked


@router.delete("/system/keys/{name}/rotation")
def cancel_rotation(name: str, caller: Principal = Depends(admin_session), db: OrmSession = Depends(get_db)) -> dict:
    """Withdraw a request that was not carried out yet."""
    key_rotation.cancel(db, _name(name), caller.actor)
    db.commit()
    return {"request": None}


@router.get("/storage/encryption")
def read_encryption(_: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Whether every file of the store is sealed, and since when; while a store from before 6.8 is
    being sealed, how many files and bytes are done and left, how long it will take, what is stuck;
    the files found damaged."""
    return store_seal.status(db)


@router.post("/storage/encryption")
def change_encryption(
    body: EncryptionAction, caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """``pause`` the conversion, ``resume`` it, or ``check`` again a store that is sealed (files put
    back by hand from a copy made before 6.8 are then sealed)."""
    if body.action == "check":
        store_seal.check_again(db, caller.actor)
    else:
        store_seal.set_paused(db, body.action == "pause", caller.actor)
    db.commit()
    store_seal.forget()
    return store_seal.status(db)


@internal.get("/store/{kind}/{ref}")
def hand_over(kind: str, ref: str, x_nik_store: str = Header(default="")):
    """A sample or an e-mail of the store, decrypted, for the automation worker (it holds no store
    key). The request proves it comes from a process of this server (``store_handover.verify``);
    anything else is answered as if the route did not exist."""
    if kind not in store_handover.KINDS or not is_sha256(ref) or not store_handover.verify(kind, ref, x_nik_store):
        raise HTTPException(status_code=404, detail="Not Found")
    path = sample_path(ref) if kind == "sample" else mail_path(ref)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="The file is not in the store")
    return stored_response(path, "application/octet-stream")
