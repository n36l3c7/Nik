"""Stored credentials (Settings, Credentials).

A credential is a secret kept once under a name; the instances of the
connectors name it where they would hold a value (``automation/credentials.py``).
It is managed by who manages the instances and their keys
(``connectors.manage``): the same people could type the value into an
instance.

The value is write-only. It is stored encrypted and no route gives it back:
a credential says its name, its kind, the user name of a pair, when it was
changed and by whom, and the instances that use it. One that is used is not
deleted, and keeps its name.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from ..automation import connector_actions, credentials, engine, instance_keys
from ..core import audit, vault
from ..core.db import get_db
from ..core.models import Connection, Credential
from ..core.security import Principal, manager_principal, now_iso

router = APIRouter(prefix="/automation", tags=["automation"])


class CredentialIn(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    title: str = Field(default="", max_length=200)
    kind: str = Field(default="secret", max_length=10)
    username: str = Field(default="", max_length=500)  # of a pair
    # Write-only: the value of a secret, the password of a pair.
    value: str = Field(min_length=1, max_length=credentials.VALUE_MAX)


class CredentialPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=40)
    title: str | None = Field(default=None, max_length=200)
    username: str | None = Field(default=None, max_length=500)
    # Left out, the value stays as it is; it is never read back to be sent again.
    value: str | None = Field(default=None, max_length=credentials.VALUE_MAX)


def _out(row: Credential, used: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "title": row.title,
        "kind": row.kind,
        "username": row.username if row.kind == "pair" else "",
        # Whether the value can still be read (it cannot once SECRET_KEY changed): never the value.
        "readable": bool(row.secret) and vault.decrypt(row.secret) is not None,
        "usedBy": used,
        "createdAt": row.created_at,
        "createdBy": row.created_by,
        "updatedAt": row.updated_at,
        "updatedBy": row.updated_by,
    }


def _row(db: OrmSession, credential_id: str) -> Credential:
    row = db.get(Credential, credential_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Credential not found")
    return row


def _username(value: str) -> str:
    text = value.strip()
    if not text:
        raise credentials.CredentialError("The user name of a pair is needed")
    if credentials.mentions(text):
        raise credentials.CredentialError("A credential holds a value, not the name of another credential")
    return text


@router.get("/credentials")
def list_credentials(_caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)) -> dict:
    """The stored credentials, by name, each with the instances that use it. Never a value."""
    used = credentials.uses(db)
    rows = db.scalars(select(Credential).order_by(func.lower(Credential.name))).all()
    return {"credentials": [_out(row, used.get(row.name, [])) for row in rows]}


@router.post("/credentials", status_code=status.HTTP_201_CREATED)
def create_credential(
    body: CredentialIn, caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> dict:
    try:
        if body.kind not in credentials.KINDS:
            raise credentials.CredentialError("A credential is a secret (one value) or a pair (user name and password)")
        name = credentials.clean_name(db, body.name)
        what = "The password" if body.kind == "pair" else "The value"
        now = now_iso()
        row = Credential(
            id=engine.new_id(),
            name=name,
            title=body.title.strip(),
            kind=body.kind,
            username=_username(body.username) if body.kind == "pair" else "",
            secret=vault.encrypt(credentials.clean_value(body.value, what)),
            created_at=now,
            created_by=caller.actor,
            updated_at=now,
            updated_by=caller.actor,
        )
    except credentials.CredentialError as error:
        raise HTTPException(status_code=error.status, detail=error.message) from None
    db.add(row)
    audit.record(
        db,
        caller.actor,
        "credential.create",
        f'Made the credential "{name}" ({credentials.what(row)})',
        target=name,
    )
    db.commit()
    return _out(row, [])


@router.put("/credentials/{credential_id}")
def update_credential(
    credential_id: str,
    body: CredentialPatch,
    caller: Principal = Depends(manager_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Change a credential. Its value is replaced, never shown: left out, it stays. A new value is what
    every instance that names the credential sends from its next request on."""
    row = _row(db, credential_id)
    used = credentials.uses(db).get(row.name, [])
    changes = []
    sends_differently = False
    try:
        if body.name is not None and body.name.strip() != row.name:
            if used:
                raise credentials.CredentialError(
                    f'"{row.name}" is used by {credentials.used_text(used)}: a credential that is used keeps its name',
                    409,
                )
            new_name = credentials.clean_name(db, body.name, but=row)
            changes.append(f'renamed from "{row.name}"')
            row.name = new_name
        if body.title is not None and body.title.strip() != row.title:
            row.title = body.title.strip()
            changes.append("its description")
        if body.username is not None and row.kind == "pair" and body.username.strip() != row.username:
            row.username = _username(body.username)
            changes.append("its user name")
            sends_differently = True
        if body.value:
            what = "The password" if row.kind == "pair" else "The value"
            row.secret = vault.encrypt(credentials.clean_value(body.value, what))
            changes.append("its password" if row.kind == "pair" else "its value")
            sends_differently = True
    except credentials.CredentialError as error:
        db.rollback()
        raise HTTPException(status_code=error.status, detail=error.message) from None
    if changes:
        row.updated_at, row.updated_by = now_iso(), caller.actor
        if sends_differently:
            # What was got with the old value is not kept as if the new one had got it: a token that is
            # cached, an answer an instance keeps, the result of its last test.
            connector_actions.forget_tokens()
            for instance_id in {entry["instance"] for entry in used}:
                instance = db.get(Connection, instance_id)
                if instance is not None:
                    instance.last_test = None
                    instance_keys.forget_answers(db, instance.id)
        where = f"; used by {credentials.used_text(used)}" if used else ""
        audit.record(
            db,
            caller.actor,
            "credential.update",
            f'Changed the credential "{row.name}": {", ".join(changes)}{where}',
            target=row.name,
        )
        db.commit()
    return _out(row, credentials.uses(db).get(row.name, []))


@router.delete("/credentials/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_credential(
    credential_id: str, caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """Delete a credential. One an instance names is refused, saying which: the instance would fail."""
    row = _row(db, credential_id)
    used = credentials.uses(db).get(row.name, [])
    if used:
        raise HTTPException(
            status_code=409,
            detail=f'"{row.name}" is used by {credentials.used_text(used)}: '
            "give those instances another credential, or a typed value, first",
        )
    audit.record(db, caller.actor, "credential.delete", f'Deleted the credential "{row.name}"', target=row.name)
    db.delete(row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
