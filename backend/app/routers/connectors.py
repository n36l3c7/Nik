"""Connectors and connections.

A connector is a YAML file (``automation/connectors.py``); a connection is a
connector plus an address and credentials. Both are managed with
``connectors.manage`` (the role *Connectors*, or an admin). Who builds or
runs playbooks reads the list of connections, names only, to choose one on a
node.

Credentials are write-only: they are stored encrypted and no route returns
them; a connection says only which of its secrets are set. A secret of an
instance may name a stored credential instead of holding a value
(``automation/credentials.py``): the name is given back, never what it stands
for.
"""

from __future__ import annotations

import io
import time
import zipfile
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from .. import fetch as fetching
from ..automation import connector_actions as store
from ..automation import connector_logo, credentials, download_hosts, engine, graph, instance_keys
from ..automation import connectors as files
from ..core import audit, vault
from ..core.db import get_db
from ..core.models import Connection, Connector, Credential, Playbook, PlaybookVersion
from ..core.permissions import AUTOMATION_EDIT, AUTOMATION_OPEN, AUTOMATION_RUN, CONNECTORS_MANAGE
from ..core.security import Principal, manager_principal, now_iso, reader_principal, require

router = APIRouter(prefix="/automation", tags=["automation"])

# Whoever builds or runs playbooks sees which connections there are (never what is in them).
instance_chooser_principal = require(CONNECTORS_MANAGE, AUTOMATION_RUN, AUTOMATION_EDIT)


class SourceIn(BaseModel):
    source: str = Field(min_length=1, max_length=files.MAX_BYTES)


class ConnectionIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    connector: str = Field(min_length=1, max_length=41)
    config: dict[str, Any] = Field(default_factory=dict)
    # Write-only. A secret left out keeps what is stored; an empty one removes it.
    secrets: dict[str, str | None] = Field(default_factory=dict)
    enabled: bool = True


class InstanceIn(BaseModel):
    """An instance made under its connector: the connector is in the address."""

    name: str = Field(min_length=1, max_length=80)
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, str | None] = Field(default_factory=dict)
    enabled: bool = True


class ConnectionPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    enabled: bool | None = None
    config: dict[str, Any] | None = None
    secrets: dict[str, str | None] | None = None
    # More keys than one (6.1). ``keys`` is every key beside the first, in the order they are tried:
    # [{id?, name, secrets?}]; one left out is removed, one with an id keeps the secrets it is not given.
    keys: list[dict[str, Any]] | None = Field(default=None, max_length=20)
    mainName: str | None = Field(default=None, max_length=60)  # what the first key is called
    # How the keys take turns: {mode, perMinute, perDay, whenExhausted, cacheHours}.
    keyPolicy: dict[str, Any] | None = None
    # How it fetches (6.4), for a connector that can: {enabled, intervalSeconds, firstFetch,
    # lookbackMinutes, mirror, mirrorAllow}; a value left out stays as it is.
    fetch: dict[str, Any] | None = None


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #
def _problems(error: files.ConnectorError) -> JSONResponse:
    first = error.problems[0]
    where = f" (line {first.line})" if first.line else ""
    return JSONResponse(
        status_code=422,
        content={
            "detail": f"The file is not a connector: {first.message}{where}",
            "problems": [problem.as_dict() for problem in error.problems],
        },
    )


def _users_of(db: OrmSession, connector_id: str, connection: Connection | None = None) -> list[str]:
    """The playbooks whose current version or draft has a node of this connector (using this connection)."""
    found = []
    for playbook in db.scalars(select(Playbook).order_by(Playbook.name)):
        version = db.get(PlaybookVersion, (playbook.id, playbook.current_version)) if playbook.current_version else None
        shapes = [shape for shape in (version.graph if version else None, playbook.draft) if shape]
        for shape in shapes:
            used = False
            for node in graph.nodes_of(shape).values():
                config = node.get("config") or {}
                if node.get("kind") != "action" or not str(config.get("action") or "").startswith(connector_id + "."):
                    continue
                if connection is None or config.get("connection") in (connection.id, connection.name):
                    used = True
            if used:
                found.append(playbook.name)
                break
    return found


def _connector_out(db: OrmSession, row: Connector, *, source: bool = False) -> dict[str, Any]:
    connector = store.parsed(row)
    instances = db.execute(select(Connection.enabled).where(Connection.connector_id == row.id)).all()
    on = sum(1 for (enabled,) in instances if enabled)
    out: dict[str, Any] = {
        "id": row.id,
        "name": row.name,
        "version": row.version,
        "builtin": bool(row.builtin),
        # ``connections`` is the name 4.x gave to the count of instances.
        "instances": len(instances),
        "instancesOn": on,
        # Its commands are offered in the editor and the War Room when one instance is on.
        "enabled": on > 0,
        "readable": connector is not None,
        # Where its logo is served from, or null: a connector of no product has none.
        "logo": store.logo_path(row),
        "updatedAt": row.updated_at,
        "updatedBy": row.updated_by,
    }
    if connector is not None:
        out.update(files.summary(connector))
        out["secrets"] = store.secret_names(connector)
    if source:
        out["source"] = row.source
        out["readme"] = row.readme or ""
        out["usedBy"] = _users_of(db, row.id)
    return out


def _connection_out(db: OrmSession, row: Connection, *, full: bool) -> dict[str, Any]:
    connector_row = db.get(Connector, row.connector_id)
    connector = store.parsed(connector_row) if connector_row is not None else None
    out: dict[str, Any] = {
        "id": row.id,
        "name": row.name,
        "connector": row.connector_id,
        "connectorName": connector_row.name if connector_row else row.connector_id,
        "enabled": bool(row.enabled),
    }
    if not full:
        return out
    stored = store.secrets_of(row)
    names = store.secret_names(connector) if connector is not None else sorted(stored)
    out.update(
        config=row.config or {},
        # Which secrets are set: never what they are.
        secrets={name: bool(stored.get(name)) for name in names},
        # Which of them name a stored credential, and which one: {field: {name, part, missing}}.
        credentials=credentials.named(db, stored),
        host=store.host_of(connector, row.config or {}) if connector is not None else None,
        lastTest=row.last_test,
        updatedAt=row.updated_at,
        updatedBy=row.updated_by,
    )
    # Its keys (the first is the credentials above) and how they take turns: never what they are.
    held = instance_keys.shown(db, row, names)
    out.update(keys=held["keys"], keyPolicy=held["policy"])
    # Whether it fetches, how, and how it goes; null for a connector that cannot fetch.
    out["fetch"] = fetching.out(db, row) if connector is not None and connector.fetch is not None else None
    return out


def _label(param: files.ConfigParam) -> str:
    return param.label or param.name.replace("_", " ").capitalize()


def _clean_config(connector: files.ConnectorFile, given: dict[str, Any]) -> dict[str, Any]:
    """The plain values of a connection, checked against what the connector asks for."""
    out: dict[str, Any] = {}
    plain = [param for param in connector.configuration if not param.is_auth and param.type != "secret"]
    known = {param.name for param in plain}
    for name in given:
        if name not in known:
            raise HTTPException(status_code=400, detail=f'"{name}" is not something this connector asks for')
    for param in plain:
        value = given.get(param.name)
        if isinstance(value, str):
            value = value.strip()
        if value in (None, ""):
            if param.required and param.default in (None, ""):
                raise HTTPException(status_code=400, detail=f"{_label(param)} is required")
            continue
        if param.type == "url":
            if not isinstance(value, str) or not value.lower().startswith(("https://", "http://")):
                raise HTTPException(status_code=400, detail=f"{_label(param)} is an https:// address")
            value = value.rstrip("/")
        elif param.type == "number":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise HTTPException(status_code=400, detail=f"{_label(param)} is a number")
        elif param.type == "bool":
            if not isinstance(value, bool):
                raise HTTPException(status_code=400, detail=f"{_label(param)} is true or false")
        elif param.type == "hosts":
            # The hosts downloads may come from: names and *. patterns, kept as a list a person reads.
            try:
                value = ", ".join(download_hosts.patterns(value if isinstance(value, str) else ""))
            except ValueError as error:
                raise HTTPException(status_code=400, detail=f"{_label(param)}: {error}") from None
            if not value:
                continue
        elif param.type == "choice":
            if value not in (param.choices or []):
                raise HTTPException(
                    status_code=400, detail=f"{_label(param)} is one of: {', '.join(param.choices or [])}"
                )
        elif not isinstance(value, str) or len(value) > 20_000:
            raise HTTPException(status_code=400, detail=f"{_label(param)} is a text")
        if credentials.mentions(value):
            # A plain value is shown and sent as it is: a credential named there would never be read.
            raise HTTPException(
                status_code=400,
                detail=f"{_label(param)} is not a secret: a credential is named in a field that holds one",
            )
        out[param.name] = value
    if store.host_of(connector, {**{p.name: p.default for p in plain if p.default is not None}, **out}) is None:
        raise HTTPException(status_code=400, detail="The instance has no address to send to")
    return out


def _secret(db: OrmSession, value: str) -> str:
    """A secret as an instance is given it: what was typed, or the name of a stored credential, which
    must exist and be of a kind that has the part asked for."""
    try:
        return credentials.checked(db, value)
    except credentials.CredentialError as error:
        raise HTTPException(status_code=error.status, detail=error.message) from None


def _merge_secrets(
    db: OrmSession, connector: files.ConnectorFile, row: Connection, given: dict[str, str | None]
) -> None:
    known = set(store.secret_names(connector))
    stored = store.secrets_of(row)
    for name, value in given.items():
        if name not in known:
            raise HTTPException(status_code=400, detail=f'"{name}" is not a secret of this connector')
        if value is None:
            continue  # kept
        if len(value) > 20_000:
            raise HTTPException(status_code=400, detail="A secret is too long")
        if value == "":
            stored.pop(name, None)
        else:
            stored[name] = _secret(db, value)
    store.store_secrets(row, stored)


def _set_fetching(db: OrmSession, row: Connection, given: dict[str, Any]) -> list[str]:
    """Whether an instance fetches and how, as its form sends it with the rest. Gives what changed."""
    known = {"enabled", "intervalSeconds", "firstFetch", "lookbackMinutes", "mirror", "mirrorAllow"}
    for name in given:
        if name not in known:
            raise fetching.FetchError(f'"{name}" is not something of how an instance fetches')
    now = time.time()
    said = fetching.set_settings(db, row, given, now)
    enabled = given.get("enabled")
    if isinstance(enabled, bool) and enabled != bool(row.fetch_enabled):
        fetching.enable(db, row, enabled, now)
        said.insert(0, "fetches" if enabled else "does not fetch any more")
    return [f"fetching ({', '.join(said)})"] if said else []


def _connector(db: OrmSession, connector_id: str) -> tuple[Connector, files.ConnectorFile]:
    row = db.get(Connector, connector_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Connector not found")
    connector = store.parsed(row)
    if connector is None:
        raise HTTPException(status_code=409, detail="The stored file of this connector cannot be read: upload it again")
    return row, connector


def _connection(db: OrmSession, connection_id: str) -> Connection:
    row = db.get(Connection, connection_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Instance not found")
    return row


# --------------------------------------------------------------------------- #
# Connectors                                                                  #
# --------------------------------------------------------------------------- #
@router.get("/connectors")
def list_connectors(_caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)) -> dict:
    rows = db.scalars(select(Connector).order_by(func.lower(Connector.name))).all()
    return {"connectors": [_connector_out(db, row) for row in rows]}


@router.post("/connectors/check")
def check_connector(body: SourceIn, _caller: Principal = Depends(manager_principal)) -> dict:
    """What is wrong with a file, without installing it: ``{problems: [{line, message, where}]}``.
    ``warnings`` has the same shape and stops nothing: what the file would better say (a connector
    that fetches and says neither how it mirrors nor why it does not)."""
    try:
        connector = files.load(body.source)
    except files.ConnectorError as error:
        return {"problems": [problem.as_dict() for problem in error.problems], "warnings": [], "connector": None}
    said = [warning.as_dict() for warning in files.warnings(body.source)]
    return {"problems": [], "warnings": said, "connector": files.summary(connector)}


@router.get("/connectors/samples")
def connector_samples(_caller: Principal = Depends(manager_principal)) -> Response:
    """The connectors Nik ships, as the files they are, in a zip: something to start from."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(store.SEED_DIR.glob("*.yml")):
            archive.writestr(path.name, path.read_text(encoding="utf-8"))
        # A connector kept as a package goes as its folder.
        for folder in sorted(path.parent for path in store.SEED_DIR.glob("*/connector.yml")):
            for path in sorted(item for item in folder.iterdir() if item.is_file()):
                archive.writestr(f"{folder.name}/{path.name}", path.read_bytes())
    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="nik-connectors.zip"'},
    )


@router.post("/connectors", status_code=status.HTTP_201_CREATED, response_model=None)
def install_connector(
    body: SourceIn, caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> dict | JSONResponse:
    """Install a connector from its file, or replace the one with the same id. ``422`` with
    every problem and its line when the file is not a connector."""
    try:
        existed = db.get(Connector, files.load(body.source).id) is not None
        row, connector = store.install(db, body.source, caller.actor)
    except files.ConnectorError as error:
        db.rollback()
        return _problems(error)
    word = "Replaced" if existed else "Installed"
    audit.record(
        db,
        caller.actor,
        "connector.install",
        f'{word} the connector "{connector.name}" (version {connector.version}, {len(connector.commands)} commands)',
        target=connector.id,
    )
    db.commit()
    return {**_connector_out(db, row, source=True), "warnings": [w.as_dict() for w in files.warnings(body.source)]}


@router.get("/connectors/{connector_id}")
def get_connector(
    connector_id: str, _caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> dict:
    row = db.get(Connector, connector_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Connector not found")
    return _connector_out(db, row, source=True)


@router.get("/connectors/{connector_id}/logo")
def connector_logo_image(
    connector_id: str, _caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """The logo of a connector, for whoever reads incidents: an image and nothing else."""
    row = db.get(Connector, connector_id)
    if row is None or not row.logo or row.logo_type not in connector_logo.TYPES:
        raise HTTPException(status_code=404, detail="This connector has no logo")
    return Response(
        content=bytes(row.logo),
        media_type=row.logo_type,
        headers={
            # Its address changes with it (``?v=``): it may be kept. An SVG opened on its own runs nothing.
            "Cache-Control": "private, max-age=86400",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": f'inline; filename="{row.id}-logo.{connector_logo.EXTENSIONS[row.logo_type]}"',
        },
    )


@router.put("/connectors/{connector_id}/logo")
async def set_connector_logo(
    connector_id: str,
    request: Request,
    caller: Principal = Depends(manager_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Give a connector its logo: the body is the image, a PNG or an SVG of 256 KB at most. The SVG is
    refused when it holds anything but a drawing."""
    row = db.get(Connector, connector_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Connector not found")
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > connector_logo.MAX_BYTES:
        raise HTTPException(status_code=413, detail=f"A logo is {connector_logo.MAX_BYTES // 1024} KB at most")
    data = b""
    async for chunk in request.stream():
        data += chunk
        if len(data) > connector_logo.MAX_BYTES:
            raise HTTPException(status_code=413, detail=f"A logo is {connector_logo.MAX_BYTES // 1024} KB at most")
    try:
        row.logo, row.logo_type = connector_logo.clean(data)
    except connector_logo.LogoError as error:
        raise HTTPException(status_code=400, detail=error.message) from None
    row.updated_at, row.updated_by = now_iso(), caller.actor
    audit.record(db, caller.actor, "connector.logo", f'Set the logo of the connector "{row.name}"', target=row.id)
    db.commit()
    return _connector_out(db, row)


@router.delete("/connectors/{connector_id}/logo", status_code=status.HTTP_204_NO_CONTENT)
def remove_connector_logo(
    connector_id: str, caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> Response:
    row = db.get(Connector, connector_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Connector not found")
    if row.logo:
        row.logo, row.logo_type = None, ""
        row.updated_at, row.updated_by = now_iso(), caller.actor
        audit.record(
            db, caller.actor, "connector.logo", f'Removed the logo of the connector "{row.name}"', target=row.id
        )
        db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/connectors/{connector_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_connector(
    connector_id: str, caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """Remove a connector with its connections. One a playbook uses is refused."""
    row = db.get(Connector, connector_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Connector not found")
    users = _users_of(db, row.id)
    if users:
        raise HTTPException(status_code=409, detail="Used by: " + ", ".join(users[:10]))
    audit.record(db, caller.actor, "connector.delete", f'Removed the connector "{row.name}"', target=row.id)
    for connection in db.scalars(select(Connection).where(Connection.connector_id == row.id)):
        db.delete(connection)
    db.delete(row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- #
# Connections                                                                 #
# --------------------------------------------------------------------------- #
@router.get("/instances")
def list_connections(caller: Principal = Depends(instance_chooser_principal), db: OrmSession = Depends(get_db)) -> dict:
    """The connections. With ``connectors.manage``: their address, which secrets are set, the last
    test. Otherwise their names only, to choose one on a node."""
    full = caller.has(CONNECTORS_MANAGE)
    rows = db.scalars(select(Connection).order_by(func.lower(Connection.name))).all()
    return {"instances": [_connection_out(db, row, full=full) for row in rows]}


@router.post("/instances", status_code=status.HTTP_201_CREATED)
def create_connection(
    body: ConnectionIn, caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> dict:
    _row, connector = _connector(db, body.connector)
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="A name is required")
    if db.scalars(select(Connection).where(func.lower(Connection.name) == name.lower())).first() is not None:
        raise HTTPException(status_code=400, detail="An instance with this name exists already")
    now = now_iso()
    row = Connection(
        id=engine.new_id(),
        name=name,
        connector_id=connector.id,
        config=_clean_config(connector, body.config),
        enabled=body.enabled,
        created_at=now,
        created_by=caller.actor,
        updated_at=now,
        updated_by=caller.actor,
    )
    _merge_secrets(db, connector, row, body.secrets)
    db.add(row)
    host = store.host_of(connector, row.config)
    entry = connector.download_hosts_from
    listed = str(row.config.get(entry) or "") if entry else ""
    audit.record(
        db,
        caller.actor,
        "connection.create",
        f'Made the instance "{name}" to {connector.name} at {host}'
        + (f"; hosts downloads may come from: {listed}" if listed else ""),
        target=name,
    )
    db.commit()
    return _connection_out(db, row, full=True)


@router.put("/instances/{connection_id}")
def update_connection(
    connection_id: str,
    body: ConnectionPatch,
    caller: Principal = Depends(manager_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Change a connection. A secret that is left out stays as it is; an empty one is removed."""
    row = _connection(db, connection_id)
    _connector_row, connector = _connector(db, row.connector_id)
    changes = []
    if body.name is not None and body.name.strip() != row.name:
        name = body.name.strip()
        taken = db.scalars(select(Connection).where(func.lower(Connection.name) == name.lower())).first()
        if not name or (taken is not None and taken.id != row.id):
            raise HTTPException(status_code=400, detail="An instance with this name exists already")
        changes.append(f'renamed from "{row.name}"')
        # Nodes name a connection by its id or by its name: one named by its old name must be chosen again.
        row.name = name
    if body.enabled is not None and body.enabled != bool(row.enabled):
        row.enabled = body.enabled
        changes.append("turned on" if body.enabled else "turned off")
    if body.config is not None:
        before = store.host_of(connector, row.config or {})
        entry = connector.download_hosts_from
        from_before = str((row.config or {}).get(entry) or "") if entry else ""
        row.config = _clean_config(connector, body.config)
        after = store.host_of(connector, row.config)
        changes.append(f"address {before} → {after}" if before != after else "settings")
        from_after = str(row.config.get(entry) or "") if entry else ""
        if from_after != from_before:
            # Where its downloads may come from is said in full: it is what the instance lets in.
            changes.append(f"hosts downloads may come from: {from_before or 'none'} → {from_after or 'none'}")
        row.last_test = None
    if body.secrets is not None and any(value is not None for value in body.secrets.values()):
        _merge_secrets(db, connector, row, body.secrets)
        changes.append("credentials")
        row.last_test = None
    try:
        if body.mainName is not None and body.mainName.strip():
            row.key_policy = {**(row.key_policy or {}), "mainName": body.mainName.strip()[:60]}
        if body.keys is not None:
            auth = connector.auth
            required = list(store.AUTH_FIELDS.get(auth.type, ())) if auth is not None else []
            before = len(instance_keys.extra_keys(row))
            given = [
                {**entry, "secrets": {field: _secret(db, value) for field, value in entry["secrets"].items()}}
                if isinstance(entry, dict) and isinstance(entry.get("secrets"), dict)
                else entry
                for entry in body.keys
            ]
            instance_keys.set_extra_keys(row, given, store.secret_names(connector), required)
            after = instance_keys.extra_keys(row)
            instance_keys.forget(db, row.id, keep={instance_keys.MAIN, *(entry["id"] for entry in after)})
            for entry in after:
                store.forget_tokens(f"{row.id}:{entry['id']}")
            if len(after) != before or any(item.get("secrets") for item in body.keys):
                changes.append(f"keys ({len(after) + 1})")
        if body.keyPolicy is not None:
            cleaned = instance_keys.clean_policy(body.keyPolicy)
            now = instance_keys.policy_of(row)
            if any(now[name] != cleaned[name] for name in cleaned):
                main_name = (row.key_policy or {}).get("mainName")
                row.key_policy = {**cleaned, **({"mainName": main_name} if main_name else {})}
                changes.append("how its keys take turns")
                if not cleaned["cacheHours"]:
                    instance_keys.forget_answers(db, row.id)
    except instance_keys.KeyError_ as error:
        db.rollback()
        raise HTTPException(status_code=400, detail=error.message) from None
    if body.fetch is not None:
        from .. import mirror as mirroring

        # A direction that sends: every incident the instance fetches from then on writes to the other
        # system, so choosing it asks what starting such a mirror on an incident asks. One that says it
        # already is saved again by who manages connectors.
        wanted = body.fetch.get("mirror")
        if wanted in ("out", "both") and wanted != mirroring.choice_of(row)[0] and not caller.has(AUTOMATION_RUN):
            raise HTTPException(
                status_code=403, detail="Sending to another system needs the permission to run playbooks"
            )
        # The classes of data the mirrors of its incidents may send: opening one is not a matter of
        # connectors alone, here as on an incident.
        asked = body.fetch.get("mirrorAllow")
        named = [name for name in asked if isinstance(name, str)] if isinstance(asked, list) else []
        opened = set(named) - set(mirroring.choice_of(row)[1])
        if opened and not caller.has(AUTOMATION_OPEN):
            raise HTTPException(status_code=403, detail="Opening a class of data needs the permission that opens them")
        try:
            changes += _set_fetching(db, row, body.fetch)
        except fetching.FetchError as error:
            db.rollback()
            raise HTTPException(status_code=error.status, detail=error.message) from None
    if changes:
        row.updated_at = now_iso()
        row.updated_by = caller.actor
        audit.record(
            db,
            caller.actor,
            "connection.update",
            f'Changed the instance "{row.name}": {", ".join(changes)}',
            target=row.name,
        )
        db.commit()
    return _connection_out(db, row, full=True)


@router.delete("/instances/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_connection(
    connection_id: str, caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> Response:
    row = _connection(db, connection_id)
    users = _users_of(db, row.connector_id, row)
    if users:
        raise HTTPException(status_code=409, detail="Used by: " + ", ".join(users[:10]))
    audit.record(db, caller.actor, "connection.delete", f'Deleted the instance "{row.name}"', target=row.name)
    store.forget_tokens(row.id)
    db.delete(row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- #
# Instances: the connections of one connector, under it                       #
# --------------------------------------------------------------------------- #
@router.get("/connectors/{connector_id}/instances")
def list_instances(
    connector_id: str, _caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """The instances of a connector, by name: where each sends, whether it is on, its last test."""
    _connector(db, connector_id)
    rows = db.scalars(
        select(Connection).where(Connection.connector_id == connector_id).order_by(func.lower(Connection.name))
    ).all()
    return {"instances": [_connection_out(db, row, full=True) for row in rows]}


@router.post("/connectors/{connector_id}/instances", status_code=status.HTTP_201_CREATED)
def create_instance(
    connector_id: str,
    body: InstanceIn,
    caller: Principal = Depends(manager_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Add an instance to a connector. It is the connection ``POST /connections`` makes; an instance is
    changed, tested and deleted through ``/connections/{id}``."""
    return create_connection(
        ConnectionIn(
            name=body.name, connector=connector_id, config=body.config, secrets=body.secrets, enabled=body.enabled
        ),
        caller,
        db,
    )


@router.post("/instances/{connection_id}/test")
def test_connection(
    connection_id: str, caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Send the connector's test request with these credentials: ``{ok, status, message, at}``.
    It reaches the host of the connection and nothing else."""
    row = _connection(db, connection_id)
    _connector_row, connector = _connector(db, row.connector_id)
    try:
        result = store.runtime_for(db, connector, row).test()
    except store.CommandError as error:
        result = {"ok": False, "status": 0, "message": error.message}
    result["at"] = now_iso()
    row.last_test = result
    db.commit()
    return result


@router.post("/instances/{connection_id}/keys/test")
def test_keys(
    connection_id: str, _caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Send the connector's test request with each key of the instance: ``{keys: [{id, name, ok, status,
    message}]}``. Nothing is counted against a key for it."""
    row = _connection(db, connection_id)
    _connector_row, connector = _connector(db, row.connector_id)
    found = []
    for key in instance_keys.keys_of(row):
        try:
            result = store.runtime_for(db, connector, row, key=key).test()
        except store.CommandError as error:
            result = {"ok": False, "status": 0, "message": error.message}
        found.append({"id": key.id, "name": key.name, **result})
    return {"keys": found}


class KeepIn(BaseModel):
    """A secret that was typed into an instance, to be kept as a stored credential under ``name``."""

    key: str = Field(default=instance_keys.MAIN, max_length=16)  # which key of the instance holds it
    field: str = Field(min_length=1, max_length=40)
    name: str = Field(min_length=1, max_length=40)
    title: str = Field(default="", max_length=200)


@router.post("/instances/{connection_id}/credentials", status_code=status.HTTP_201_CREATED)
def keep_as_credential(
    connection_id: str,
    body: KeepIn,
    caller: Principal = Depends(manager_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Turn a secret typed into the instance into a stored credential: the value moves there, and the
    instance names the credential where it held the value. Nobody types it again, and it is not shown.

    A user name and a password that the instance holds together become one credential of the kind
    ``pair``; anything else becomes a ``secret``. Returns the instance, as it is now."""
    row = _connection(db, connection_id)
    _connector_row, connector = _connector(db, row.connector_id)
    names = store.secret_names(connector)
    key = next((held for held in instance_keys.keys_of(row) if held.id == body.key), None)
    if key is None:
        raise HTTPException(status_code=404, detail="This key is not of this instance any more")
    if body.field not in names:
        raise HTTPException(status_code=400, detail=f'"{body.field}" is not a secret of this connector')
    held = dict(key.secrets)

    def typed(field: str) -> bool:
        return bool(held.get(field)) and credentials.reference(held[field]) is None

    if credentials.reference(held.get(body.field)) is not None:
        raise HTTPException(status_code=400, detail="This is a stored credential already")
    if not typed(body.field):
        raise HTTPException(status_code=400, detail="There is no value stored there to keep")
    pair = credentials.pair_fields(names)
    together = pair is not None and body.field in pair and typed(pair[0]) and typed(pair[1])
    now = now_iso()
    try:
        name = credentials.clean_name(db, body.name)
        made = Credential(
            id=engine.new_id(),
            name=name,
            title=body.title.strip(),
            kind="pair" if together else "secret",
            username=held[pair[0]][:500] if together else "",
            secret=vault.encrypt(credentials.clean_value(held[pair[1]] if together else held[body.field])),
            created_at=now,
            created_by=caller.actor,
            updated_at=now,
            updated_by=caller.actor,
        )
        db.add(made)
        db.flush()
        if together:
            held[pair[0]] = credentials.Reference(name, "username").text
            held[pair[1]] = credentials.Reference(name, "password").text
        else:
            held[body.field] = credentials.Reference(name).text
        instance_keys.set_key_secrets(row, key.id, held)
    except (credentials.CredentialError, instance_keys.KeyError_) as error:
        db.rollback()
        raise HTTPException(status_code=400, detail=error.message) from None
    row.updated_at, row.updated_by = now, caller.actor
    which = "" if key.id == instance_keys.MAIN else f', key "{key.name}"'
    audit.record(
        db,
        caller.actor,
        "credential.create",
        f'Kept what the instance "{row.name}"{which} held as the credential "{name}" ({credentials.what(made)}): '
        "the instance names it now",
        target=name,
    )
    db.commit()
    return _connection_out(db, row, full=True)


@router.delete("/instances/{connection_id}/answers")
def forget_kept_answers(
    connection_id: str, caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Forget the answers the instance keeps: the next command asks again. ``{forgotten}``."""
    row = _connection(db, connection_id)
    forgotten = instance_keys.forget_answers(db, row.id)
    audit.record(
        db, caller.actor, "connection.update", f'Forgot the answers kept for the instance "{row.name}"', target=row.name
    )
    db.commit()
    return {"forgotten": forgotten}
