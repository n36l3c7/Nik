"""The nodes that send something out: an HTTP request, an e-mail.

Both go the same way: the data guard decides on what is about to leave
(guard.py), then the egress client sends it under the playbook's policy
(egress.py). In a dry run nothing is sent: the step shows the request it
would have made, and whether the guard or the egress rules would have let it.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session as OrmSession

from ..core import vault
from . import egress, guard, state
from .actions import ActionError, Call, Result, action

TEXT_SHOWN = 100_000
MAX_RECIPIENTS = 50


def policy_for(db: OrmSession, playbook: Any, extra_hosts: tuple[str, ...] = ()) -> egress.Policy:
    """Where a playbook may send: its own hosts, the hosts an admin listed for all, and its connections'."""
    hosts = {*(playbook.egress_hosts or []), *(state.read(db).get("hosts") or []), *extra_hosts}
    return egress.Policy(mode=playbook.egress_mode or "listed", hosts=frozenset(h.lower() for h in hosts if h))


def guarded(call: Call, payload: dict[str, Any], argument_names: dict[str, str] | None = None) -> tuple[dict, dict]:
    """Pass a payload through the data guard. Returns ``(payload, what was decided)``:
    the payload as it may leave (with ``held: drop`` on the node, without what was held).
    Raises ``ActionError`` when something is held and the node does not drop it."""
    context = guard.context_from(call.db)
    opened = frozenset(call.playbook.data_allow or [])
    decision = guard.check(payload, call.classes, opened, context)
    if decision.allowed:
        return payload, decision.as_dict()
    if call.held == "drop":
        # What came tagged from a held class is taken out whole; what the scan finds, value by value.
        allowed = guard.ALWAYS | opened
        cleaned = dict(payload)
        for name, held in (call.arg_classes or {}).items():
            key = (argument_names or {}).get(name.split(".")[0], name.split(".")[0])
            if key in cleaned and set(held) - allowed:
                cleaned[key] = None
        cleaned = guard.drop(cleaned, context, opened) or {}
        again = guard.check(cleaned, frozenset(), opened, context)
        if again.allowed:
            return cleaned, {**decision.as_dict(), "dropped": True}
    raise ActionError(decision.sentence(), retry=False, request={"held": decision.as_dict()})


def _fail(error: egress.EgressError) -> ActionError:
    return ActionError(error.message, retry=not error.refused, unknown_outcome=error.sent, request=error.record)


# --------------------------------------------------------------------------- #
# HTTP                                                                        #
# --------------------------------------------------------------------------- #
@action(
    "http.request",
    group="HTTP",
    name="HTTP request",
    description="Send a request to an address the playbook may reach, and read the answer.",
    arguments=[
        {
            "name": "method",
            "type": "choice",
            "choices": ["GET", "POST", "PUT", "PATCH", "DELETE"],
            "default": "GET",
            "description": "GET reads; the others change something on the other side and ask for approval by default",
        },
        {"name": "url", "type": "text", "required": True, "description": "The address, https://…"},
        {"name": "headers", "type": "object", "description": "Headers to send"},
        {"name": "query", "type": "object", "description": "Query parameters"},
        {"name": "json", "type": "any", "description": "A JSON body"},
        {"name": "body", "type": "text", "description": "A body as text, when it is not JSON"},
        {
            "name": "timeout",
            "type": "number",
            "default": 60,
            "description": "Seconds to wait for the answer (300 at most)",
        },
        {
            "name": "fail_on_error",
            "type": "bool",
            "default": True,
            "description": "Treat an answer of 400 or more as a failure",
        },
    ],
    outputs=[
        {"name": "status", "type": "number", "description": "The HTTP status"},
        {"name": "ok", "type": "bool", "description": "The status is below 400"},
        {"name": "json", "type": "any", "description": "The answer as JSON, when it is"},
        {"name": "text", "type": "text", "description": "The answer as text"},
    ],
    outside=lambda args: str(args.get("method") or "GET").upper() not in ("GET", "HEAD"),
    idempotent=False,
    timeout=300,
)
def http_request(call: Call) -> Result:
    args = call.args
    method = str(args.get("method") or "GET").upper()
    url = str(args.get("url") or "").strip()
    payload = {
        "url": url,
        "headers": args.get("headers") if isinstance(args.get("headers"), dict) else {},
        "query": args.get("query") if isinstance(args.get("query"), dict) else {},
        "json": args.get("json"),
        "body": args.get("body"),
    }
    payload, decided = guarded(call, payload)
    if not payload.get("url"):
        raise ActionError("The address was held back with the data it carried", retry=False, request={"held": decided})
    policy = policy_for(call.db, call.playbook)
    try:
        if call.dry_run:
            _scheme, host, _port, path, _address = egress.destination(policy, payload["url"])
            would = {"method": method, "host": host, "path": path.split("?")[0][:300], "held": decided, "dry_run": True}
            return Result(output={"status": 0, "ok": True, "json": None, "text": ""}, request=would)
        answer = egress.request(
            policy,
            method,
            payload["url"],
            headers=payload.get("headers") or {},
            query=payload.get("query") or None,
            json=payload.get("json"),
            body=payload.get("body"),
            timeout=float(args.get("timeout") or 60),
        )
    except egress.EgressError as error:
        raise _fail(error) from None
    record = {**answer.record, "held": decided}
    if answer.status >= 400 and args.get("fail_on_error", True):
        raise ActionError(f"The other side answered {answer.status}", retry=answer.status >= 500, request=record)
    output = {
        "status": answer.status,
        "ok": answer.status < 400,
        "json": answer.json(),
        "text": answer.text[:TEXT_SHOWN],
        "content_type": answer.headers.get("content-type", ""),
    }
    # What comes back may repeat what was sent: it keeps the classes of what went out.
    return Result(output=output, classes={"": sorted(call.classes)} if call.classes else {}, request=record)


# --------------------------------------------------------------------------- #
# E-mail                                                                      #
# --------------------------------------------------------------------------- #
def smtp_settings(db: OrmSession) -> dict[str, Any]:
    """The SMTP server an admin configured, with its password decrypted ({} when there is none)."""
    stored = dict(state.read(db).get("smtp") or {})
    if stored.get("password"):
        stored["password"] = vault.decrypt(stored["password"]) or ""
    return stored


def _recipients(value: Any) -> list[str]:
    items = value if isinstance(value, (list, tuple)) else str(value or "").replace(";", ",").split(",")
    found = [str(item).strip() for item in items if str(item).strip()]
    return list(dict.fromkeys(found))


def _mail_instance(call: Call):
    """The instance of the Mail connector a node of 4.x sends through: the one it names, or the only
    one that is on. None when there is none (the SMTP server of the settings is then used)."""
    from . import connector_actions

    found = connector_actions.find_connection(call.db, "mail", call.connection)
    return found if found is not None and found.enabled else None


def _send_through(call: Call, instance, to: list[str], subject: str, text: str, decided: dict) -> Result:
    from ..core.models import Connector
    from . import connector_actions
    from .connector_runtime import CommandError

    row = call.db.get(Connector, "mail")
    connector = connector_actions.parsed(row) if row is not None else None
    if connector is None:
        raise ActionError("The Mail connector is not installed", retry=False)
    runtime = connector_actions.runtime_for(call.db, connector, instance, call.playbook, call.now)
    args = {"to": to, "subject": subject, "text": text}
    try:
        if call.dry_run:
            would = {**runtime.would_send("send", args), "held": decided, "connection": instance.name}
            return Result(output={"sent": False, "recipients": len(to)}, request=would)
        answer = runtime.run("send", args)
    except CommandError as error:
        raise ActionError(
            error.message,
            retry=error.retry,
            unknown_outcome=error.sent and error.retry,
            request={**(error.record or {}), "held": decided, "connection": instance.name},
        ) from None
    record = {**(answer.records[-1] if answer.records else {}), "held": decided, "connection": instance.name}
    return Result(output={"sent": True, "recipients": len(to)}, request=record)


@action(
    "email.send",
    group="E-mail",
    name="Send an e-mail",
    description=(
        "Send a message through an instance of the Mail connector, to recipients the playbook may write to. "
        "Kept for the playbooks made before 5.1: new ones use the send command of the Mail connector."
    ),
    arguments=[
        {
            "name": "to",
            "type": "list",
            "required": True,
            "description": "Recipients: a list, or addresses separated by commas",
        },
        {"name": "subject", "type": "text", "required": True, "description": "The subject"},
        {"name": "text", "type": "text", "required": True, "description": "The message, as plain text"},
    ],
    outputs=[
        {"name": "sent", "type": "bool", "description": "The server took the message"},
        {"name": "recipients", "type": "number", "description": "How many recipients"},
    ],
    idempotent=False,
)
def email_send(call: Call) -> Result:
    to = _recipients(call.args.get("to"))
    if not to or len(to) > MAX_RECIPIENTS:
        raise ActionError(f"1 to {MAX_RECIPIENTS} recipients are needed", retry=False)
    policy = policy_for(call.db, call.playbook)
    for address in to:
        name, _, domain = address.rpartition("@")
        domain = egress.clean_host(domain) or ""
        if not name or not domain or any(char in address for char in " \r\n<>,"):
            raise ActionError("A recipient is not an e-mail address", retry=False)
        # A recipient is a destination: its domain is among the hosts the playbook may reach.
        if policy.mode != "any" and domain not in policy.hosts:
            raise ActionError(
                f"{domain} is not among the hosts this playbook may reach: list it to write to its addresses",
                retry=False,
            )
    # The recipients are where it goes; what is judged is what is said.
    payload, decided = guarded(call, {"subject": call.args.get("subject"), "text": call.args.get("text")}, {"to": "_"})
    subject, text = str(payload.get("subject") or "(no subject)"), str(payload.get("text") or "")
    # Since 5.1 mail is a connector: an instance of it that is on sends. The SMTP server of the
    # settings of 4.x is used while there is none (it is made an instance when the server starts).
    instance = _mail_instance(call)
    if instance is not None:
        return _send_through(call, instance, to, subject, text, decided)
    server = smtp_settings(call.db)
    if not server.get("host") and not call.dry_run:
        raise ActionError(
            "No instance of the Mail connector is on: add one in Settings, Connectors, to send e-mail",
            retry=False,
        )
    if call.dry_run:
        would = {"method": "SMTP", "host": server.get("host") or "(not configured)", "path": f"{len(to)} recipient(s)"}
        return Result(
            output={"sent": False, "recipients": len(to)}, request={**would, "held": decided, "dry_run": True}
        )
    try:
        record = egress.send_mail(server, to=to, subject=subject, text=text)
    except egress.EgressError as error:
        raise _fail(error) from None
    return Result(output={"sent": True, "recipients": len(to)}, request={**record, "held": decided})
