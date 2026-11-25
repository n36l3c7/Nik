"""The Sigma routes of the forensics worker, as a test double.

``FakeSigma`` takes the place of ``app.sigma.worker.ask``: it reads a rule with PyYAML the way the real worker
says what it read (it judges nothing of Sigma beyond what these tests need), keeps the sets of rules it is
given by digest, and runs the one kind of rule the tests write: ``selection`` fields equal to the values of a
record. It records every call, so a test can say how many times the worker was asked.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

import yaml

from app.core.config import settings
from app.sigma import worker


def rule_text(
    rule_id: str | None = None,
    *,
    title: str = "Log cleared",
    level: str = "high",
    event: int | str = 1102,
    product: str = "windows",
    service: str = "security",
    category: str = "",
    status: str = "stable",
    tags: list[str] | None = None,
    author: str = "Tester",
    name: str = "",
    more: dict[str, Any] | None = None,
) -> str:
    """The text of a rule that matches records whose ``EventID`` is ``event``."""
    doc: dict[str, Any] = {
        "title": title,
        "id": rule_id or str(uuid.uuid4()),
        "status": status,
        "author": author,
        "tags": tags if tags is not None else ["attack.defense-evasion", "attack.t1070.001"],
        "logsource": {
            key: value for key, value in (("product", product), ("category", category), ("service", service)) if value
        },
        "detection": {"selection": {"EventID": event}, "condition": "selection"},
        "level": level,
    }
    if name:
        doc["name"] = name
    doc.update(more or {})
    return yaml.safe_dump(doc, sort_keys=False)


class FakeSigma:
    def __init__(self, monkeypatch, engine: str = "1"):
        self.engine = engine
        self.calls: list[tuple[str, Any]] = []
        self.sets: dict[str, bytes] = {}
        self.refuse_sets = False
        monkeypatch.setattr(settings, "FORENSICS_URL", "http://forensics.test")
        monkeypatch.setattr(worker, "ask", self.ask)
        worker.forget()

    def of(self, route: str) -> list[Any]:
        return [body for called, body in self.calls if called == route]

    def ask(self, route, body=None, *, method="POST", raw=None, timeout=120):
        self.calls.append((route, raw if raw is not None else body))
        if route == "/health":
            return 200, {"status": "ok", "sigma": self.engine}
        if route == "/sigma/check":
            return 200, {"engine": self.engine, "documents": [self.read(item["source"]) for item in body["documents"]]}
        if route == "/sigma/try":
            return 200, self.run(body)
        if route.startswith("/rules/") and method == "PUT":
            if self.refuse_sets:
                return 507, {"detail": "The worker has no room for rules"}
            digest = route.split("/")[-1]
            if hashlib.sha256(raw).hexdigest() != digest:
                return 400, {"detail": "The digest is not the one of the body"}
            self.sets[digest] = raw
            return 200, {"rules": raw.count(b"\n")}
        return 404, {"detail": "no such route"}

    # ---- /sigma/check
    def read(self, text: str) -> dict[str, Any]:
        try:
            docs = [doc for doc in yaml.safe_load_all(text) if doc is not None]
        except yaml.YAMLError as error:
            mark = getattr(error, "problem_mark", None)
            line = mark.line + 1 if mark is not None else 1
            return {"rules": [], "errors": [{"line": line, "column": 1, "message": str(error.problem or error)}]}
        rules, errors = [], []
        for number, doc in enumerate(docs):
            if not isinstance(doc, dict) or not doc.get("title"):
                errors.append({"line": 1, "column": 1, "message": "This is not a Sigma rule: it needs a title"})
            elif not doc.get("id"):
                errors.append({"line": 1, "column": 1, "message": "a rule needs an id (a UUID)"})
            elif "detection" not in doc and "correlation" not in doc:
                errors.append({"line": 2, "column": 1, "message": "a rule needs a detection"})
            else:
                rules.append(self.info(doc, text if len(docs) == 1 else yaml.safe_dump(doc, sort_keys=False), number))
        if errors:
            return {"rules": [], "errors": errors}
        return {"rules": rules, "errors": []}

    def info(self, doc: dict[str, Any], source: str, number: int) -> dict[str, Any]:
        where = doc.get("logsource") if isinstance(doc.get("logsource"), dict) else {}
        product = str(where.get("product") or "")
        reason = ""
        category = str(where.get("category") or "")
        # What the real worker answers (sigma/logsource.py): the Linux syslog records are read, but only the process
        # creation of the categories; the macOS ones only with no category and no service.
        if (product == "linux" and category not in ("", "process_creation")) or (
            product == "macos" and (category or where.get("service"))
        ):
            reason = f"Nik reads no records of this log source: {product}/{category or where.get('service')}"
        elif "unsupported" in yaml.safe_dump(doc.get("detection") or {}):
            reason = "The modifier |unsupported is not run by Nik"
        return {
            "id": str(doc["id"]),
            "name": str(doc.get("name") or ""),
            "title": str(doc["title"]),
            "author": str(doc.get("author") or ""),
            "level": str(doc.get("level") or "medium"),
            "status": str(doc.get("status") or ""),
            "kind": "correlation" if "correlation" in doc else "rule",
            "product": product,
            "category": str(where.get("category") or ""),
            "service": str(where.get("service") or ""),
            "tags": list(doc.get("tags") or []),
            "supported": not reason,
            "reason": reason,
            "source": source,
            "line": 1 + number,
        }

    # ---- /sigma/try
    def run(self, body: dict[str, Any]) -> dict[str, Any]:
        matches, left = [], []
        for line in body["rules"]:
            if line["kind"] == "correlation":
                left.append({"rule": line["id"], "reason": "a correlation is not run by this double"})
        for line in body["rules"]:
            if line["kind"] == "correlation":
                continue
            detection = yaml.safe_load(line["source"])["detection"]
            if (line["product"], line["service"]) == ("nik", "process-chain"):
                # The log source of the chains: the records of kind process-chain, the conditions of the shipped
                # rules (names joined by and/or, parentheses), the modifiers they use.
                for record in body["records"]:
                    if record["kind"] == "process-chain" and chain_matches(detection, record["data"]):
                        matches.append({"rule": line["id"], "key": record["key"]})
                continue
            wanted = detection["selection"]
            for record in body["records"]:
                held = {"EventID": record["event_id"], "Channel": record["channel"], **record["data"]}
                if all(held.get(field) == value for field, value in wanted.items()):
                    matches.append({"rule": line["id"], "key": record["key"]})
        return {"matches": matches, "notEvaluated": left}


def _field_matches(held: Any, modifier: str, wanted: Any) -> bool:
    """One field of a selection against a record (a list of wanted values: any of them; a list held: any element)."""
    values = held if isinstance(held, list) else [held]
    for wanted_one in wanted if isinstance(wanted, list) else [wanted]:
        for value in values:
            have, want = str(value).lower(), str(wanted_one).lower()
            if modifier == "endswith" and have.endswith(want):
                return True
            if modifier == "startswith" and have.startswith(want):
                return True
            if modifier == "contains" and want in have:
                return True
            if modifier == "" and have == want:
                return True
    return False


def chain_matches(detection: dict[str, Any], data: dict[str, Any]) -> bool:
    """What the real worker does with a rule of the log source ``nik/process-chain``, as far as these tests need:
    the fields are the ones of the design (``Image``, ``ParentImage``, ``Ancestors``…), each selection is an AND of
    its fields, and the condition joins selections with ``and``, ``or``, ``not`` and parentheses."""
    done: dict[str, bool] = {}
    for name, selection in detection.items():
        if name == "condition":
            continue
        ok = True
        for field, wanted in selection.items():
            key, _, modifier = field.partition("|")
            ok = ok and _field_matches(data.get(key), modifier, wanted)
        done[name] = ok
    expression = detection["condition"]
    for name in sorted(done, key=len, reverse=True):
        expression = expression.replace(name, str(done[name]))
    return bool(eval(expression, {"__builtins__": {}}, {}))  # noqa: S307 - the text is a rule of a test
