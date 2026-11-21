"""What restart-chaos.sh runs inside its own container: the other system, and who drives Nik.

    python restart_chaos.py stub             the other system: an HTTP server that counts what it is asked
    python restart_chaos.py setup            the first account, a key, a connector, playbooks, a fetch
    python restart_chaos.py start <round>    start one of every kind of work
    python restart_chaos.py settle           wait until nothing moves any more, answering what waits
    python restart_chaos.py verify           every assertion of the test; exit 1 with what is wrong
    python restart_chaos.py archive          the names of the archive of the log, on the standard input: no gap

Standard library only. Nothing here is a sample: the "malware" is a PE of a few hundred bytes
that does nothing, the capture is the fixture of the pcap worker's tests, the mailbox two lines.

**The other system** (``stub``) stands for what a playbook reaches outside: an EDR, a ticketing
tool. It has one address per class of command and counts each call by the key it is given (the
run that calls):

    GET  /read/<key>      a command that only reads
    POST /isolate/<key>   one that changes something and may be repeated (it sets a state)
    POST /ticket/<key>    one that changes something and may not (it makes a new thing each time)
    POST /keyed/<key>     one that sends an ``Idempotency-Key``: the system acts once per key
    GET  /alerts          the alerts a fetch brings in, the same list at every cycle
    GET  /counts          everything it counted
    POST /hold            {"seconds": n}: how long it keeps each call before it answers

It answers a call only after ``hold`` seconds, and has counted it before: a worker killed while
it waits has made its call for certain, and Nik holds only the mark that it began.
"""

from __future__ import annotations

import json
import os
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API = os.environ.get("CHAOS_API", "http://api:8000")
STUB = os.environ.get("CHAOS_STUB", "http://chaos:8099")
STATE = os.environ.get("CHAOS_STATE", "/tmp/chaos-state.json")
COUNTS = os.environ.get("CHAOS_COUNTS", "/tmp/chaos-counts.json")
PASSWORD = "restart-chaos-password"
ALERTS = 6
SETTLE_SECONDS = int(os.environ.get("CHAOS_SETTLE_SECONDS", "420"))


# --------------------------------------------------------------------------- #
# The other system                                                            #
# --------------------------------------------------------------------------- #
class Stub(BaseHTTPRequestHandler):
    lock = threading.Lock()
    counts: dict = {"read": {}, "isolate": {}, "ticket": {}, "keyed": {}, "keys": {}, "alerts": 0}
    hold = 0.0

    def _send(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _count(self) -> None:
        kind, _, key = self.path.strip("/").partition("/")
        key = key.split("?")[0]
        with Stub.lock:
            if kind == "alerts":
                Stub.counts["alerts"] += 1
            elif kind in ("read", "isolate", "ticket", "keyed"):
                Stub.counts[kind][key] = Stub.counts[kind].get(key, 0) + 1
                if kind == "keyed":
                    sent = self.headers.get("Idempotency-Key", "")
                    Stub.counts["keys"].setdefault(key, [])
                    if sent not in Stub.counts["keys"][key]:
                        Stub.counts["keys"][key].append(sent)
            with open(COUNTS, "w", encoding="utf-8") as out:
                json.dump(Stub.counts, out)

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        if self.path == "/health":
            return self._send({"status": "ok"})
        if self.path == "/counts":
            with Stub.lock:
                return self._send(Stub.counts)
        self._count()
        if self.path.startswith("/alerts"):
            day = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600))
            items = [{"id": f"alert-{n}", "title": f"Chaos alert {n}", "created": day} for n in range(ALERTS)]
            return self._send({"data": items})
        time.sleep(Stub.hold)
        self._send({"ok": True, "at": time.time()})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        if self.path == "/hold":
            Stub.hold = float(json.loads(body or b"{}").get("seconds") or 0)
            return self._send({"hold": Stub.hold})
        self._count()
        time.sleep(Stub.hold)
        self._send({"ok": True, "id": f"made-{time.time()}"})

    def log_message(self, fmt: str, *args) -> None:
        return


def stub() -> None:
    if os.path.exists(COUNTS):
        with open(COUNTS, encoding="utf-8") as held:
            Stub.counts = json.load(held)
    ThreadingHTTPServer(("0.0.0.0", 8099), Stub).serve_forever()  # noqa: S104 - a network of the test only


# --------------------------------------------------------------------------- #
# Talking to Nik                                                              #
# --------------------------------------------------------------------------- #
def state() -> dict:
    if not os.path.exists(STATE):
        return {"runs": [], "samples": [], "captures": [], "mailboxes": [], "scans": [], "jobs": [], "incidents": []}
    with open(STATE, encoding="utf-8") as held:
        return json.load(held)


def keep(held: dict) -> None:
    with open(STATE, "w", encoding="utf-8") as out:
        json.dump(held, out)


def call(method: str, path: str, body=None, *, headers=None, raw: bytes | None = None, tries: int = 60):
    """One request to the API, waited for while the server is away (it is killed on purpose): at
    most ``tries`` times three seconds. Returns (status, parsed answer)."""
    sent = dict(headers or {})
    data = raw
    if body is not None:
        data = json.dumps(body).encode()
        sent["Content-Type"] = "application/json"
    cookie = state().get("cookie")
    if cookie:
        sent.setdefault("Cookie", cookie)
    last = "no answer"
    for _ in range(tries):
        request = urllib.request.Request(f"{API}{path}", data=data, method=method, headers=sent)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - the stack of the test
                text = response.read()
                return response.status, (json.loads(text) if text[:1] in (b"{", b"[") else text)
        except urllib.error.HTTPError as error:
            text = error.read()
            if error.code in (502, 503, 504):
                last = f"{error.code}"
                time.sleep(3)
                continue
            return error.code, (json.loads(text) if text[:1] in (b"{", b"[") else text)
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            last = str(error)
            time.sleep(3)
    raise SystemExit(f"the API did not answer {method} {path}: {last}")


def must(answer: tuple, *codes: int):
    status, body = answer
    if status not in (codes or (200, 201, 202)):
        raise SystemExit(f"unexpected answer {status}: {str(body)[:400]}")
    return body


def multipart(name: str, filename: str, data: bytes) -> tuple[bytes, dict]:
    edge = "----nik-restart-chaos"
    head = f'--{edge}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
    head += "Content-Type: application/octet-stream\r\n\r\n"
    return head.encode() + data + f"\r\n--{edge}--\r\n".encode(), {
        "Content-Type": f"multipart/form-data; boundary={edge}"
    }


def tiny_pe(payload: bytes) -> bytes:
    """A valid PE32 of one section that holds ``payload`` (a few bytes that return): a file the
    analyzer and capa read, and that does nothing. Never run by anything."""
    dos = bytearray(b"MZ" + b"\0" * 58 + struct.pack("<I", 0x80))
    dos += b"\0" * (0x80 - len(dos))
    file_header = struct.pack("<HHIIIHH", 0x014C, 1, 0x5F5E1000, 0, 0, 0xE0, 0x0102)
    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 14, 0, 0x200, 0, 0, 0x1000, 0x1000, 0x2000, 0x400000, 0x1000, 0x200,
        6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0, 2, 0x8140, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )  # fmt: skip
    optional += b"\0" * (16 * 8)
    section = struct.pack("<8sIIIIIIHHI", b".text\0\0\0", len(payload), 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    body = bytearray(dos + b"PE\0\0" + file_header + optional + section)
    body += b"\0" * (0x200 - len(body))
    return bytes(body + payload.ljust(0x200, b"\0"))


CONNECTOR = """\
name: Chaos
id: chaos
version: 1
description: The other system of the restart test. It counts what it is asked.
configuration:
  - { name: url, type: url, required: true }
base_url: "{{ config.url }}"
commands:
  - name: read
    description: Only reads.
    arguments: [{ name: key, type: text, required: true }]
    request: { method: GET, path: "/read/{{ args.key }}" }
    outputs: { ok: "{{ response.ok }}" }
  - name: isolate
    description: Changes something, and may be repeated.
    changes_outside: true
    idempotent: true
    arguments: [{ name: key, type: text, required: true }]
    request: { method: POST, path: "/isolate/{{ args.key }}", json: { state: isolated } }
    outputs: { ok: "{{ response.ok }}" }
  - name: ticket
    description: Changes something, and may not be repeated.
    changes_outside: true
    idempotent: false
    arguments: [{ name: key, type: text, required: true }]
    request: { method: POST, path: "/ticket/{{ args.key }}", json: { title: a ticket } }
    outputs: { id: "{{ response.id }}" }
  - name: keyed
    description: Changes something; the other system acts once per key.
    changes_outside: true
    idempotent: false
    idempotency_key: true
    arguments: [{ name: key, type: text, required: true }]
    request:
      method: POST
      path: "/keyed/{{ args.key }}"
      headers: { Idempotency-Key: "{{ idempotency.key }}" }
      json: { title: a payment }
    outputs: { id: "{{ response.id }}" }
fetch:
  interval_seconds: 30
  first_fetch: 3 days
  request: { method: GET, path: /alerts }
  items: "{{ response.data }}"
  item_id: "{{ item.id }}"
  occurred: "{{ item.created }}"
"""


def node(node_id: str, kind: str, **config) -> dict:
    return {"id": node_id, "kind": kind, "name": node_id, "config": config}


def outside(node_id: str, command: str) -> dict:
    return node(
        node_id,
        "action",
        action=f"chaos.{command}",
        args={"key": "{{ run.id }}"},
        connection="Chaos",
        approval={"ask": False},
    )


def chain(*nodes: dict) -> list[dict]:
    ids = ["start", *(found["id"] for found in nodes)]
    return [{"from": a, "to": b} for a, b in zip(ids, ids[1:], strict=False)]


def playbook(name: str, nodes: list[dict], trigger: dict, enabled: bool = False) -> str:
    made = must(call("POST", "/api/automation/playbooks", {"name": name}))
    pid = made["id"]
    must(call("PUT", f"/api/automation/playbooks/{pid}", {"maxRunsPerHour": 10000, "maxSeconds": 3600}))
    shape = {"nodes": [node("start", "trigger", **trigger), *nodes], "edges": chain(*nodes)}
    must(call("POST", f"/api/automation/playbooks/{pid}/versions", {"graph": shape}))
    if enabled:
        must(call("PUT", f"/api/automation/playbooks/{pid}/enabled", {"enabled": True}))
    return pid


def setup() -> None:
    held = state()
    # The first account and its session: every other request is made with it.
    status, _ = call("POST", "/api/users", {"username": "admin", "password": PASSWORD})
    if status not in (201, 403, 409):
        raise SystemExit(f"the first account was not made ({status})")
    request = urllib.request.Request(
        f"{API}/api/auth/login",
        data=json.dumps({"username": "admin", "password": PASSWORD}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        held["cookie"] = response.headers.get("Set-Cookie", "").split(";")[0]
    keep(held)

    must(call("POST", "/api/automation/connectors", {"source": CONNECTOR}))
    instance = must(
        call("POST", "/api/automation/instances", {"name": "Chaos", "connector": "chaos", "config": {"url": STUB}})
    )
    held["instance"] = instance["id"]
    script = must(call("POST", "/api/automation/scripts", {"name": "ChaosScript"}))
    must(call("POST", f"/api/automation/scripts/{script['id']}/versions", {}))

    manual = {"manual": True}
    held["calls"] = playbook(
        "Chaos calls",
        [
            outside("read", "read"),
            outside("isolate", "isolate"),
            outside("keyed", "keyed"),
            outside("ticket", "ticket"),
            node("make", "action", action="nik.create-incident", args={"title": "made by {{ run.id }}"}),
            node("calc", "script", script="ChaosScript", script_version=1, args={}),
        ],
        manual,
    )
    held["timer"] = playbook("Chaos timer", [node("pause", "wait", seconds=60), outside("read", "read")], manual)
    held["event"] = playbook(
        "Chaos event",
        [node("note", "action", action="nik.add-note", args={"text": "seen by the restart test"})],
        {"event": "incident.created"},
        enabled=True,
    )
    must(call("PUT", f"/api/fetch/{instance['id']}", {"enabled": True}))
    keep(held)
    print("setup done")


def start(round_number: str) -> None:
    held = state()
    for _ in range(2):
        held["runs"].append(must(call("POST", f"/api/automation/playbooks/{held['calls']}/run", {}))["id"])
    held["runs"].append(must(call("POST", f"/api/automation/playbooks/{held['timer']}/run", {}))["id"])
    incident = f"chaos-{round_number}"
    status, _ = call("POST", "/api/incidents", {"id": incident, "name": incident, "data": {}})
    if status in (200, 201):
        held["incidents"].append(incident)
    # A file (static analysis, disassembly, capa), unlike that of any other round.
    body, headers = multipart("file", f"round-{round_number}.exe", tiny_pe(b"\x90" * int(round_number) + b"\xc3"))
    status, made = call("POST", f"/api/incidents/{incident}/samples", raw=body, headers=headers)
    if status == 201:
        held["samples"].append(made["sample"]["sha256"])
    capture = "/chaos/phish.pcapng"
    if os.path.exists(capture):
        with open(capture, "rb") as handle:
            body, headers = multipart("file", f"round-{round_number}.pcapng", handle.read())
        status, made = call("POST", f"/api/incidents/{incident}/captures", raw=body, headers=headers)
        if status == 201:
            held["captures"].append(made["capture"]["id"])
    mbox = b"".join(
        f"From a@example.com Thu Jan  1 00:00:00 2026\nFrom: a@example.com\nTo: b@example.com\n"
        f"Subject: round {round_number} message {n}\nMessage-ID: <{round_number}-{n}@example.com>\n\n"
        f"hello {n}\n\n".encode()
        for n in range(3)
    )
    body, headers = multipart("file", f"round-{round_number}.mbox", mbox)
    status, made = call("POST", "/api/artifacts/mailboxes", raw=body, headers=headers)
    if status == 201:
        held["mailboxes"].append(made["id"])
    # An address to scan. Whether the isolated browser reaches it is not the point (a machine with no
    # way out gets an error): the scan must end, done or failed, whatever is stopped under it.
    status, made = call("POST", "/api/artifacts/urls", {"url": f"https://example.com/?round={round_number}"})
    if status == 201 and isinstance(made, dict) and made.get("id"):
        held["scans"].append(made["id"])
    else:
        print(f"round {round_number}: the scan was not taken ({status}: {str(made)[:200]})")
    body, headers = multipart("file", ".bash_history", b"whoami\nid\nuname -a\n")
    status, made = call(
        "POST", f"/api/incidents/{incident}/upload?tab=commands&shell=bash&async=true", raw=body, headers=headers
    )
    if status == 202:
        held["jobs"].append(made["jobId"])
    keep(held)
    print(f"round {round_number}: started")


# --------------------------------------------------------------------------- #
# Settling, and what must be true at the end                                  #
# --------------------------------------------------------------------------- #
FINAL = ("done", "failed", "stopped")


def look(held: dict) -> dict:
    """Where everything stands: what still moves, and what waits for a person."""
    moving, waiting = [], []
    for run_id in held["runs"]:
        status, run = call("GET", f"/api/automation/runs/{run_id}")
        if status != 200:
            continue
        if run["status"] in FINAL:
            continue
        cut = [step for step in run["steps"] if step["status"] == "interrupted"]
        if cut:
            waiting += [(run_id, step["id"], step["node"]) for step in cut]
        else:
            moving.append(f"run {run_id} is {run['status']}")
    for sha in held["samples"]:
        for kind in ("code", "capabilities"):
            status, found = call("GET", f"/api/samples/{sha}/{kind}")
            if status == 200 and found.get("status") in ("queued", "running"):
                moving.append(f"{kind} of {sha[:12]} is {found['status']}")
    for capture in held["captures"]:
        status, found = call("GET", f"/api/captures/{capture}")
        if status == 200 and found.get("status") in ("indexing", "live"):
            moving.append(f"capture {capture} is {found['status']}")
    for mailbox in held["mailboxes"]:
        status, found = call("GET", f"/api/mailboxes/{mailbox}")
        if status == 200 and found.get("status") in ("indexing", "importing"):
            moving.append(f"mailbox {mailbox} is {found['status']}")
    for scan in held["scans"]:
        status, found = call("GET", f"/api/urls/{scan}")
        if status == 200 and found.get("status") in ("queued", "running"):
            moving.append(f"scan {scan} is {found['status']}")
    for job in held["jobs"]:
        status, found = call("GET", f"/api/jobs/{job}")
        if status == 200 and found.get("status") in ("queued", "running"):
            moving.append(f"upload job {job} is {found['status']}")
    return {"moving": moving, "waiting": waiting}


def settle() -> None:
    """Wait until nothing moves, answering each step a restart interrupted, in turn: it happened,
    it did not (do it again), stop. What was answered is kept: the assertions depend on it."""
    held = state()
    held.setdefault("answers", {})
    answers = ("happened", "again", "stop")
    deadline = time.time() + SETTLE_SECONDS
    seen = {"moving": ["nothing was looked at"], "waiting": []}
    while time.time() < deadline:
        seen = look(held)
        for run_id, step_id, node_id in seen["waiting"]:
            said = answers[len(held["answers"]) % len(answers)]
            status, _ = call("POST", f"/api/automation/runs/{run_id}/steps/{step_id}/resolve", {"answer": said})
            if status == 200:
                held["answers"].setdefault(run_id, []).append([node_id, said])
                keep(held)
                print(f"run {run_id}: {node_id} was interrupted, answered {said!r}")
        if not seen["moving"] and not seen["waiting"]:
            keep(held)
            print("settled: nothing moves, nothing waits")
            return
        time.sleep(5)
    keep(held)
    raise SystemExit("did not settle: " + "; ".join(seen["moving"][:12]))


def verify() -> None:
    held = state()
    wrong: list[str] = []
    with urllib.request.urlopen(f"{STUB}/counts", timeout=30) as response:  # noqa: S310
        counts = json.loads(response.read())
    answers = held.get("answers", {})
    done = stopped = given_up = 0
    for run_id in held["runs"]:
        run = must(call("GET", f"/api/automation/runs/{run_id}"))
        if run["status"] not in FINAL:
            wrong.append(f"run {run_id} is {run['status']} at the end")
            continue
        done += run["status"] == "done"
        stopped += run["status"] == "stopped"
        steps = {step["node"]: step for step in run["steps"]}
        again = sum(1 for node_id, said in answers.get(run_id, []) if node_id == "ticket" and said == "again")
        # What may not be repeated was sent at most once, plus once for each "do it again" of a person.
        tickets = counts["ticket"].get(run_id, 0)
        if tickets > 1 + again:
            wrong.append(f"run {run_id}: the ticket was opened {tickets} times ({again} asked for again)")
        if steps.get("ticket", {}).get("status") == "done" and not tickets and not answers.get(run_id):
            wrong.append(f"run {run_id}: the ticket step is done and the other system never saw it")
        # What sends a key: the other system saw one key for the step, however many requests.
        if len(counts["keys"].get(run_id, [])) > 1:
            wrong.append(f"run {run_id}: the keyed command sent {len(counts['keys'][run_id])} different keys")
        if run["playbook"] == "Chaos calls" and run["status"] == "done":
            for kind in ("read", "isolate", "keyed"):
                if not counts[kind].get(run_id):
                    wrong.append(f"run {run_id} is done and {kind} never reached the other system")
        if run["status"] == "failed":
            # A step that was cut three times while it ran is given up, and says so: an end of its
            # own, counted here. Any other failure is not what a restart may do to a run.
            if "Interrupted by a restart" in str(run.get("error")):
                given_up += 1
            else:
                wrong.append(f"run {run_id} failed: {run.get('error')}")
    # Inside Nik: the incident a run makes is made once, and only by a run that got that far.
    incidents = must(call("GET", "/api/incidents?limit=1000"))
    listed = incidents if isinstance(incidents, list) else incidents.get("incidents", incidents.get("items", []))
    names = [str(found.get("name") or "") for found in listed]
    for run_id in held["runs"]:
        made = sum(1 for name in names if name == f"made by {run_id}")
        if made > 1:
            wrong.append(f"run {run_id} made {made} incidents")
    # A fetch: each alert of the other system is one incident, whatever was killed between two cycles.
    status, items = call("GET", f"/api/fetch/{held['instance']}/items")
    rows = (items.get("items") if isinstance(items, dict) else items) or []
    fetched = [str(row.get("itemId") or row.get("item_id") or row.get("id")) for row in rows]
    for n in range(ALERTS):
        if fetched.count(f"alert-{n}") != 1:
            wrong.append(f"alert-{n} was fetched {fetched.count(f'alert-{n}')} times")
    # An event: the playbook that waits for a new incident ran once for each, never twice.
    runs = must(call("GET", f"/api/automation/runs?playbook={held['event']}&limit=200"))["runs"]
    per_incident: dict[str, int] = {}
    for run in runs:
        per_incident[run["objectId"]] = per_incident.get(run["objectId"], 0) + 1
        if run["status"] not in FINAL:
            wrong.append(f"the run {run['id']} of the event playbook is {run['status']}")
    for incident, times in per_incident.items():
        if times != 1:
            wrong.append(f"the event playbook ran {times} times for the incident {incident}")
    for incident in held["incidents"]:
        if per_incident.get(incident, 0) != 1:
            wrong.append(f"the event playbook ran {per_incident.get(incident, 0)} times for {incident}")
    # Every job of the API process reached an end.
    left = look(held)
    wrong += [f"still moving: {what}" for what in left["moving"]]
    wrong += [f"still waiting for a person: run {run_id} at {node_id}" for run_id, _step, node_id in left["waiting"]]
    health = must(call("GET", "/api/health/details"))
    rows = {row["id"]: row for row in health.get("rows", [])}
    for name in ("work.interrupted", "work.silent"):
        if rows.get(name, {}).get("state") not in ("fine", None):
            wrong.append(f"the health row {name} says: {rows[name]['value']}")
    summary = {
        "runs": len(held["runs"]),
        "done": done,
        "stopped by an answer": stopped,
        "given up after three interruptions": given_up,
        "answers": sum(len(found) for found in answers.values()),
        "samples": len(held["samples"]),
        "captures": len(held["captures"]),
        "mailboxes": len(held["mailboxes"]),
        "scans": len(held["scans"]),
        "upload jobs": len(held["jobs"]),
        "event runs": len(runs),
        "set aside": rows.get("work.aside", {}).get("value"),
        "calls counted": {kind: sum(counts[kind].values()) for kind in ("read", "isolate", "ticket", "keyed")},
    }
    print(json.dumps(summary, indent=1))
    if wrong:
        print("\n".join(f"WRONG: {line}" for line in wrong))
        raise SystemExit(1)
    print("verified")


def archive_gaps(names: list[str]) -> tuple[int, list[str]]:
    """The segments an archive holds, and those it lacks between its first and its last, timeline
    by timeline. A segment is named by its timeline, then two numbers of eight hexadecimal digits:
    256 segments of 16 MB to each of the first."""
    held: dict[str, set[int]] = {}
    for name in names:
        stem = name.strip().removesuffix(".gz")
        if len(stem) == 24 and all(letter in "0123456789ABCDEF" for letter in stem):
            held.setdefault(stem[:8], set()).add(int(stem[8:16], 16) * 256 + int(stem[16:], 16))
    missing = []
    for timeline, numbers in sorted(held.items()):
        for number in range(min(numbers), max(numbers) + 1):
            if number not in numbers:
                missing.append(f"{timeline}{number // 256:08X}{number % 256:08X}")
    return sum(len(numbers) for numbers in held.values()), missing


def archive() -> None:
    count, missing = archive_gaps(sys.stdin.read().split())
    if not count:
        print("WRONG: the archive of the log holds no segment")
        raise SystemExit(1)
    if missing:
        print(f"WRONG: the archive of the log lacks {len(missing)} segment(s) between its first and its last:")
        for name in missing[:40]:
            print(f"  {name}")
        raise SystemExit(1)
    print(f"the archive of the log holds {count} segments, with no gap")


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "stub":
        stub()
    elif command == "setup":
        setup()
    elif command == "start":
        start(sys.argv[2])
    elif command == "settle":
        settle()
    elif command == "verify":
        verify()
    elif command == "archive":
        archive()
    else:
        raise SystemExit(__doc__)
