"""End-to-end API tests: auth, API-key permissions, incidents, notes, upload,
pagination, concurrency, idempotency, jobs and webhooks."""

from __future__ import annotations

import http.server
import threading
import time

from fastapi.testclient import TestClient

from app.main import app as fastapi_app

from .conftest import ADMIN, make_key


def test_health_ready_metrics(client: TestClient):
    h = client.get("/api/health")
    assert h.status_code == 200 and "X-Request-ID" in h.headers
    assert client.get("/api/ready").json()["status"] == "ready"
    m = client.get("/api/metrics")
    assert m.status_code == 200 and b"nik_http_requests_total" in m.content


def test_public_docs_and_unauth(client: TestClient):
    assert client.get("/api/docs").status_code == 200
    assert client.get("/api/openapi.json").status_code == 200
    assert client.get("/api/incidents").status_code == 401


def test_first_run_and_login(client: TestClient):
    r = client.post("/api/users", json=ADMIN)
    assert r.status_code == 201 and r.json()["user"]["role"] == "admin"
    r = client.post("/api/auth/login", json=ADMIN)
    assert r.status_code == 200 and "nik_session" in client.cookies


def test_api_key_permissions(admin: TestClient):
    analyst = make_key(admin, label="a")
    k = TestClient(fastapi_app)
    assert k.get("/api/incidents", headers={"X-API-Key": "nik_bogus"}).status_code == 401
    assert k.get("/api/incidents", headers=analyst).status_code == 200
    # analyst blocked from admin data
    assert k.get("/api/users", headers=analyst).status_code == 403
    assert k.get("/api/backup/export", headers=analyst).status_code == 403
    # admin key allowed
    adm = make_key(admin, label="adm", role="admin")
    assert k.get("/api/users", headers=adm).status_code == 200
    assert k.get("/api/backup/export", headers=adm).status_code == 200
    # read-only key can't write
    ro = make_key(admin, label="ro", scopes=["read"])
    assert k.get("/api/incidents", headers=ro).status_code == 200
    assert k.post("/api/incidents", headers=ro, json={"id": "x", "data": {}}).status_code == 403


def test_incident_crud_notes_via_key(admin: TestClient):
    k = TestClient(fastapi_app)
    H = make_key(admin)
    assert k.post("/api/incidents", headers=H, json={"id": "i1", "name": "H1", "data": {}}).json()["createdBy"] == "api:test"
    assert k.patch("/api/incidents/i1", headers=H, json={"host": "wks"}).json()["host"] == "wks"
    n = k.post("/api/incidents/i1/notes", headers=H, json={"text": "hi"})
    assert n.status_code == 201 and n.json()["author"] == "api:test"
    assert k.delete(f"/api/incidents/i1/notes/{n.json()['id']}", headers=H).status_code == 204
    assert k.delete("/api/incidents/i1", headers=H).status_code == 204


def test_upload_sync_and_async(admin: TestClient):
    k = TestClient(fastapi_app)
    H = make_key(admin)
    k.post("/api/incidents", headers=H, json={"id": "u1", "data": {}})
    files = {"file": (".bash_history", b"#1700000000\nsudo cat /etc/shadow\nls\n", "text/plain")}
    r = k.post("/api/incidents/u1/upload?tab=commands&shell=bash", headers=H, files=files)
    assert r.status_code == 200 and r.json()["rows"] == 2
    cmds = k.get("/api/incidents/u1", headers=H).json()["data"]["commands"]["shells"]["bash"]["commands"]
    assert cmds[0]["command"] == "sudo cat /etc/shadow"
    # async
    files = {"file": (".zsh_history", b"a\nb\nc\n", "text/plain")}
    r = k.post("/api/incidents/u1/upload?tab=commands&shell=zsh&async=true", headers=H, files=files)
    assert r.status_code == 202
    job = k.get(f"/api/jobs/{r.json()['jobId']}", headers=H).json()
    assert job["status"] == "done" and job["result"]["rows"] == 3


def test_pagination_etag_idempotency(admin: TestClient):
    k = TestClient(fastapi_app)
    H = make_key(admin)
    for i in range(3):
        k.post("/api/incidents", headers=H, json={"id": f"p{i}", "name": f"N{i}", "data": {}})
    r = k.get("/api/incidents?view=summary&limit=2", headers=H)
    assert len(r.json()["incidents"]) == 2 and "data" not in r.json()["incidents"][0]
    assert int(r.headers["X-Total-Count"]) == 3
    # ETag / If-Match
    etag = k.get("/api/incidents/p0", headers=H).headers["ETag"]
    assert k.patch("/api/incidents/p0", headers={**H, "If-Match": '"stale"'}, json={"host": "x"}).status_code == 412
    assert k.patch("/api/incidents/p0", headers={**H, "If-Match": etag}, json={"host": "x"}).status_code == 200
    # Idempotency
    idem = {**H, "Idempotency-Key": "abc"}
    a = k.post("/api/incidents/p1/notes", headers=idem, json={"text": "once"})
    b = k.post("/api/incidents/p1/notes", headers=idem, json={"text": "once"})
    assert a.json()["id"] == b.json()["id"]
    assert len(k.get("/api/incidents/p1", headers=H).json()["notes"]) == 1


def test_webhook_delivery(admin: TestClient):
    k = TestClient(fastapi_app)
    H = make_key(admin)
    k.post("/api/incidents", headers=H, json={"id": "w1", "data": {}})

    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            received.append((dict(self.headers), self.rfile.read(n)))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        wr = admin.post("/api/webhooks", json={"url": f"http://127.0.0.1:{srv.server_address[1]}/h", "events": ["note.added"]})
        assert wr.status_code == 201 and wr.json()["secret"].startswith("whsec_")
        assert k.post("/api/webhooks", headers=H, json={"url": "http://x", "events": ["note.added"]}).status_code == 403
        k.post("/api/incidents/w1/notes", headers=H, json={"text": "hook"})
        time.sleep(0.3)
        assert len(received) >= 1
        assert any("X-Nik-Signature" in h for h, _ in received)
    finally:
        srv.shutdown()
