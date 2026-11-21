"""The document viewer worker: needs LibreOffice and pypdfium2 (its image has both)."""

from __future__ import annotations

import base64
import collections
import io
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DOCVIEW_TOKEN", "test-token")

import nik_docview  # noqa: E402
import server  # noqa: E402

RTF = rb"{\rtf1\ansi{\fonttbl\f0\fswiss Helvetica;}\f0\pard Invoice 2041: please enable editing.\par}"


def _pdf(pages: int) -> bytes:
    import pypdfium2 as pdfium

    document = pdfium.PdfDocument.new()
    for _ in range(pages):
        document.new_page(595, 842)
    buffer = io.BytesIO()
    document.save(buffer)
    return buffer.getvalue()


def _png() -> bytes:
    from PIL import Image

    buffer = io.BytesIO()
    Image.new("RGB", (40, 20), "red").save(buffer, "PNG")
    return buffer.getvalue()


def test_kinds():
    assert nik_docview.kind_of("a.pdf", b"%PDF-1.7") == "pdf"
    assert nik_docview.kind_of("Invoice.DOCM", b"PK\x03\x04") == "office"
    assert nik_docview.kind_of("noname", RTF) == "office"
    assert nik_docview.kind_of("x", _png()) == "image"
    assert nik_docview.kind_of("setup.exe", b"MZ") is None


def test_office_document_is_converted_and_rendered():
    result = nik_docview.render("invoice.rtf", RTF)
    assert result["format"] == "office" and result["converted"] and result["total"] == 1
    page = result["pages"][0]
    assert page["width"] == nik_docview.WIDTH and base64.b64decode(page["png"]).startswith(b"\x89PNG")


def test_unknown_or_hostile_names_never_reach_the_command(monkeypatch):
    seen = []
    real_run = nik_docview.subprocess.run

    def run(command, **kwargs):
        seen.append(command[-1])
        return real_run(command, **kwargs)

    monkeypatch.setattr(nik_docview.subprocess, "run", run)
    # In this process, where the command can be watched (render() runs it in a child).
    nik_docview.render_here("../../etc/passwd --infilter=x.rtf\\x", RTF)
    assert seen[0].endswith(".rtf") and "passwd" not in seen[0] and "infilter" not in seen[0]


def test_pdf_pages_are_capped():
    result = nik_docview.render("big.pdf", _pdf(25), max_pages=3)
    assert result["total"] == 25 and len(result["pages"]) == 3 and not result["converted"]


def test_image_and_errors():
    assert nik_docview.render("a.png", _png())["pages"][0]["width"] == 40
    with pytest.raises(nik_docview.PreviewError):
        nik_docview.render("broken.pdf", b"%PDF-1.7 not really")
    with pytest.raises(nik_docview.PreviewError):
        nik_docview.render("setup.exe", b"MZ\x90\x00")


@pytest.fixture()
def worker():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _post(url, body, token="test-token"):
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"X-Docview-Token": token, "Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_server(worker, monkeypatch):
    monkeypatch.setattr(server, "TOKEN", "test-token")
    body = {"name": "x.pdf", "data": base64.b64encode(_pdf(1)).decode()}
    assert _post(f"{worker}/render", body, token="wrong")[0] == 401
    status, result = _post(f"{worker}/render", body)
    assert status == 200 and result["total"] == 1
    assert _post(f"{worker}/render", {"name": "x.exe", "data": base64.b64encode(b"MZ").decode()})[0] == 422
    assert _post(f"{worker}/render", {"data": "not base64!"})[0] == 400


def test_a_preview_that_stalls_is_killed_with_everything_it_started(monkeypatch, tmp_path):
    """The time limit ends the preview process AND what it started (soffice.bin outlives its launcher)."""
    import os
    import time

    grandchild = tmp_path / "pid"
    # In place of the preview process: starts a child of its own, then never answers.
    monkeypatch.setattr(nik_docview, "_RENDERER", ["sh", "-c", f"sleep 300 & echo $! > {grandchild}; sleep 300"])
    monkeypatch.setattr(nik_docview, "TIMEOUT", 1.0)
    started = time.monotonic()
    with pytest.raises(nik_docview.PreviewError, match="took more than 1 s"):
        nik_docview.render("a.pdf", b"%PDF-1.4")
    assert time.monotonic() - started < 15
    pid = int(grandchild.read_text())
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        raise AssertionError("the process started by the preview is still running")


def test_a_preview_process_that_dies_is_an_error_not_a_hang(monkeypatch):
    monkeypatch.setattr(nik_docview, "_RENDERER", ["sh", "-c", "exit 137"])
    with pytest.raises(nik_docview.PreviewError, match="stopped before finishing"):
        nik_docview.render("a.pdf", b"%PDF-1.4")


def _post_pst(url, data, token="test-token"):
    request = urllib.request.Request(
        url, data=data, headers={"X-Docview-Token": token, "Content-Type": "application/octet-stream"}
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())["detail"].encode()


def test_a_pst_is_converted_on_the_work_volume_when_there_is_room(worker, monkeypatch, tmp_path):
    monkeypatch.setattr(server, "TOKEN", "test-token")
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(server, "WORK_DIR", str(work))
    seen = {}

    def fake_readpst(source, folder):
        seen["source"], seen["size"] = source, os.path.getsize(source)
        part = os.path.join(folder, "Inbox")
        with open(part, "wb") as out:
            out.write(b"From a\n\nhello\n")
        return [part]

    monkeypatch.setattr(server, "pst_to_mbox", fake_readpst)
    status, body = _post_pst(f"{worker}/pst", b"!BDN" + b"\x00" * 2000)
    assert status == 200 and body == b"From a\n\nhello\n\n"
    # Converted under the work directory, not in /tmp, and nothing is left there.
    assert seen["source"].startswith(str(work)) and seen["size"] == 2004
    # The answer is complete a moment before the worker has removed its folder.
    deadline = time.monotonic() + 5
    while list(work.iterdir()) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert list(work.iterdir()) == []
    # A disk without room for the file and its mbox: refused before a byte is written.
    usage = collections.namedtuple("usage", "total used free")
    monkeypatch.setattr(server.shutil, "disk_usage", lambda path: usage(10_000, 9_000, 1_000))
    status, why = _post_pst(f"{worker}/pst", b"!BDN" + b"\x00" * 2000)
    assert status == 507 and b"Not enough room to convert this PST" in why
    assert server.pst_refusal(300) is None  # 750 bytes needed, 1 000 free
    # What a conversion that was cut short left behind is cleared at the next start.
    (work / "nik-pst-stale").mkdir()
    (work / "kept").mkdir()
    server.clear_work_dir()
    assert sorted(path.name for path in work.iterdir()) == ["kept"]


def test_without_a_work_volume_only_a_small_pst_is_taken(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "WORK_DIR", str(tmp_path / "missing"))
    monkeypatch.setattr(server, "PST_TMP_MAX_BYTES", 1000)
    assert server.work_dir() is None
    assert server.pst_refusal(900) is None
    status, why = server.pst_refusal(2000)
    assert status == 413 and "no work volume" in why
    assert server.pst_refusal(0) == (400, "Empty file")
    monkeypatch.setattr(server, "PST_MAX_BYTES", 500)
    assert server.pst_refusal(900)[0] == 413


def test_a_pst_being_read_says_how_far_it_is_and_a_restarted_worker_does_not_know_it(worker, monkeypatch, tmp_path):
    import jobs

    monkeypatch.setattr(server, "TOKEN", "test-token")
    monkeypatch.setattr(server, "JOBS", jobs.Jobs())
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(server, "WORK_DIR", str(work))
    job, seen = "mailbox:" + "c" * 32 + ":1", []

    def asked(token="test-token"):
        request = urllib.request.Request(f"{worker}/jobs/{job}", headers={"X-Docview-Token": token})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def fake_readpst(source, folder):
        seen.append(asked())  # the backend asks while readpst works
        part = os.path.join(folder, "Inbox")
        with open(part, "wb") as out:
            out.write(b"From a\n\nhello\n")
        return [part]

    monkeypatch.setattr(server, "pst_to_mbox", fake_readpst)
    request = urllib.request.Request(
        f"{worker}/pst",
        data=b"!BDN" + b"\x00" * 2000,
        headers={"X-Docview-Token": "test-token", "Content-Type": "application/octet-stream", jobs.HEADER: job},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        assert response.status == 200 and response.read() == b"From a\n\nhello\n\n"
    assert seen == [
        (200, {"state": "running", "seconds": seen[0][1]["seconds"], "progress": "reading the PST (readpst)"})
    ]
    assert asked()[1]["state"] == "finished" and asked(token="wrong")[0] == 401
    # Killed and started again: the job is unknown, said at once.
    monkeypatch.setattr(server, "JOBS", jobs.Jobs())
    status, unknown = asked()
    assert status == 404 and unknown["unknown"] is True and unknown["detail"] == "Unknown job"
