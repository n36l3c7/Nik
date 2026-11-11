"""The document viewer worker: needs LibreOffice and pypdfium2 (its image has both)."""

from __future__ import annotations

import base64
import io
import json
import os
import sys
import threading
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
