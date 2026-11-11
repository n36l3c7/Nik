"""Document previews: Office documents to PDF (LibreOffice), PDF to page images (pdfium).

``render(name, data)`` returns ``{"format", "converted", "total", "pages": [{"png", "width", "height"}]}``
with the first ``MAX_PAGES`` pages as base64 PNG.

LibreOffice runs headless with a fresh profile per conversion that sets the
macro security to "very high" (no macro runs, signed or not) and never
updates links to other files or the network; the container has no route
outside anyway.

Every preview is made in a process of its own (this file run as a script),
and that process is killed with everything it started after ``TIMEOUT``
seconds. A document built to stall LibreOffice, pdfium or the image decoder
costs one preview, not a slot of the worker for ever: ``soffice`` is only a
launcher, and killing it alone would leave ``soffice.bin`` running.
"""

from __future__ import annotations

import base64
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import uuid

MAX_PAGES = int(os.environ.get("DOCVIEW_MAX_PAGES", "20"))
TIMEOUT = float(os.environ.get("DOCVIEW_TIMEOUT", "90"))
WIDTH = 1100  # rendered page width in pixels
MAX_PIXELS = 40_000_000

OFFICE = {
    "doc", "docx", "docm", "dot", "dotx", "dotm", "rtf", "odt", "ott", "wpd",
    "xls", "xlsx", "xlsm", "xlsb", "xlt", "xltx", "xltm", "ods", "csv",
    "ppt", "pptx", "pptm", "pps", "ppsx", "ppsm", "pot", "potx", "odp",
}  # fmt: skip
IMAGES = {"png", "jpg", "jpeg", "gif", "bmp", "tif", "tiff", "webp"}

# A LibreOffice profile: no macros, no link updates, no recovery, no update check.
_PROFILE = """<?xml version="1.0" encoding="UTF-8"?>
<oor:items xmlns:oor="http://openoffice.org/2001/registry" xmlns:xs="http://www.w3.org/2001/XMLSchema"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<item oor:path="/org.openoffice.Office.Common/Security/Scripting"><prop oor:name="MacroSecurityLevel"
 oor:op="fuse"><value>3</value></prop></item>
<item oor:path="/org.openoffice.Office.Common/Security/Scripting"><prop oor:name="DisableMacrosExecution"
 oor:op="fuse"><value>true</value></prop></item>
<item oor:path="/org.openoffice.Office.Writer/Content/Update"><prop oor:name="Link" oor:op="fuse">
<value>2</value></prop></item>
<item oor:path="/org.openoffice.Office.Calc/Content/Update"><prop oor:name="Link" oor:op="fuse">
<value>2</value></prop></item>
<item oor:path="/org.openoffice.Office.Common/Misc"><prop oor:name="UseLocking" oor:op="fuse">
<value>false</value></prop></item>
<item oor:path="/org.openoffice.Office.Recovery/RecoveryInfo"><prop oor:name="Enabled" oor:op="fuse">
<value>false</value></prop></item>
</oor:items>
"""


class PreviewError(Exception):
    """The document cannot be previewed."""


def extension(name: str) -> str:
    base = (name or "").rsplit("/", 1)[-1].lower().strip(" .")
    return base.rsplit(".", 1)[-1] if "." in base else ""


def kind_of(name: str, data: bytes) -> str | None:
    """``pdf``, ``office``, ``image`` or None."""
    ext = extension(name)
    if data[:5] == b"%PDF-" or ext == "pdf":
        return "pdf"
    if ext in OFFICE or data[:5] == b"{\\rtf":
        return "office"
    if ext in IMAGES or data[:8] == b"\x89PNG\r\n\x1a\n" or data[:3] == b"\xff\xd8\xff" or data[:4] == b"GIF8":
        return "image"
    return None


def office_to_pdf(name: str, data: bytes) -> bytes:
    work = tempfile.mkdtemp(prefix="nik-docview-")
    try:
        profile = os.path.join(work, "profile")
        os.makedirs(os.path.join(profile, "user"))
        with open(os.path.join(profile, "user", "registrymodifications.xcu"), "w", encoding="utf-8") as handle:
            handle.write(_PROFILE)
        # A neutral name: a known extension tells LibreOffice the format; nothing
        # of the original name reaches the path or the command line.
        ext = next((known for known in sorted(OFFICE) if known == extension(name)), "rtf")
        source = os.path.join(work, f"{uuid.uuid4().hex}.{ext}")
        with open(source, "wb") as handle:
            handle.write(data)
        out = os.path.join(work, "out")
        command = [
            shutil.which("soffice") or "soffice",
            f"-env:UserInstallation=file://{profile}",
            "--headless",
            "--norestore",
            "--nologo",
            "--nodefault",
            "--nolockcheck",
            "--convert-to",
            "pdf",
            "--outdir",
            out,
            source,
        ]
        try:
            subprocess.run(command, capture_output=True, timeout=TIMEOUT, check=False, cwd=work)  # noqa: S603
        except subprocess.TimeoutExpired as exc:
            raise PreviewError(f"LibreOffice took more than {int(TIMEOUT)} s") from exc
        produced = [f for f in os.listdir(out)] if os.path.isdir(out) else []
        if not produced:
            raise PreviewError("LibreOffice could not open the document")
        with open(os.path.join(out, produced[0]), "rb") as handle:
            return handle.read()
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _png(image) -> dict:
    buffer = io.BytesIO()
    image.save(buffer, "PNG", optimize=True)
    return {"png": base64.b64encode(buffer.getvalue()).decode(), "width": image.width, "height": image.height}


def pdf_pages(data: bytes, max_pages: int = MAX_PAGES) -> tuple[int, list[dict]]:
    import pypdfium2 as pdfium

    try:
        document = pdfium.PdfDocument(data)
    except Exception as exc:  # noqa: BLE001 - pdfium raises its own error types
        raise PreviewError(f"pdfium cannot read the PDF: {exc}") from exc
    try:
        total = len(document)
        pages = []
        for index in range(min(total, max_pages)):
            page = document[index]
            width, height = page.get_size()
            scale = min(3.0, WIDTH / max(width, 1))
            if width * height * scale * scale > MAX_PIXELS:
                scale = (MAX_PIXELS / max(width * height, 1)) ** 0.5
            pages.append(_png(page.render(scale=scale).to_pil()))
            page.close()
        return total, pages
    finally:
        document.close()


def image_page(data: bytes) -> dict:
    from PIL import Image

    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    try:
        with Image.open(io.BytesIO(data)) as image:
            image.seek(0)
            frame = image.convert("RGB")
    except Exception as exc:  # noqa: BLE001 - not an image Pillow reads
        raise PreviewError(f"not a readable image: {exc}") from exc
    if frame.width > 2400:
        frame = frame.resize((2400, int(frame.height * 2400 / frame.width)))
    return _png(frame)


def render_here(name: str, data: bytes, max_pages: int = MAX_PAGES) -> dict:
    """Make the preview in this process (what the child of ``render`` runs)."""
    kind = kind_of(name, data)
    if kind is None:
        raise PreviewError("not a document Nik can preview (PDF, Office, OpenDocument, RTF, image)")
    if kind == "image":
        return {"format": "image", "converted": False, "total": 1, "pages": [image_page(data)]}
    pdf = office_to_pdf(name, data) if kind == "office" else data
    total, pages = pdf_pages(pdf, max_pages)
    return {"format": kind, "converted": kind == "office", "total": total, "pages": pages}


# The preview process: this file, run as a script (see ``_main``).
_RENDERER = [sys.executable, os.path.abspath(__file__)]


def _kill_group(process: subprocess.Popen) -> None:
    """Kill the preview process and whatever it started (``soffice.bin`` outlives its launcher)."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass  # already gone
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def render(name: str, data: bytes, max_pages: int = MAX_PAGES) -> dict:
    """The preview of a document, made in a process of its own within ``TIMEOUT`` seconds."""
    request = json.dumps({"name": name, "data": base64.b64encode(data).decode(), "max_pages": max_pages}).encode()
    process = subprocess.Popen(  # noqa: S603 - this interpreter, this file
        _RENDERER, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True
    )
    try:
        output, _ = process.communicate(request, timeout=TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        raise PreviewError(f"the preview took more than {int(TIMEOUT)} s") from exc
    finally:
        _kill_group(process)
    try:
        answer = json.loads(output)
    except ValueError as exc:
        raise PreviewError("the preview stopped before finishing (the document may need too much memory)") from exc
    if "error" in answer:
        raise PreviewError(answer["error"])
    return answer["preview"]


def _main() -> None:
    """The preview process: a request on stdin, the preview (or the error) on stdout."""
    request = json.load(sys.stdin.buffer)
    try:
        answer = {"preview": render_here(request["name"], base64.b64decode(request["data"]), int(request["max_pages"]))}
    except PreviewError as exc:
        answer = {"error": str(exc)}
    json.dump(answer, sys.stdout)


if __name__ == "__main__":
    _main()
