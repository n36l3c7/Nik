"""A file of the store for a process of the server that does not hold the store key.

The automation worker runs the steps of playbooks: it unpacks archives, reads
evidence out of files, sends files to connectors. It is also the one
container with a way out to the Internet. So it is given neither the store
nor its key: when a step needs the bytes of a sample or of an e-mail, it asks
the API process, which decrypts the file and sends it (``fetch`` here, the
route ``GET /api/internal/store/{kind}/{sha256}`` there).

Who asks is proved with ``SECRET_KEY``, which both processes hold already: the
request carries the time and an HMAC-SHA256 of the time and of what is asked,
under a key derived from ``SECRET_KEY`` for this purpose only. A request is
good for two minutes. nginx does not publish ``/api/internal/``; if it did,
the route would still answer nothing to who cannot make that proof.

What this buys: a subverted automation worker can ask for files one by one
while it runs, and each request is the API's to see; it cannot read the
store at rest, and it has no store key to carry away.

The worker also deletes: an artifact whose day came is removed by it
(``artifact_expiry.py``). The rows go in its transaction; the files it cannot
touch are named in a job the API process does (``ask_removal``, the kind
``remove`` of ``artifact_jobs.py``).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .core.config import settings

HEADER = "X-Nik-Store"
KINDS = ("sample", "mail")
GOOD_FOR = 120
TIMEOUT = 300


class NotServed(OSError):
    """The API process did not give the file: what it said."""


def _key(secret: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"nik store hand-over").derive(
        secret.encode("utf-8")
    )


def _proof(secret: str, kind: str, ref: str, at: int) -> str:
    return hmac.new(_key(secret), f"{at}:{kind}:{ref}".encode(), hashlib.sha256).hexdigest()


def token(kind: str, ref: str, now: float | None = None) -> str:
    at = int(time.time() if now is None else now)
    return f"{at}.{_proof(settings.SECRET_KEY, kind, ref, at)}"


def verify(kind: str, ref: str, sent: str, now: float | None = None) -> bool:
    """Whether ``sent`` proves that the request for this file comes from a process of this server."""
    at_text, _dot, proof = (sent or "").partition(".")
    if not at_text.isdigit() or len(proof) != 64:
        return False
    at = int(at_text)
    if abs((time.time() if now is None else now) - at) > GOOD_FOR:
        return False
    # While SECRET_KEY is being changed the two processes may start a moment apart.
    return any(
        hmac.compare_digest(proof, _proof(secret, kind, ref, at))
        for secret in (settings.SECRET_KEY, *settings.SECRET_KEY_PREVIOUS)
    )


def ask_removal(names: list[str]) -> None:
    """Ask the API process to delete files or folders of the store, named by their path inside it.
    Written in a transaction of its own: the rows that spoke of them are gone already."""
    import uuid

    from .core.db import SessionLocal
    from .core.models import ArtifactJob

    names = [name for name in names if name and not name.startswith(("/", "."))]
    if not names:
        return
    with SessionLocal() as db:
        db.add(
            ArtifactJob(
                id=uuid.uuid4().hex,
                kind="remove",
                status="queued",
                params={"names": names},
                result={},
                actor="nik",
                run_id="",
                depth=0,
                created_epoch=time.time(),
            )
        )
        db.commit()


def fetch(kind: str, ref: str) -> bytes:
    """The bytes of a sample or of an e-mail, asked of the API process. Raises ``NotServed``."""
    if not settings.STORE_API_URL:
        raise NotServed(
            "This process does not hold the store key and was not told where to ask for files (NIK_STORE_API_URL)"
        )
    request = urllib.request.Request(  # noqa: S310 - the address of the API container, from the configuration
        f"{settings.STORE_API_URL}/api/internal/store/{kind}/{ref}", headers={HEADER: token(kind, ref)}
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310
            data = response.read()
            expected = response.headers.get("Content-Length")
    except urllib.error.HTTPError as error:
        try:
            detail = json.loads(error.read() or b"{}").get("detail")
        except (ValueError, AttributeError):
            detail = None
        if error.code == 404:
            raise FileNotFoundError(str(detail or "The file is not in the store")) from None
        raise NotServed(str(detail or f"The API process answered {error.code}")) from None
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise NotServed(f"The API process could not be asked for the file: {getattr(error, 'reason', error)}") from None
    if expected is not None and int(expected) != len(data):
        # The API stops in the middle of a file it finds damaged: half a file is never taken for one.
        raise NotServed("The file stopped before its end: the API process found it damaged, or went away")
    if hashlib.sha256(data).hexdigest() != ref:
        raise NotServed("The file received is not the one that was asked for")
    return data


def backend_health() -> str:
    """What the API process answers to its health check, asked from the process that has no store
    key: ``ok``, the word of a server that did not start (``stopped``, ``upgrade-stopped``), or
    nothing when it does not answer or this process was not told where it is."""
    if not settings.STORE_API_URL:
        return ""
    try:
        with urllib.request.urlopen(f"{settings.STORE_API_URL}/api/health", timeout=5) as answer:  # noqa: S310
            return str(json.loads(answer.read(4096)).get("status") or "")
    except Exception:  # noqa: BLE001 - not there: the caller decides
        return ""
