"""A syslog receiver for the tests: UDP, TCP with octet counting, and TLS, on the loopback.

It keeps every message it got, in the order it got them, and reads the
framing strictly: over TCP and TLS a message is ``<decimal length> <that many
bytes>`` and anything else is written down as a framing error. It can be
stopped and started again on the same port (a receiver that restarts), and
told not to read what it is sent (a receiver that is stuck).
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import socket
import ssl
import threading
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _name(common: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])


def _pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


class Authority:
    """A certificate authority made for one test, and what it signs."""

    def __init__(self, common: str = "Test syslog CA") -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        self.certificate = (
            x509.CertificateBuilder()
            .subject_name(_name(common))
            .issuer_name(_name(common))
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self.key, hashes.SHA256())
        )
        self.pem = _pem(self.certificate)

    def issue(self, common: str, *, server: bool = True, days: int = 30) -> tuple[str, str]:
        """A certificate and its key, both in PEM, for ``common`` (a server: also for 127.0.0.1)."""
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(_name(common))
            .issuer_name(self.certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=days))
        )
        if server:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(common), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False,
            )
        return _pem(builder.sign(self.key, hashes.SHA256())), _key_pem(key)


class Receiver:
    """``Receiver("tcp")``, ``Receiver("udp")`` or ``Receiver("tls", folder, authority)``."""

    def __init__(
        self,
        protocol: str = "tcp",
        folder: Path | None = None,
        authority: Authority | None = None,
        *,
        name: str = "localhost",
        want_client: bool = False,
    ) -> None:
        self.protocol = protocol
        self.port = 0
        self.raw: list[bytes] = []
        self.errors: list[str] = []
        self.connections = 0
        self.reading = threading.Event()
        self.reading.set()
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._threads: list[threading.Thread] = []
        self._clients: list[socket.socket] = []
        self._context: ssl.SSLContext | None = None
        if protocol == "tls":
            assert folder is not None and authority is not None
            certificate, key = authority.issue(name)
            (folder / "server.crt").write_text(certificate)
            (folder / "server.key").write_text(key)
            self.certificate = certificate
            self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._context.load_cert_chain(folder / "server.crt", folder / "server.key")
            if want_client:
                self._context.verify_mode = ssl.CERT_REQUIRED
                self._context.load_verify_locations(cadata=authority.pem)

    # ----- running ----- #
    def start(self) -> Receiver:
        self._stop.clear()
        kind = socket.SOCK_DGRAM if self.protocol == "udp" else socket.SOCK_STREAM
        listener = socket.socket(socket.AF_INET, kind)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", self.port))
        self.port = listener.getsockname()[1]
        listener.settimeout(0.1)
        if self.protocol != "udp":
            listener.listen(8)
        self._listener = listener
        thread = threading.Thread(target=self._datagrams if self.protocol == "udp" else self._accept, daemon=True)
        thread.start()
        self._threads = [thread]
        return self

    def stop(self) -> None:
        """Go away at once: the listener and every connection are closed."""
        self._stop.set()
        self.reading.set()
        for client in self._clients:
            try:
                client.close()
            except OSError:
                pass
        self._clients = []
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        for thread in self._threads:
            thread.join(timeout=5)
        self._threads = []

    def __enter__(self) -> Receiver:
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()

    def _datagrams(self) -> None:
        listener = self._listener
        while not self._stop.is_set():
            try:
                data, _ = listener.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError:
                return
            self.raw.append(data)

    def _accept(self) -> None:
        listener = self._listener
        while not self._stop.is_set():
            try:
                client, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.connections += 1
            thread = threading.Thread(target=self._serve, args=(client,), daemon=True)
            thread.start()
            self._threads.append(thread)

    def _serve(self, client: socket.socket) -> None:
        try:
            if self._context is not None:
                client.settimeout(5)
                client = self._context.wrap_socket(client, server_side=True)
        except (ssl.SSLError, OSError) as error:
            self.errors.append(f"handshake: {error}")
            client.close()
            return
        self._clients.append(client)
        client.settimeout(0.1)
        pending = b""
        while not self._stop.is_set():
            if not self.reading.is_set():
                time.sleep(0.05)
                continue
            try:
                data = client.recv(65536)
            except (TimeoutError, ssl.SSLWantReadError):
                continue
            except OSError:
                return
            if not data:
                return
            pending += data
            while pending:
                size, space, rest = pending.partition(b" ")
                if not space:
                    if len(size) > 8 or not size.isdigit():
                        self.errors.append(f"framing: {pending[:40]!r}")
                        return
                    break
                if not size.isdigit() or size.startswith(b"0"):
                    self.errors.append(f"framing: {pending[:40]!r}")
                    return
                if len(rest) < int(size):
                    break
                self.raw.append(rest[: int(size)])
                pending = rest[int(size) :]

    # ----- what arrived ----- #
    def wait(self, count: int, timeout: float = 10.0) -> None:
        deadline = time.time() + timeout
        while len(self.raw) < count and time.time() < deadline:
            time.sleep(0.02)

    @property
    def lines(self) -> list[str]:
        return [message.decode("utf-8") for message in list(self.raw)]

    def bodies(self, kind: str = "audit") -> list[dict]:
        found = []
        for line in self.lines:
            body = json.loads(line[line.index('{"nik":') :])
            if body.get("nik") == kind:
                found.append(body)
        return found

    def numbers(self) -> list[int]:
        return [body["seq"] for body in self.bodies()]
