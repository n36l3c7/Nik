"""The way out: the one place a playbook's request leaves from.

Every request a playbook sends (the HTTP node, a connector command, an
e-mail) goes through this module, and **no other module of the package opens
a socket** (a test greps for it). What it enforces:

- **Where.** A playbook reaches the hosts listed for it, for its connections
  and for every playbook by the admin (``listed``), or any host (``any``, a
  choice an admin makes behind a double check).
- **Never by accident inside.** Whatever the mode, a name that resolves to
  the loopback, a link-local or private address, the container networks or a
  cloud metadata address is refused, unless that very host is listed: an
  internal firewall manager is reachable because someone wrote its name.
- **No rebinding.** The name is resolved once, the address is checked, and
  the connection goes to that address (with the name for TLS and Host).
- **Redirects** are followed three times at most, each checked like a first
  request; credentials do not follow to another host.
- **TLS** is always verified (a CA bundle can be given for an internal
  certificate; there is no "skip verification"). Plain http only where a
  connection says so.
- **Limits**: 10 s to connect, 60 s in all (300 at most), 5 MB of answer.

What is recorded for a step: method, host, path, status, bytes, time. Never a
header that carries a credential, never a secret.
"""

from __future__ import annotations

import http.client
import ipaddress
import json as jsonlib
import os
import smtplib
import socket
import ssl
import time
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any
from urllib.parse import urlencode, urljoin, urlsplit

CONNECT_TIMEOUT = 10
DEFAULT_TIMEOUT = 60
MAX_TIMEOUT = 300
MAX_BODY = 5_000_000
MAX_REDIRECTS = 3
MAX_URL = 8000
# Headers that carry a credential: never recorded, never sent on to another host.
CREDENTIAL_HEADERS = ("authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token", "x-chkp-sid")
METADATA = ipaddress.ip_network("169.254.169.254/32")


class EgressError(Exception):
    """A request that was not sent, or got no usable answer: a sentence safe to show.

    ``refused``: the rules above said no (trying again cannot help).
    ``sent``: the request left, so its effect on the other side is not known.
    """

    def __init__(self, message: str, *, refused: bool = False, sent: bool = False, record: dict | None = None):
        super().__init__(message)
        self.message = message
        self.refused = refused
        self.sent = sent
        self.record = record


@dataclass(frozen=True)
class Policy:
    """Where a playbook may send: its mode and the hosts listed for it (lower case, with or without a port)."""

    mode: str = "listed"  # listed | any
    hosts: frozenset = frozenset()

    def lists(self, host: str, port: int) -> bool:
        return host in self.hosts or f"{host}:{port}" in self.hosts


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    record: dict[str, Any] = field(default_factory=dict)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        """The body as JSON when the answer says it is (None otherwise, or when it is not valid)."""
        if "json" not in self.headers.get("content-type", "").lower():
            return None
        try:
            return jsonlib.loads(self.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None


def clean_host(value: str) -> str | None:
    """A host as it is listed and compared: lower case, IDNA, no trailing dot. None when it is not one."""
    host = str(value or "").strip().lower().rstrip(".")
    if not host or len(host) > 253 or any(char in host for char in " /\\@#?"):
        return None
    name, _, port = host.partition(":") if host.count(":") == 1 else (host, "", "")
    if port and not (port.isdigit() and 0 < int(port) < 65536):
        return None
    try:
        ipaddress.ip_address(name.strip("[]"))
    except ValueError:
        try:
            name = name.encode("idna").decode("ascii")
        except UnicodeError:
            return None
        if not all(part and len(part) <= 63 for part in name.split(".")):
            return None
    return f"{name}:{port}" if port else name


# --------------------------------------------------------------------------- #
# Addresses                                                                   #
# --------------------------------------------------------------------------- #
def _local_networks() -> list:
    """The networks this container is on (its compose networks): never a destination by accident."""
    found = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            address = ipaddress.ip_address(info[4][0])
            if address.is_loopback:
                continue
            prefix = 16 if address.version == 4 else 64
            found.append(ipaddress.ip_network(f"{address}/{prefix}", strict=False))
    except (OSError, ValueError):
        pass
    return found


_LOCAL = _local_networks()


def is_inside(address: str) -> bool:
    """An address that is not out on the internet: this host, this network, a private range."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_private
        or ip.is_reserved
        or ip in METADATA
        or any(ip in network for network in _LOCAL)
    )


def resolve(host: str, port: int) -> list[str]:
    """The addresses of a name (patched in tests: no test reaches the network)."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(info[4][0] for info in infos))


def _proxy() -> tuple[str, int] | None:
    value = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
    if not value:
        return None
    parts = urlsplit(value if "://" in value else f"http://{value}")
    return (parts.hostname, parts.port or 3128) if parts.hostname else None


def _no_proxy(host: str) -> bool:
    for entry in (os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or "").split(","):
        entry = entry.strip().lower().lstrip(".")
        if entry and (host == entry or host.endswith("." + entry)):
            return True
    return False


def destination(policy: Policy, url: str, *, allow_http: bool = False) -> tuple[str, str, int, str, str | None]:
    """Check a URL against the policy and the address rules.

    Returns ``(scheme, host, port, path-and-query, address)``: ``address`` is
    the one to connect to, or None when a proxy resolves the name. Raises
    ``EgressError(refused=True)`` with the reason."""
    if len(url) > MAX_URL:
        raise EgressError("The address is too long", refused=True)
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http"):
        raise EgressError("Only https addresses can be reached", refused=True)
    if parts.scheme == "http" and not allow_http:
        raise EgressError("Plain http is refused: use https, or allow http on the connection", refused=True)
    if parts.username or parts.password:
        raise EgressError("An address with a user name in it is refused", refused=True)
    host = clean_host(parts.hostname or "")
    if not host:
        raise EgressError("The address names no host", refused=True)
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        raise EgressError("The port of the address is not valid", refused=True) from None
    listed = policy.lists(host, port)
    if policy.mode != "any" and not listed:
        raise EgressError(f"{host} is not among the hosts this playbook may reach", refused=True)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    proxied = _proxy() is not None and not _no_proxy(host)
    try:
        # An address written as such is itself: nothing to resolve, the same rules.
        addresses = [str(ipaddress.ip_address(host.strip("[]")))]
    except ValueError:
        addresses = []
    try:
        addresses = addresses or resolve(host, port)
    except OSError:
        if proxied:
            return parts.scheme, host, port, path, None  # the proxy resolves it
        raise EgressError(f"{host} could not be resolved") from None
    if not addresses:
        raise EgressError(f"{host} could not be resolved")
    inside = [address for address in addresses if is_inside(address)]
    if inside and not listed:
        raise EgressError(
            f"{host} is an address inside the network: it is reached only when the host is listed", refused=True
        )
    if proxied and not inside:
        return parts.scheme, host, port, path, None
    return parts.scheme, host, port, path, addresses[0]


# --------------------------------------------------------------------------- #
# Requests                                                                    #
# --------------------------------------------------------------------------- #
class _Pinned(http.client.HTTPSConnection):
    """An HTTPS connection to an address chosen beforehand, with the name for SNI and the certificate."""

    def __init__(self, host: str, port: int, address: str, timeout: float, context: ssl.SSLContext):
        super().__init__(host, port, timeout=timeout, context=context)
        self._address = address

    def connect(self) -> None:
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedPlain(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


def _context(ca_pem: str | None) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if ca_pem:
        try:
            context.load_verify_locations(cadata=ca_pem)
        except ssl.SSLError:
            raise EgressError("The CA certificate of the connection is not valid PEM", refused=True) from None
    return context


def _connect(scheme: str, host: str, port: int, address: str | None, timeout: float, ca_pem: str | None):
    if address is None:  # through the proxy, which resolves the name
        proxy_host, proxy_port = _proxy()
        if scheme == "https":
            connection = http.client.HTTPSConnection(proxy_host, proxy_port, timeout=timeout, context=_context(ca_pem))
            connection.set_tunnel(host, port)
            return connection
        return http.client.HTTPConnection(proxy_host, proxy_port, timeout=timeout)
    if scheme == "https":
        return _Pinned(host, port, address, timeout, _context(ca_pem))
    return _PinnedPlain(host, port, address, timeout)


def _send(
    scheme, host, port, path, address, method, headers, body, timeout, ca_pem, max_body
) -> tuple[int, dict, bytes]:
    """One request, no redirect followed (patched in tests with recorded answers)."""
    connection = _connect(scheme, host, port, address, min(CONNECT_TIMEOUT, timeout), ca_pem)
    deadline = time.monotonic() + timeout
    target = path if address is not None or scheme == "https" else f"http://{host}:{port}{path}"
    try:
        connection.request(method, target, body=body, headers=headers)
        if connection.sock is not None:
            connection.sock.settimeout(max(1.0, deadline - time.monotonic()))
        answer = connection.getresponse()
        chunks: list[bytes] = []
        size = 0
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError
            chunk = answer.read(65536)
            if not chunk:
                break
            size += len(chunk)
            if size > max_body:
                raise EgressError(f"The answer is larger than {max_body // 1_000_000} MB", sent=True)
            chunks.append(chunk)
        return answer.status, {key.lower(): value for key, value in answer.getheaders()}, b"".join(chunks)
    finally:
        connection.close()


def request(
    policy: Policy,
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    query: dict[str, Any] | None = None,
    json: Any = None,
    form: dict[str, Any] | None = None,
    body: str | bytes | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    allow_http: bool = False,
    ca_pem: str | None = None,
    max_body: int = MAX_BODY,
) -> Response:
    """Send a request under the policy. Raises ``EgressError``."""
    method = str(method or "GET").upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"):
        raise EgressError("Unknown HTTP method", refused=True)
    timeout = max(1.0, min(float(timeout or DEFAULT_TIMEOUT), MAX_TIMEOUT))
    sent = {str(key): str(value) for key, value in (headers or {}).items()}
    if any("\n" in key or "\r" in key or "\n" in value or "\r" in value for key, value in sent.items()):
        raise EgressError("A header holds a line break", refused=True)
    if query:
        pairs = [(key, value) for key, value in query.items() if value is not None]
        url += ("&" if "?" in url else "?") + urlencode(pairs, doseq=True)
    payload: bytes | None = None
    if json is not None:
        payload = jsonlib.dumps(json).encode("utf-8")
        sent.setdefault("Content-Type", "application/json")
    elif form is not None:
        payload = urlencode({key: value for key, value in form.items() if value is not None}, doseq=True).encode(
            "utf-8"
        )
        sent.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif body is not None:
        payload = body.encode("utf-8") if isinstance(body, str) else body
    sent.setdefault("User-Agent", "nik-automation")
    sent.setdefault("Accept", "application/json, */*;q=0.5")

    started = time.monotonic()
    first_host = None
    record: dict[str, Any] = {}
    for hop in range(MAX_REDIRECTS + 1):
        scheme, host, port, path, address = destination(policy, url, allow_http=allow_http)
        if first_host is None:
            first_host = host
        elif host != first_host:
            # Credentials do not follow to another host.
            sent = {key: value for key, value in sent.items() if key.lower() not in CREDENTIAL_HEADERS}
        record = {"method": method, "host": host, "path": path.split("?")[0][:300], "redirects": hop}
        try:
            status, answer_headers, content = _send(
                scheme, host, port, path, address, method, sent, payload, timeout, ca_pem, max_body
            )
        except EgressError as error:
            error.record = error.record or record
            raise
        except ssl.SSLCertVerificationError:
            raise EgressError(f"The certificate of {host} could not be verified", record=record) from None
        except (TimeoutError, socket.timeout):
            raise EgressError(f"{host} did not answer in time", sent=True, record=record) from None
        except (OSError, http.client.HTTPException):
            raise EgressError(f"{host} could not be reached", record=record) from None
        if status in (301, 302, 303, 307, 308) and answer_headers.get("location"):
            if hop >= MAX_REDIRECTS:
                break
            url = urljoin(url, answer_headers["location"])
            if status == 303 or (status in (301, 302) and method == "POST"):
                method, payload = "GET", None
                sent.pop("Content-Type", None)
            continue
        record.update(status=status, bytes=len(content), ms=int((time.monotonic() - started) * 1000))
        return Response(status=status, headers=answer_headers, body=content, record=record)
    raise EgressError("Too many redirects", sent=True, record=record)


# --------------------------------------------------------------------------- #
# E-mail                                                                      #
# --------------------------------------------------------------------------- #
def send_mail(
    server: dict[str, Any],
    *,
    to: list[str],
    subject: str,
    text: str,
    timeout: float = 30,
) -> dict[str, Any]:
    """Send a message through the SMTP server an admin configured
    (``{host, port, security: starttls|tls|none, username, password, sender, ca_pem}``).
    The server is the one written in the settings: it is reached wherever it is."""
    host = clean_host(str(server.get("host") or ""))
    if not host or not server.get("sender"):
        raise EgressError("No SMTP server is configured: an admin sets it in Settings", refused=True)
    port = int(server.get("port") or 587)
    security = str(server.get("security") or "starttls")
    message = EmailMessage()
    message["From"] = str(server["sender"])
    message["To"] = ", ".join(to)
    message["Subject"] = " ".join(str(subject).split())[:300]
    message.set_content(text)
    record = {"method": "SMTP", "host": host, "path": f"{len(to)} recipient(s)"}
    try:
        context = _context(server.get("ca_pem") or None)
        if security == "tls":
            client = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
        else:
            client = smtplib.SMTP(host, port, timeout=timeout)
        with client:
            if security == "starttls":
                client.starttls(context=context)
            if server.get("username"):
                client.login(str(server["username"]), str(server.get("password") or ""))
            refused = client.send_message(message)
    except smtplib.SMTPAuthenticationError:
        raise EgressError(
            "The SMTP server refused the user name or the password", refused=True, record=record
        ) from None
    except smtplib.SMTPRecipientsRefused:
        raise EgressError("The SMTP server refused every recipient", refused=True, record=record) from None
    except ssl.SSLError:
        raise EgressError(f"The certificate of {host} could not be verified", record=record) from None
    except (OSError, smtplib.SMTPException):
        raise EgressError(f"The SMTP server {host} could not be reached", record=record) from None
    record["status"] = "sent"
    record["refused"] = sorted(refused) if refused else []
    return record


# --------------------------------------------------------------------------- #
# The sandbox                                                                 #
# --------------------------------------------------------------------------- #
def sandbox_run(url: str, token: str, code: str, args: dict, timeout: int) -> dict:
    """Ask the sandbox to run a script: ``{ok, result | error, stdout, duration_ms}``.
    The sandbox is a container of the stack on an internal network: its address is
    the one of the configuration, not something a playbook chooses."""
    parts = urlsplit(url)
    if parts.scheme != "http" or not parts.hostname:
        raise EgressError("The address of the sandbox is not valid", refused=True)
    payload = jsonlib.dumps({"code": code, "args": args, "timeout": timeout}).encode("utf-8")
    connection = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout + 10)
    try:
        headers = {"Content-Type": "application/json", "X-Sandbox-Token": token}
        connection.request("POST", "/run", body=payload, headers=headers)
        answer = connection.getresponse()
        content = answer.read(MAX_BODY + 1)
        status = answer.status
    except (OSError, http.client.HTTPException):
        raise EgressError("The sandbox could not be reached") from None
    finally:
        connection.close()
    if status == 503:
        raise EgressError("The sandbox is busy: try again in a moment")
    if status != 200:
        raise EgressError("The sandbox refused the request")
    try:
        return jsonlib.loads(content.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise EgressError("The sandbox gave an answer that cannot be read") from None
