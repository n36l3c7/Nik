"""The socket to the syslog receiver.

Three ways to send, chosen by the administrator:

- ``tls``  TCP with TLS (RFC 5425), the one to use. The receiver's
  certificate is always verified: against the CA or the certificate pasted
  in the settings when there is one (a certificate of the receiver itself is
  enough: it is pinned), against the system's authorities otherwise. Its
  name is checked too unless the settings say the certificate does not carry
  it. A client certificate is presented when one is set.
- ``tcp``  plain TCP (RFC 6587, octet counting): nothing is authenticated
  and anyone on the path reads the log.
- ``udp``  for receivers that take nothing else: unauthenticated, and a
  datagram that is lost is lost in silence.

**Where it may connect.** The process that sends (the automation worker)
refuses addresses inside the network for everything a playbook does, unless
the host is listed. The receiver is an exception of its own, because a SIEM
on a private address is the normal case: this module connects to the host
and the port of the settings, whatever range the address is in, and to
nothing else. It gives a playbook no way through: a playbook's requests go
through ``automation/egress.py``, which does not read these settings. A name
is resolved once and the connection goes to that address. Link-local
addresses (the metadata service of a cloud among them), multicast and
unspecified addresses are refused whatever the settings say.

TCP has no acknowledgement a sender can read: ``send`` returning means the
bytes left this host. ``alive`` looks whether the receiver closed since; the
forwarder counts a batch as arrived only when the connection is still up a
moment later, and sends it again otherwise.
"""

from __future__ import annotations

import ipaddress
import os
import select
import socket
import ssl
import tempfile
from typing import Any

from . import syslog

CONNECT_TIMEOUT = 10
SEND_TIMEOUT = 20


class TransportError(Exception):
    """The receiver could not be reached, or stopped listening: a sentence that can be shown."""


def resolve(host: str, port: int, datagram: bool) -> list[tuple[int, str]]:
    """The addresses of the receiver (replaced in tests)."""
    kind = socket.SOCK_DGRAM if datagram else socket.SOCK_STREAM
    return list(dict.fromkeys((info[0], info[4][0]) for info in socket.getaddrinfo(host, port, type=kind)))


def refused(address: str) -> str:
    """Why an address is never a receiver, or the empty text."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "it is not an address"
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_link_local:
        return "it is a link-local address"
    if ip.is_multicast:
        return "it is a multicast address"
    if ip.is_unspecified:
        return "it is not an address of a host"
    if ip.version == 4 and ip == ipaddress.ip_address("255.255.255.255"):
        return "it is the broadcast address"
    return ""


def addresses_of(host: str, port: int, datagram: bool = False) -> list[tuple[int, str]]:
    """The addresses of the receiver, resolved once and every one of them checked: the connection
    goes to the first that answers, and never back to the name."""
    try:
        found = resolve(host, port, datagram)
    except OSError as error:
        raise TransportError(f"{host} could not be resolved: {error}") from None
    if not found:
        raise TransportError(f"{host} could not be resolved")
    for _family, address in found:
        why = refused(address)
        if why:
            raise TransportError(f"{host} is {address}: {why}, and nothing is sent there")
    return found


def address_of(host: str, port: int, datagram: bool = False) -> tuple[int, str]:
    return addresses_of(host, port, datagram)[0]


def _context(settings: dict[str, Any], client_key: str) -> ssl.SSLContext:
    pinned = str(settings.get("ca") or "").strip()
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cadata=pinned or None)
    except ssl.SSLError as error:
        raise TransportError(f"The CA or certificate of the receiver cannot be read: {error}") from None
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if pinned:
        # A certificate of the receiver itself, pasted alone, is trusted as it is.
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    if settings.get("verifyName") is False:
        context.check_hostname = False
    certificate = str(settings.get("clientCert") or "").strip()
    if certificate:
        if not client_key:
            raise TransportError("A client certificate is set without its key")
        # The standard library reads a certificate and its key from files only: two that live
        # for the time of the call, in the memory-backed /tmp of the container.
        paths = []
        try:
            for text in (certificate, client_key):
                handle, path = tempfile.mkstemp(prefix="nik-syslog-")
                paths.append(path)
                with os.fdopen(handle, "w", encoding="ascii", errors="replace") as target:
                    target.write(text.strip() + "\n")
            context.load_cert_chain(paths[0], paths[1])
        except (ssl.SSLError, OSError) as error:
            raise TransportError(f"The client certificate or its key cannot be read: {error}") from None
        finally:
            for path in paths:
                try:
                    os.unlink(path)
                except OSError:
                    pass
    return context


class Connection:
    """One connection to the receiver of the settings. Not shared between threads."""

    def __init__(self, settings: dict[str, Any], client_key: str = "") -> None:
        self.settings = settings
        self.host = str(settings.get("host") or "")
        self.port = int(settings.get("port") or 0)
        self.protocol = str(settings.get("protocol") or "tls")
        self._client_key = client_key
        self._socket: socket.socket | None = None
        self.said: dict[str, Any] = {}
        # What the receiver said when it closed the connection (a TLS alert), when it said anything.
        self.closed_why = ""

    @property
    def datagram(self) -> bool:
        return self.protocol == "udp"

    @property
    def open(self) -> bool:
        return self._socket is not None

    def connect(self) -> dict[str, Any]:
        """Open the connection. Returns what the socket said: the address, and for TLS the
        version, the cipher and the certificate the receiver presented."""
        self.close()
        found = addresses_of(self.host, self.port, self.datagram)
        family, address = found[0]
        said: dict[str, Any] = {"address": address, "port": self.port, "protocol": self.protocol}
        try:
            if self.datagram:
                plain = socket.socket(family, socket.SOCK_DGRAM)
                plain.settimeout(SEND_TIMEOUT)
                plain.connect((address, self.port))
                self._socket = plain
            else:
                # A name with several addresses (IPv6 and IPv4): the first that takes the connection.
                for position, (_family, address) in enumerate(found):
                    try:
                        plain = socket.create_connection((address, self.port), CONNECT_TIMEOUT)
                        break
                    except OSError:
                        if position == len(found) - 1:
                            raise
                said["address"] = address
                plain.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                if self.protocol == "tls":
                    context = _context(self.settings, self._client_key)
                    try:
                        secured = context.wrap_socket(plain, server_hostname=self.host)
                    except BaseException:
                        plain.close()
                        raise
                    peer = secured.getpeercert() or {}
                    said.update(
                        tls=secured.version(),
                        cipher=(secured.cipher() or ("",))[0],
                        subject=", ".join(
                            f"{name}={value}" for part in peer.get("subject", ()) for name, value in part
                        ),
                        notAfter=peer.get("notAfter", ""),
                    )
                    plain = secured
                plain.settimeout(SEND_TIMEOUT)
                self._socket = plain
        except ssl.SSLCertVerificationError as error:
            raise TransportError(
                f"The certificate of {self.host} was refused: {error.verify_message or error}"
            ) from None
        except ssl.SSLError as error:
            raise TransportError(f"TLS with {self.host}:{self.port} failed: {error.reason or error}") from None
        except TimeoutError:
            raise TransportError(f"{self.host}:{self.port} did not answer in {CONNECT_TIMEOUT} seconds") from None
        except OSError as error:
            raise TransportError(f"{self.host}:{self.port} cannot be reached: {error.strerror or error}") from None
        self.said = said
        return said

    def send(self, messages: list[bytes]) -> int:
        """Send messages in order. Returns the bytes written; raises when the receiver is gone."""
        if self._socket is None:
            self.connect()
        assert self._socket is not None
        try:
            if self.datagram:
                written = 0
                for message in messages:
                    written += self._socket.send(message)
                return written
            data = b"".join(syslog.frame(message) for message in messages)
            self._socket.sendall(data)
            return len(data)
        except TimeoutError:
            self.close()
            raise TransportError(
                f"{self.host}:{self.port} took nothing for {SEND_TIMEOUT} seconds: the receiver is not reading"
            ) from None
        except OSError as error:
            self.close()
            raise TransportError(f"{self.host}:{self.port} stopped listening: {error.strerror or error}") from None

    def alive(self) -> bool:
        """Whether the receiver still holds the connection (it sends nothing: anything
        readable is the end of the connection, or an alert that announces it)."""
        if self._socket is None:
            return False
        if self.datagram:
            return True
        try:
            readable, _, _ = select.select([self._socket], [], [], 0)
            if not readable:
                return True
            self._socket.settimeout(0.5)
            try:
                data = self._socket.recv(4096)
            finally:
                self._socket.settimeout(SEND_TIMEOUT)
        except (ssl.SSLWantReadError, TimeoutError):
            return True
        except (OSError, ValueError) as error:
            self.closed_why = str(getattr(error, "reason", "") or getattr(error, "strerror", "") or "")
            self.close()
            return False
        if not data:
            self.close()
            return False
        return True  # a receiver that talks: not ours to read, and still there

    def close(self) -> None:
        held, self._socket = self._socket, None
        if held is not None:
            try:
                held.close()
            except OSError:
                pass
