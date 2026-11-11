"""The only way out of the isolated browser: a filtering proxy.

Chromium is started with this proxy as its sole route, so every connection a
page causes goes through it: the navigation, each hop of a redirect, images,
scripts, frames, WebSockets. For each one the proxy resolves the name ITSELF,
refuses unless every address is public, and connects to the address it just
checked.

That closes what a check on the request's URL cannot:

- a public page answering ``302 Location: http://10.0.0.1/`` (a redirect hop
  never passes through the request interception);
- DNS rebinding, a name that resolves to a public address when it is checked
  and to a private one when the browser connects: here there is one
  resolution, and the connection goes to its result.

It is deliberately small: ``CONNECT`` tunnels (https, wss) and plain ``http``
requests, one request per connection. It never reads what flows through.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

INTERNAL_SUFFIXES = (".local", ".lan", ".internal", ".intranet", ".corp", ".home", ".home.arpa", ".localdomain")
HEAD_TIMEOUT = 30.0
CONNECT_TIMEOUT = 15.0
# A tunnel with nothing flowing either way for this long is closed.
IDLE_TIMEOUT = 300.0
REMEMBERED = 2000


def is_public(address: str) -> bool:
    """True for an address on the internet (not private, loopback, link-local, reserved…)."""
    try:
        return ipaddress.ip_address(address.split("%")[0]).is_global
    except ValueError:
        return False


def plain_host(host: str) -> str:
    return (host or "").strip().strip("[]").rstrip(".").lower()


def internal_name(host: str) -> bool:
    """A name that can only be internal: no dot, or an internal suffix."""
    host = plain_host(host)
    if not host:
        return True
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return "." not in host or host.endswith(INTERNAL_SUFFIXES)


class EgressProxy:
    """``allow`` decides which addresses may be reached (the public ones, by default)."""

    def __init__(self, allow: Callable[[str], bool] = is_public) -> None:
        self.allow = allow
        self.port = 0
        self.refused = 0
        # (host, port) -> the address the last connection went to, for the network log.
        self.addresses: dict[tuple[str, int], str] = {}
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> int:
        """Listen on a free loopback port; returns it."""
        if self._server is None:
            self._server = await asyncio.start_server(self._client, "127.0.0.1", 0)
            self.port = self._server.sockets[0].getsockname()[1]
        return self.port

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def vetted(self, host: str) -> str | None:
        """The address to connect to for ``host``, or None when it may not be reached.

        A name is refused when ANY of its addresses is not allowed: the answer
        cannot be used to slip one private address among public ones.
        """
        host = plain_host(host)
        if internal_name(host):
            return None
        try:
            ipaddress.ip_address(host)
            return host if self.allow(host) else None
        except ValueError:
            pass
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError:
            return None
        addresses = sorted({info[4][0].split("%")[0] for info in infos}, key=lambda a: ":" in a)
        if not addresses or not all(self.allow(address) for address in addresses):
            return None
        return addresses[0]

    def address_of(self, host: str, port: int) -> str | None:
        return self.addresses.get((plain_host(host), port))

    async def _refuse(self, writer: asyncio.StreamWriter, status: int, reason: str) -> None:
        body = (
            "<!doctype html><title>Blocked by Nik</title>"
            '<body style="font:16px sans-serif;margin:3em;color:#222">'
            f"<h2>Blocked by Nik</h2><p>{reason}.</p></body>"
        ).encode()
        writer.write(
            f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("latin-1")
            + body
        )
        await self._close(writer)

    @staticmethod
    async def _close(writer: asyncio.StreamWriter) -> None:
        try:
            await writer.drain()
        except (OSError, asyncio.CancelledError):
            pass
        writer.close()

    @staticmethod
    def _target(method: bytes, target: bytes) -> tuple[str, int, str] | None:
        """``(host, port, path)`` of a request line, or None when it is not one this proxy serves."""
        text = target.decode("latin-1")
        if method == b"CONNECT":
            host, _, port = text.rpartition(":")
            if not host or not port.isdigit():
                return None
            return plain_host(host), int(port), ""
        parts = urlsplit(text)
        if parts.scheme != "http" or not parts.hostname:
            return None
        try:
            port = parts.port or 80
        except ValueError:
            return None
        return plain_host(parts.hostname), port, urlunsplit(("", "", parts.path or "/", parts.query, ""))

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, OSError):
            writer.close()
            return
        request_line, _, rest = head.partition(b"\r\n")
        words = request_line.split()
        target = self._target(words[0], words[1]) if len(words) == 3 else None
        if target is None or not 0 < target[1] < 65536:
            await self._refuse(writer, 400, "Not a request this proxy serves")
            return
        host, port, path = target
        address = await self.vetted(host)
        if address is None:
            self.refused += 1
            await self._refuse(writer, 403, "Not a public address")
            return
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(address, port), CONNECT_TIMEOUT
            )
        except (OSError, asyncio.TimeoutError):
            await self._refuse(writer, 502, "The site did not answer")
            return
        if len(self.addresses) >= REMEMBERED:
            self.addresses.clear()
        self.addresses[(host, port)] = address
        if words[0] == b"CONNECT":
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        else:
            # Origin form, without the hop-by-hop headers; one request per connection,
            # so the next one is vetted again.
            kept = [
                line
                for line in rest.split(b"\r\n")
                if line and not line.lower().startswith((b"proxy-", b"connection:", b"keep-alive:"))
            ]
            upstream_writer.write(
                words[0]
                + b" "
                + path.encode("latin-1")
                + b" HTTP/1.1\r\n"
                + b"\r\n".join(kept)
                + b"\r\nConnection: close\r\n\r\n"
            )
        await asyncio.gather(self._pipe(reader, upstream_writer), self._pipe(upstream_reader, writer))

    @staticmethod
    async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while data := await asyncio.wait_for(reader.read(65536), IDLE_TIMEOUT):
                writer.write(data)
                await writer.drain()
        except (OSError, asyncio.TimeoutError, asyncio.CancelledError):
            pass
        finally:
            writer.close()
